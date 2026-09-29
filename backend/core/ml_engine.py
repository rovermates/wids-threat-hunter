"""Portable numeric feature contract and RF/linear-SVM inference engine."""
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import SGDClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from backend.core.feature_builder import FEATURE_DTYPES, TemporalFeatureBuilder
from backend.core.detection_features import DETECTION_FEATURES, detection_features
from backend.core.ap_behavior import AP_FEATURES, APBehaviorBuilder
from backend.core.advertiser_features import ADVERTISER_FEATURES, AdvertiserFeatureBuilder
from backend.core.multiscale_features import MULTISCALE_FEATURES, MultiScaleFeatures

STATIC = ['rssi_dbm', 'frame_type', 'frame_subtype']
TEMPORAL = list(FEATURE_DTYPES)
PROTOCOL_FIELDS = {
    'frame_length': ('frame.len', 'frame.len'),
    'retry_flag': ('wlan.fc.retry', 'wlan.fc.retry'),
    'protected_flag': ('wlan.fc.protected', 'wlan.fc.protected'),
    'fragment_number': ('wlan.frag', 'wlan.frag'),
    'beacon_interval_tu': ('wlan_mgt.fixed.beacon', 'wlan.fixed.beacon'),
    'ess_flag': ('wlan_mgt.fixed.capabilities.ess', 'wlan.fixed.capabilities.ess'),
    'privacy_flag': ('wlan_mgt.fixed.capabilities.privacy', 'wlan.fixed.capabilities.privacy'),
    'qos_tid': ('wlan.qos.tid', 'wlan.qos.tid'),
}
PROTOCOL = list(PROTOCOL_FIELDS)
FEATURE_SETS = {'static': STATIC, 'temporal': TEMPORAL, 'combined': STATIC + TEMPORAL,
                'protocol': STATIC + PROTOCOL, 'full': STATIC + TEMPORAL + PROTOCOL}
FEATURE_SETS.update({f'combined_plus_{name}': STATIC + TEMPORAL + [name] for name in PROTOCOL})


def protocol_features(frame, names=None):
    """Map existing AWID/tshark fields to the same decimal numeric contract."""
    result = pd.DataFrame(index=frame.index)
    for name in (PROTOCOL if names is None else names):
        aliases = PROTOCOL_FIELDS[name]
        source = next((key for key in aliases if key in frame), None)
        if source is None:
            raise ValueError(f'Missing protocol source for {name}')
        # Native repeated fields use the first value, matching existing aliases.
        values = frame[source].astype('string').str.split(',').str[0]
        values = values.replace({'?': pd.NA, '': pd.NA, '<MISSING>': pd.NA,
                                 'True': '1', 'False': '0', 'true': '1', 'false': '0'})
        result[name] = pd.to_numeric(values, errors='raise').astype('float64')
    return result


def numeric_features(frame, features):
    """Strict allowlist; identifiers, labels and timestamps never enter the model."""
    if not features or not set(features) <= set(STATIC + TEMPORAL + PROTOCOL + DETECTION_FEATURES + AP_FEATURES + ADVERTISER_FEATURES + MULTISCALE_FEATURES):
        raise ValueError('Invalid feature allowlist')
    missing = set(features) - set(frame.columns)
    if missing:
        raise ValueError(f'Missing model features: {sorted(missing)}')
    result = frame.loc[:, features].apply(pd.to_numeric, errors='raise').astype('float64')
    if np.isinf(result.to_numpy()).any():
        raise ValueError('Infinite model inputs are not allowed')
    return result


def make_ensemble(alpha=0.0001, min_samples_leaf=1):
    prep = [('imputer', SimpleImputer(strategy='median', add_indicator=True,
                                      keep_empty_features=True))]
    rf = Pipeline(prep + [('model', RandomForestClassifier(
        n_estimators=100, class_weight='balanced', random_state=42,
        min_samples_leaf=min_samples_leaf, n_jobs=4))])
    svm = Pipeline([('imputer', SimpleImputer(strategy='median', add_indicator=True,
                                             keep_empty_features=True)),
                    ('scaler', StandardScaler()),
                    ('model', SGDClassifier(loss='hinge', penalty='l2', max_iter=1000,
                                            alpha=alpha, class_weight='balanced',
                                            random_state=42))])
    return VotingClassifier([('rf', rf), ('svm', svm)], voting='hard')


def vote_score(model, x):
    """Fraction of positive hard votes: a three-level rank score, NOT probability."""
    return np.mean(model.transform(x), axis=1)


class InferenceSession:
    """Fresh instance per capture; temporal state persists only across its chunks.

    Load only trusted joblib artifacts: pickle-based loading can execute code.
    """
    def __init__(self, artifact):
        self.bundle = joblib.load(Path(artifact))
        if self.bundle.get('format_version') not in {1, 2, 3}:
            raise ValueError('Unsupported model artifact version')
        self.builder = TemporalFeatureBuilder(self.bundle['rssi_window'])
        self.behavior = APBehaviorBuilder(self.bundle.get('behavior_window',100))
        self.advertiser = AdvertiserFeatureBuilder(self.bundle.get('behavior_window',100))
        self.multiscale = MultiScaleFeatures()
        from backend.core.score_history import ScoreHistory
        self.score_history = ScoreHistory(**self.bundle['score_history']) if self.bundle.get('score_history') else None

    def predict_chunk(self, raw):
        predictions, _ = self.predict_with_features(raw)
        return predictions

    def predict_with_features(self, raw):
        """Return predictions and their evidence using one temporal-state update."""
        enriched = self.builder.transform(raw)
        if set(self.bundle['features']) & set(PROTOCOL):
            names = [name for name in self.bundle['features'] if name in PROTOCOL]
            for name, values in protocol_features(raw, names).items():
                enriched[name] = values
        if set(self.bundle['features']) & set(DETECTION_FEATURES):
            for name, values in detection_features(raw).items():
                enriched[name] = values
        if set(self.bundle['features']) & set(AP_FEATURES):
            for name, values in self.behavior.transform(raw).items():
                enriched[name] = values
        if set(self.bundle['features']) & set(ADVERTISER_FEATURES):
            for name, values in self.advertiser.transform(raw).items():
                enriched[name] = values
        if set(self.bundle['features']) & set(MULTISCALE_FEATURES):
            for name, values in self.multiscale.transform(enriched).items():
                enriched[name] = values
        x = numeric_features(enriched, self.bundle['features'])
        model = self.bundle['model']
        if self.bundle['format_version'] in {2,3}:
            classes = list(model.classes_)
            target = 'evil_twin' if 'evil_twin' in classes else 1
            eligible = (raw.frame_type.eq(0) & raw.frame_subtype.isin([5,8])).fillna(False) if self.bundle.get('scope') == 'ap_advertisements' else pd.Series(True,index=raw.index)
            scores = np.full(len(raw),np.nan)
            if eligible.any():
                scores[eligible.to_numpy(dtype=bool)] = model.predict_proba(x.loc[eligible])[:, classes.index(target)]
            if self.score_history is not None:
                scores = self.score_history.transform(scores, raw.timestamp_ns, raw.bssid)
            predictions = pd.DataFrame({'rogue_ap_prediction': (scores >= self.bundle['threshold']).astype(int),
                                        'positive_vote_fraction': np.nan, 'detection_score': scores, 'evaluated':eligible.to_numpy(dtype=bool)}, index=raw.index)
            return predictions, enriched
        predictions = pd.DataFrame({'rogue_ap_prediction': model.predict(x),
                                    'positive_vote_fraction': vote_score(model, x)}, index=raw.index)
        return predictions, enriched
