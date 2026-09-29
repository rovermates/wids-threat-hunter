"""Validation-only model/threshold search. Does not load the consumed test capture."""
import argparse
import hashlib
import json
from pathlib import Path
import time

import joblib
import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import precision_recall_curve
from sklearn.pipeline import Pipeline
from threadpoolctl import threadpool_limits

from backend.core.class_balance import undersample_training
from backend.core.detection_features import DETECTION_FEATURES
from backend.core.ml_engine import FEATURE_SETS, PROTOCOL
from backend.train_ensemble import metrics


def select_threshold(y, scores, recall_floor=.90):
    p, r, thresholds = precision_recall_curve(y, scores)
    f1 = np.divide(2 * p[:-1] * r[:-1], p[:-1] + r[:-1], out=np.zeros_like(p[:-1]), where=(p[:-1] + r[:-1]) != 0)
    eligible = np.flatnonzero(r[:-1] >= recall_floor)
    if not len(eligible):
        raise ValueError('No threshold meets recall floor')
    best = max(eligible, key=lambda i: (f1[i], p[i], thresholds[i]))
    return float(thresholds[best])


def candidates():
    for name, estimator in [
        ('rf64', RandomForestClassifier(n_estimators=64, max_depth=18, min_samples_leaf=2, class_weight='balanced', n_jobs=4, random_state=42)),
        ('rf128', RandomForestClassifier(n_estimators=128, max_depth=None, min_samples_leaf=2, class_weight='balanced', n_jobs=4, random_state=42)),
        ('extra96', ExtraTreesClassifier(n_estimators=96, max_depth=24, min_samples_leaf=2, class_weight='balanced', n_jobs=4, random_state=42)),
        ('hist120', HistGradientBoostingClassifier(max_iter=120, max_leaf_nodes=15, learning_rate=.08,
            min_samples_leaf=30, l2_regularization=1., class_weight='balanced', early_stopping=False, random_state=42)),
    ]:
        yield name, Pipeline([('imputer', SimpleImputer(strategy='median', add_indicator=True, keep_empty_features=True)), ('model', estimator)])


def train(cache, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    source = joblib.load(cache)
    training, balance = undersample_training(source['data']['train'], benign_to_attack_ratio=1.)
    validation = source['data']['validation']
    y = (training.label == 'evil_twin').to_numpy(dtype=int)
    vy = (validation.label == 'evil_twin').to_numpy(dtype=int)
    for target in [y, vy]:
        if len(np.unique(target)) != 2:
            raise ValueError('Both classes required in train and validation')
    baseline = FEATURE_SETS['combined_plus_frame_length']
    sets = {'baseline': baseline, 'portable': baseline + DETECTION_FEATURES,
            'extended': list(dict.fromkeys(baseline + PROTOCOL + DETECTION_FEATURES))}
    protocol = {'feature_sets': sets, 'candidates': ['rf64', 'rf128', 'extra96', 'hist120'],
                'threshold_selection': 'maximize validation F1 subject to recall >= 0.90; ties prefer precision',
                'test_used_for_selection': False, 'data': source['metadata']}
    (output / 'protocol.json').write_text(json.dumps(protocol, indent=2), encoding='utf8')
    experiments = []
    best = None
    best_key = (-1., -1.)
    with threadpool_limits(limits=4):
        for feature_set, features in sets.items():
            x = training[features].astype('float64')
            vx = validation[features].astype('float64')
            for name, estimator in candidates():
                start = time.perf_counter()
                estimator.fit(x, y)
                train_seconds = time.perf_counter() - start
                start = time.perf_counter()
                scores = estimator.predict_proba(vx)[:, 1]
                seconds = time.perf_counter() - start
                threshold = select_threshold(vy, scores)
                m = metrics(vy, scores >= threshold, scores)
                trial = {'model': name, 'feature_set': feature_set, 'threshold': threshold,
                         'train_seconds': train_seconds, 'predict_seconds': seconds, 'validation': m}
                experiments.append(trial)
                print(json.dumps(trial), flush=True)
                (output / 'experiments.json').write_text(json.dumps(experiments, indent=2), encoding='utf8')
                key = (m['f1'], m['precision'])
                if key > best_key:
                    best_key = key
                    best = {'format_version': 2, 'model': estimator, 'features': features, 'threshold': threshold,
                            'rssi_window': source['metadata']['rssi_window'], 'selection': trial,
                            'training_metadata': source['metadata'], 'balance': balance,
                            'model_name': name, 'target': 'evil_twin versus all other AWID ATK labels',
                            'score_semantics': 'Uncalibrated positive-class model score; not a probability guarantee'}
                    joblib.dump(best, output / 'trained_ensemble.joblib', compress=3)
    meta = {k: v for k, v in best.items() if k != 'model'}
    meta['artifact_sha256'] = hashlib.sha256((output / 'trained_ensemble.joblib').read_bytes()).hexdigest()
    (output / 'metadata.json').write_text(json.dumps(meta, indent=2), encoding='utf8')
    print('FROZEN', best['selection'], flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('cache')
    p.add_argument('output')
    a = p.parse_args()
    train(a.cache, a.output)
