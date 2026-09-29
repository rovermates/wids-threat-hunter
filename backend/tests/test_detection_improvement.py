import tempfile
import random
from statistics import pstdev
from backend.core.feature_builder import _RssiWindow
from pathlib import Path
import unittest

import joblib
import numpy as np
import pandas as pd

from backend.core.detection_features import detection_features, DETECTION_FEATURES
from backend.core.feature_builder import TemporalFeatureBuilder
from backend.core.ml_engine import InferenceSession, FEATURE_SETS, numeric_features
from backend.improve_detection import candidates, select_threshold
from backend.train_multisource import macro_threshold
from sklearn.metrics import f1_score
from backend.dashboard.model_info import load_model_info
from backend.tests.test_ml_engine import fixture


def raw_fixture():
    raw = fixture()
    raw['source_mac'] = raw.bssid
    raw['destination_mac'] = 'ff:ff:ff:ff:ff:ff'
    raw['wlan.fc.ds'] = '0x02'
    for field in ['wlan.fc.pwrmgt', 'wlan.fc.frag', 'wlan.fc.moredata', 'wlan.duration']:
        raw[field] = '0'
    raw['frame.len'] = '200'
    return raw


class DetectionImprovementTests(unittest.TestCase):
    def test_incremental_rssi_matches_reference_with_expiration_and_missing_values(self):
        rng = random.Random(42)
        for size in [1, 2, 7, 100]:
            window = _RssiWindow(size)
            history = []
            for _ in range(1000):
                value = None if rng.random() < .2 else rng.randint(-128,127)
                history.append(value); window.append(value)
                values = [v for v in history[-size:] if v is not None]
                count, std, drift = window.summary()
                self.assertEqual(count, len(values))
                if count < 2:
                    self.assertIsNone(std); self.assertIsNone(drift)
                else:
                    self.assertAlmostEqual(std, pstdev(values), places=12)
                    self.assertEqual(drift, values[-1]-values[0])

    def test_mac_features_are_relationships_not_identity(self):
        raw = raw_fixture()
        original = detection_features(raw)
        self.assertTrue((original.source_is_bssid == 1).all())
        self.assertTrue((original.destination_multicast == 1).all())
        self.assertTrue((original.to_ds == 0).all())
        self.assertTrue((original.from_ds == 1).all())
        raw['source_mac'] = raw['bssid'] = '02:de:ad:be:ef:00'
        raw['timestamp_ns'] += 90000000000
        raw['label'] = 'evil_twin'
        pd.testing.assert_frame_equal(original, detection_features(raw))

    def test_awid_ds_bits_match_native_fields_and_missing_is_missing(self):
        raw = raw_fixture()
        raw['wlan.fc.ds'] = [str(i % 4) for i in range(len(raw))]
        awid = detection_features(raw)
        raw['wlan.fc.tods'] = [str(i % 4 & 1) for i in range(len(raw))]
        raw['wlan.fc.fromds'] = [str((i % 4 >> 1) & 1) for i in range(len(raw))]
        pd.testing.assert_frame_equal(awid, detection_features(raw))
        raw.loc[0, ['source_mac', 'destination_mac', 'bssid']] = pd.NA
        self.assertTrue(detection_features(raw).loc[0, ['source_is_bssid', 'destination_is_bssid', 'destination_multicast']].isna().all())

    def test_threshold_is_selected_from_supplied_validation_scores(self):
        y = np.array([0, 0, 0, 1, 1])
        scores = np.array([.1, .2, .4, .7, .8])
        self.assertEqual(select_threshold(y, scores), .7)

    def test_macro_threshold_matches_brute_force_with_different_score_ranges(self):
        targets = [np.array([0,1,0,1]), np.array([1,0,1,0])]
        scores = [np.array([.1,.5,.5,.8]), np.array([.7,.9,.95,.99])]
        threshold = macro_threshold(targets, scores)
        actual = np.mean([f1_score(y,s >= threshold) for y,s in zip(targets,scores)])
        expected = max(np.mean([f1_score(y,s >= t) for y,s in zip(targets,scores)])
                       for t in np.unique(np.concatenate(scores)))
        self.assertEqual(actual, expected)

    def test_new_artifact_reload_chunk_equivalence_and_old_contract(self):
        raw = raw_fixture()
        features = FEATURE_SETS['combined_plus_frame_length'] + DETECTION_FEATURES
        enriched = TemporalFeatureBuilder().transform(raw)
        enriched['frame_length'] = 200.
        for name, column in detection_features(raw).items():
            enriched[name] = column
        x = numeric_features(enriched, features)
        model = next(candidates())[1].fit(x, np.arange(len(raw)) % 2)
        with tempfile.TemporaryDirectory() as folder:
            artifact = Path(folder) / 'v2.joblib'
            joblib.dump({'format_version': 2, 'features': features, 'rssi_window': 100,
                         'model': model, 'threshold': .45}, artifact)
            info = load_model_info(artifact)
            self.assertTrue(info['ready'], info['error'])
            self.assertIsNone(info['benchmark'])
            whole = InferenceSession(artifact).predict_chunk(raw)
            session = InferenceSession(artifact)
            chunked = pd.concat([session.predict_chunk(raw.iloc[:27]), session.predict_chunk(raw.iloc[27:])])
            pd.testing.assert_frame_equal(whole, chunked)
            np.testing.assert_allclose(whole.detection_score, model.predict_proba(x)[:, 1])
            np.testing.assert_array_equal(whole.rogue_ap_prediction, whole.detection_score >= .45)
            self.assertTrue(whole.positive_vote_fraction.isna().all())


if __name__ == '__main__':
    unittest.main()
