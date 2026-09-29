import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from backend.core.feature_builder import TemporalFeatureBuilder
from backend.core.ml_engine import (FEATURE_SETS, InferenceSession, make_ensemble,
                                     numeric_features, vote_score, protocol_features, PROTOCOL_FIELDS)
from backend.train_ensemble import metrics
from backend.predict import predict_file


def fixture():
    return pd.DataFrame({'timestamp_ns': pd.array(np.arange(80) * 100000000, dtype='Int64'),
        'bssid': ['00:11:22:33:44:55'] * 80, 'ssid': ['example'] * 80,
        'rssi_dbm': pd.array([-70 + i % 7 for i in range(80)], dtype='Int16'),
        'sequence_number': pd.array(np.arange(80), dtype='Int16'),
        'frame_type': pd.array([0] * 80, dtype='Int8'),
        'frame_subtype': pd.array([8] * 80, dtype='Int8')})


class EngineTests(unittest.TestCase):
    def test_protocol_alias_parity_and_missing_values(self):
        awid = pd.DataFrame({aliases[0]: ['100', '?', '0'] for aliases in PROTOCOL_FIELDS.values()})
        pcap = pd.DataFrame({aliases[1]: ['100', '', '0,1'] for aliases in PROTOCOL_FIELDS.values()})
        pd.testing.assert_frame_equal(protocol_features(awid), protocol_features(pcap))
        pcap['wlan.fc.retry'] = [True, False, True]
        self.assertEqual(protocol_features(pcap).retry_flag.tolist(), [1., 0., 1.])
        with self.assertRaises(ValueError):
            protocol_features(pd.DataFrame())
        awid['frame.len'] = 'bad'
        with self.assertRaises(ValueError):
            protocol_features(awid)

    def test_extended_pipeline_reload_matches_offline_features(self):
        raw = fixture()
        for aliases in PROTOCOL_FIELDS.values():
            raw[aliases[1]] = '0'
        raw['frame.len'] = [str(100 + i % 5) for i in range(len(raw))]
        frame = TemporalFeatureBuilder().transform(raw)
        for name, column in protocol_features(raw).items():
            frame[name] = column
        features = FEATURE_SETS['combined_plus_frame_length']
        x = numeric_features(frame, features)
        model = make_ensemble().fit(x, np.arange(80) % 2)
        with tempfile.TemporaryDirectory() as folder:
            artifact = Path(folder) / 'model.joblib'
            joblib.dump({'format_version': 1, 'features': features, 'rssi_window': 100,
                         'model': model}, artifact)
            session = InferenceSession(artifact)
            result = pd.concat([session.predict_chunk(raw.iloc[:17]), session.predict_chunk(raw.iloc[17:])])
            np.testing.assert_array_equal(result.rogue_ap_prediction, model.predict(x))

    def test_contract_and_training_only_scaler(self):
        features = FEATURE_SETS['combined']
        frame = TemporalFeatureBuilder().transform(fixture())
        x = numeric_features(frame, features)
        model = make_ensemble()
        model.fit(x.iloc[:60], np.arange(60) % 2)
        before = model.named_estimators_['svm'].named_steps['scaler'].mean_.copy()
        future = x.iloc[60:].copy()
        future['rssi_dbm'] = 100000
        model.predict(future)
        np.testing.assert_array_equal(before, model.named_estimators_['svm'].named_steps['scaler'].mean_)
        with self.assertRaises(ValueError):
            numeric_features(frame, ['timestamp_ns'])
        with self.assertRaises(ValueError):
            numeric_features(frame.drop(columns='rssi_dbm'), features)
        frame.loc[0, 'rssi_std_db'] = np.inf
        with self.assertRaises(ValueError):
            numeric_features(frame, features)
        self.assertEqual(model.named_estimators_['rf'].named_steps['model'].n_estimators, 100)
        svm = model.named_estimators_['svm'].named_steps['model']
        self.assertEqual((svm.loss, svm.penalty, svm.max_iter), ('hinge', 'l2', 1000))

    def test_reload_chunk_equivalence_and_capture_reset(self):
        raw = fixture()
        features = FEATURE_SETS['combined']
        enriched = TemporalFeatureBuilder().transform(raw)
        x = numeric_features(enriched, features)
        model = make_ensemble().fit(x, np.arange(80) % 2)
        bundle = {'format_version': 1, 'features': features, 'rssi_window': 100, 'model': model}
        with tempfile.TemporaryDirectory() as folder:
            artifact = Path(folder) / 'model.joblib'
            joblib.dump(bundle, artifact)
            session = InferenceSession(artifact)
            chunked = pd.concat([session.predict_chunk(raw.iloc[:13]), session.predict_chunk(raw.iloc[13:])])
            whole = InferenceSession(artifact).predict_chunk(raw)
            pd.testing.assert_frame_equal(chunked, whole)
            np.testing.assert_array_equal(whole.rogue_ap_prediction, model.predict(x))
            np.testing.assert_array_equal(whole.positive_vote_fraction, vote_score(model, x))

    def test_metrics_and_vote_ties(self):
        result = metrics(np.array([0, 0, 1, 1]), [0, 1, 0, 1], [0, .5, .5, 1])
        self.assertEqual(result['f1'], .5)
        self.assertEqual(result['confusion_matrix_tn_fp_fn_tp'], [1, 1, 1, 1])
        self.assertIsNone(metrics(np.array([0, 0]), [0, 1], [0, 1])['average_precision'])
        raw = fixture()
        x = numeric_features(TemporalFeatureBuilder().transform(raw), FEATURE_SETS['combined'])
        model = make_ensemble().fit(x, np.arange(80) % 2)
        votes = model.transform(x)
        np.testing.assert_array_equal(model.predict(x), (votes.sum(axis=1) > 1).astype(int))

    def test_inference_export_failure_is_atomic(self):
        raw = fixture()
        features = FEATURE_SETS['combined']
        x = numeric_features(TemporalFeatureBuilder().transform(raw), features)
        model = make_ensemble().fit(x, np.arange(80) % 2)
        with tempfile.TemporaryDirectory() as folder:
            artifact = Path(folder) / 'model.joblib'
            output = Path(folder) / 'output.jsonl'
            joblib.dump({'format_version': 1, 'features': features, 'rssi_window': 100,
                         'model': model}, artifact)
            def broken():
                yield raw
                raise ValueError('Late input failure')
            with patch('backend.predict.iter_awid_chunks', return_value=broken()):
                with self.assertRaisesRegex(ValueError, 'Late input failure'):
                    predict_file('unused', artifact, output, source_format='awid')
            self.assertFalse(output.exists())
            self.assertEqual(list(Path(folder).glob('*.partial')), [])
            output.write_text('preserve', encoding='utf-8')
            with self.assertRaises(FileExistsError):
                predict_file('unused', artifact, output, source_format='awid')
            self.assertEqual(output.read_text(), 'preserve')


if __name__ == '__main__':
    unittest.main()
