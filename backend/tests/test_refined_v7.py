import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pandas as pd

from backend.refine_v7 import select_threshold
from backend.config import DashboardSettings, PROJECT_ROOT
from backend.dashboard.model_info import load_model_info
from backend.core.ml_engine import InferenceSession
from backend.tests.test_rogue_scope import mixed_frames
from backend.core.target_classifier import TargetFamilyClassifier
from unittest.mock import Mock
from backend.refine_v7_recall import select_recall_threshold
from backend.core.confirmed_classifier import ConfirmedClassifier


class RefinedV7Tests(unittest.TestCase):
    def test_zero_confirmation_threshold_preserves_sensitive_decision(self):
        sensitive, confirmer = Mock(), Mock()
        sensitive.predict_proba.return_value=np.array([[.2,.8],[.9,.1]])
        confirmer.predict_proba.return_value=np.array([[1.,0.],[1.,0.]])
        model=ConfirmedClassifier(sensitive,confirmer,['a'],['b'],.5,0.,.9)
        frame=pd.DataFrame({'a':[0,0],'b':[0,0]})
        self.assertTrue(np.isfinite(model.predict_proba(frame)).all())
        np.testing.assert_array_equal(model.predict(frame),[1,0])

    def test_confirmation_recovery_and_threshold_boundaries(self):
        sensitive, confirmer = Mock(), Mock()
        a=np.array([.7,.7,.1,.6]);b=np.array([.1,.3,.95,.2])
        sensitive.predict_proba.return_value=np.column_stack([1-a,a])
        confirmer.predict_proba.return_value=np.column_stack([1-b,b])
        model=ConfirmedClassifier(sensitive,confirmer,['a'],['b'],.6,.2,.9)
        frame=pd.DataFrame({'a':[0]*4,'b':[0]*4})
        np.testing.assert_array_equal(model.predict(frame),[0,1,1,1])

    def test_recall_constraint_applies_to_each_attack_family(self):
        frames = [pd.DataFrame({'label':['normal','rogue_ap','evil_twin','evil_twin']})]
        scores = [np.array([.7,.3,.8,.9])]
        threshold,_,point = select_recall_threshold(frames,scores)
        self.assertLessEqual(threshold,.3)
        self.assertEqual(point['min_family_recall'],1)

    def test_target_families_sum_without_counting_other_attacks(self):
        estimator = Mock()
        estimator.classes_ = np.array(['beacon_flood','evil_twin','normal','rogue_ap'])
        estimator.predict_proba.return_value = np.array([[.2,.3,.1,.4],[.7,.05,.2,.05]])
        model = TargetFamilyClassifier(estimator,['evil_twin','rogue_ap'])
        np.testing.assert_allclose(model.predict_proba(None),[[.3,.7],[.9,.1]])

    def test_refined_predictions_preserve_history_across_chunks(self):
        path = PROJECT_ROOT/'backend/models/v7_error_reduction_final/trained_ensemble.joblib'
        raw = mixed_frames()
        whole = InferenceSession(path).predict_chunk(raw)
        session = InferenceSession(path)
        chunked = pd.concat([session.predict_chunk(raw.iloc[:23]), session.predict_chunk(raw.iloc[23:])])
        pd.testing.assert_frame_equal(whole, chunked)
        self.assertTrue(whole.iloc[::2].detection_score.isna().all())
        self.assertFalse(whole.iloc[::2].evaluated.any())

    def test_negative_only_source_penalizes_false_alerts(self):
        frames = [pd.DataFrame({'label':['normal','rogue_ap','rogue_ap']}),
                  pd.DataFrame({'label':['normal','beacon_flood']})]
        threshold, _, point = select_threshold(frames,
            [np.array([.1,.85,.95]), np.array([.8,.8])])
        self.assertGreater(threshold,.8)
        self.assertEqual(point['max_fpr'],0)
        self.assertEqual(point['min_recall'],1)

    def test_default_and_benchmark_artifact_are_consistent(self):
        with patch.dict('os.environ', {}, clear=True):
            settings = DashboardSettings()
        self.assertEqual(settings.model_path.parent.name,'v7_error_reduction_final')
        info = load_model_info(settings.model_path)
        self.assertTrue(info['ready'],info)
        self.assertIsNotNone(info['benchmark'])
        self.assertEqual(len(info['regression_benchmarks']),3)
        self.assertGreater(len(info['feature_importance']),5)

    def test_mismatched_regression_hash_is_not_displayed(self):
        source = PROJECT_ROOT/'backend/models/final_v7/trained_ensemble.joblib'
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/source.name
            path.write_bytes(source.read_bytes())
            (path.parent/'new_rogue.json').write_text(json.dumps({'artifact_sha256':'wrong'}))
            info = load_model_info(path)
            self.assertTrue(info['ready'])
            self.assertEqual(info['regression_benchmarks'],[])

if __name__ == '__main__':
    unittest.main()
