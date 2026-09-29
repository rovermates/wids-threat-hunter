import unittest
import numpy as np
import pandas as pd
from backend.core.score_history import ScoreHistory,score_cached_blocks

class ScoreHistoryTests(unittest.TestCase):
    def test_benchmark_and_live_inference_agree_on_eligible_frames(self):
        from backend.config import DashboardSettings
        from backend.core.ml_engine import InferenceSession
        from backend.benchmark_detection import score_bundle
        from backend.tests.test_rogue_scope import mixed_frames
        session=InferenceSession(DashboardSettings().model_path)
        predictions,enriched=session.predict_with_features(mixed_frames())
        selected=enriched.loc[predictions.evaluated].copy()
        selected['_bssid']=selected.bssid;selected['_block']=0
        pred,score=score_bundle(session.bundle,selected)
        np.testing.assert_array_equal(pred,predictions.loc[predictions.evaluated,'rogue_ap_prediction'])
        np.testing.assert_allclose(score,predictions.loc[predictions.evaluated,'detection_score'])

    def test_isolation_gaps_missing_and_chunk_boundaries(self):
        scores=[0.,1.,1.,np.nan,0.,1.]
        times=[0,1,2,3,4,6_000_000_000]
        macs=['a','b','a','a','b','a']
        whole=ScoreHistory(window=3,alpha=.5).transform(scores,times,macs)
        np.testing.assert_allclose(whole,[0,1,.75,np.nan,.25,1],equal_nan=True)
        h=ScoreHistory(window=3,alpha=.5)
        split=np.r_[h.transform(scores[:3],times[:3],macs[:3]),h.transform(scores[3:],times[3:],macs[3:])]
        np.testing.assert_allclose(whole,split,equal_nan=True)
        np.testing.assert_allclose(whole[:3],ScoreHistory(window=3,alpha=.5).transform(scores[:3],times[:3],macs[:3]))

    def test_cached_block_boundaries_match_capture_reset(self):
        frame=pd.DataFrame({'_block':[0,0,1,1],'timestamp_ns':[0,1,2,3],'_bssid':['a']*4})
        np.testing.assert_allclose(score_cached_blocks(frame,[0,1,1,0],{'window':3,'alpha':.5}),[0,.75,1,.25])

    def test_unattributed_predictions_are_not_pooled(self):
        np.testing.assert_allclose(ScoreHistory().transform([0,1],[0,1],[None,None]),[0,1])

    def test_unordered_and_resource_limits_fail_explicitly(self):
        with self.assertRaisesRegex(ValueError,'Unordered'):
            ScoreHistory().transform([0,1],[1,0],['a','a'])
        with self.assertRaisesRegex(ValueError,'limit'):
            ScoreHistory(max_bssids=1).transform([0,1],[0,1],['a','b'])

if __name__=='__main__':unittest.main()
