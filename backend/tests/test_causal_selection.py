import unittest
import numpy as np
import pandas as pd
from backend.causal_selection import CachedHistoryOperator
from backend.core.score_history import score_cached_blocks
from backend.core.evidence_refiner import refine_scores

class CausalSelectionTests(unittest.TestCase):
    def test_vectorized_search_matches_streaming_with_resets_and_missing_ids(self):
        frame=pd.DataFrame({'_block':[0,0,0,0,0,0,1,1],
            'timestamp_ns':[0,1,2,3,4,7_000_000_000,8_000_000_000,8_000_000_001],
            '_bssid':['a','b','a',None,'ff:ff:ff:ff:ff:ff','a','a','a']})
        policy={'window':3,'alpha':.75,'max_gap_ns':5_000_000_000}
        scores=np.array([0,.5,1,.3,.2,.8,.9,.1])
        np.testing.assert_allclose(CachedHistoryOperator(frame,policy).apply(scores),score_cached_blocks(frame,scores,policy),rtol=1e-14)

    def test_disabled_refinement_preserves_every_score_exactly(self):
        a=np.array([0,.001,.4993664,.99,1.]);b=np.array([1,0,.9,.2,.1])
        np.testing.assert_array_equal(refine_scores(a,b,.4993664,0,None),a)

    def test_confirmation_does_not_create_alerts_without_recovery(self):
        a=np.array([.2,.8]);b=np.array([1,0])
        np.testing.assert_allclose(refine_scores(a,b,.5,.2,None),[.2,0])

if __name__=='__main__':unittest.main()
