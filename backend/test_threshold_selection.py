"""Training-only selection checks (requires optional CatBoost dependency)."""
import unittest
import numpy as np
from backend.train_v7_hard_negatives import select_threshold,counts

class ThresholdSelectionTests(unittest.TestCase):
    def test_exact_selection_matches_brute_force_with_ties(self):
        ys=[np.array([False,False,True,True]),np.array([False,False])]
        scores=[np.array([.1,.4,.4,.7]),np.array([.1,.2])]
        baseline=[[1,1,1,1],[1,1,0,0]]
        result=select_threshold(ys,scores,baseline,.5)
        candidates=[]
        for t in np.unique(np.r_[.5,np.concatenate(scores)]):
            cm=[counts(y,s>=t) for y,s in zip(ys,scores)]
            if any(c[1]>b[1] or c[2]>b[2] for c,b in zip(cm,baseline)):continue
            f1=2*cm[0][3]/(2*cm[0][3]+cm[0][1]+cm[0][2])
            candidates.append((f1-.2*cm[1][1]/2,-sum(c[1]+c[2] for c in cm),-abs(t-.5),t))
        self.assertEqual(result['threshold'],max(candidates)[-1])
        self.assertEqual(result['confusion'],[counts(y,s>=result['threshold']) for y,s in zip(ys,scores)])

    def test_conflicting_constraints_return_none(self):
        result=select_threshold([np.array([False,True])],[np.array([.9,.1])],[[1,0,0,1]],.5)
        self.assertIsNone(result)

if __name__=='__main__':unittest.main()
