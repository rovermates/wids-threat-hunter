import unittest
import pandas as pd
import numpy as np
from backend.train_additional_captures import operating_point
class AdditionalTrainingTests(unittest.TestCase):
 def test_negative_only_source_constrains_selection(self):
  frames=[pd.DataFrame({'label':['normal','rogue_ap']}),pd.DataFrame({'label':['beacon_flood','normal']})]
  threshold,passed,point=operating_point(frames,[np.array([.1,.9]),np.array([.8,.2])])
  self.assertTrue(passed);self.assertGreater(threshold,.8);self.assertEqual(point['minimum_family_recall'],1.)
 def test_conflicting_positive_and_negative_scores_cannot_pass(self):
  frames=[pd.DataFrame({'label':['normal','rogue_ap']}),pd.DataFrame({'label':['beacon_flood','normal']})]
  _,passed,_=operating_point(frames,[np.array([.1,.8]),np.array([.9,.2])])
  self.assertFalse(passed)
if __name__=='__main__':unittest.main()
