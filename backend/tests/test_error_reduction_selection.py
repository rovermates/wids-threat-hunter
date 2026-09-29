import unittest
import numpy as np
from backend.reduce_v7_errors import select

class SelectionTests(unittest.TestCase):
    def test_equal_validation_decisions_disable_unnecessary_recovery(self):
        result=select([np.array([True,False])],[np.array([1.,0.])],
                      [np.array([.8,.2])],[[1,0,0,1]])
        self.assertEqual(result['recovery'],1.000001)
        self.assertEqual(result['confusion'],[[1,0,0,1]])

    def test_one_source_cannot_trade_errors_for_another(self):
        y=[np.array([True,False]),np.array([True,False])]
        a=[np.array([1.,0.]),np.array([1.,0.])]
        b=[np.array([.9,.1]),np.array([0.,0.])]
        result=select(y,a,b,[[1,0,0,1],[1,0,0,1]])
        self.assertEqual(result['confusion'],[[1,0,0,1],[1,0,0,1]])

if __name__=='__main__':unittest.main()
