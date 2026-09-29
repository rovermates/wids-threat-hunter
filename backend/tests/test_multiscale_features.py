import unittest
import pandas as pd
from backend.core.advertiser_features import AdvertiserFeatureBuilder
from backend.core.multiscale_features import MultiScaleFeatures
from backend.tests import test_advertiser_features

class MultiScaleTests(unittest.TestCase):
    def test_client_is_excluded_and_history_is_chunk_invariant(self):
        raw=test_advertiser_features.AdvertiserFeaturesTests().raw()
        frame=raw.join(AdvertiserFeatureBuilder().transform(raw))
        result=MultiScaleFeatures().transform(frame)
        self.assertTrue(result.iloc[1].isna().all())
        self.assertEqual(result.iloc[-1].short_rssi_std_5,0)
        self.assertEqual(result.iloc[-1].short_sequence_gap_mean_5,1)
        builder=MultiScaleFeatures()
        split=pd.concat([builder.transform(frame.iloc[:2]),builder.transform(frame.iloc[2:])])
        pd.testing.assert_frame_equal(result,split)
        pd.testing.assert_frame_equal(result.iloc[:2],MultiScaleFeatures().transform(frame.iloc[:2]))

    def test_capture_gap_resets_short_history(self):
        raw=test_advertiser_features.AdvertiserFeaturesTests().raw().iloc[[0,2]].copy()
        raw.loc[raw.index[-1],'timestamp_ns']=6_000_000_000
        frame=raw.join(AdvertiserFeatureBuilder().transform(raw))
        self.assertTrue(pd.isna(MultiScaleFeatures().transform(frame).iloc[-1].short_rssi_std_5))

if __name__=='__main__':unittest.main()
