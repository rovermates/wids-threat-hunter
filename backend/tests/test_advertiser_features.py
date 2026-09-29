import unittest
import pandas as pd
from backend.core.advertiser_features import AdvertiserFeatureBuilder
from backend.core.feature_builder import TemporalFeatureBuilder
from backend.tests.test_feature_builder import frames

class AdvertiserFeaturesTests(unittest.TestCase):
    def raw(self):
        raw=frames([(0,'aa:bb:cc:dd:ee:00','lab',-40,100,0,8),
                    (100_000_000,'aa:bb:cc:dd:ee:00',None,-90,3000,2,0),
                    (200_000_000,'aa:bb:cc:dd:ee:00','lab',-40,101,0,8)])
        raw['source_mac']=['aa:bb:cc:dd:ee:00','aa:bb:cc:dd:ee:01','aa:bb:cc:dd:ee:00']
        raw['destination_mac']='ff:ff:ff:ff:ff:ff'
        return raw

    def test_client_rssi_and_sequence_do_not_contaminate_advertiser(self):
        raw=self.raw();old=TemporalFeatureBuilder().transform(raw)
        fixed=AdvertiserFeatureBuilder().transform(raw)
        self.assertGreater(old.rssi_std_db.iloc[-1],20)
        self.assertGreater(old.sequence_gap.iloc[-1],1000)
        self.assertEqual(fixed.ad_rssi_std_db.iloc[-1],0)
        self.assertEqual(fixed.ad_sequence_gap.iloc[-1],1)
        self.assertEqual(fixed.ad_ap_window_count.iloc[-1],2)
        self.assertTrue(fixed.iloc[1].isna().all())

    def test_chunk_boundaries_and_prefix_causality(self):
        raw=self.raw();whole=AdvertiserFeatureBuilder().transform(raw)
        builder=AdvertiserFeatureBuilder()
        split=pd.concat([builder.transform(raw.iloc[:2]),builder.transform(raw.iloc[2:])])
        pd.testing.assert_frame_equal(whole,split)
        pd.testing.assert_frame_equal(whole.iloc[:2],AdvertiserFeatureBuilder().transform(raw.iloc[:2]))

if __name__=='__main__':unittest.main()
