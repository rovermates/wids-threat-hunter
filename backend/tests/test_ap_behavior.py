import tempfile
from pathlib import Path
import unittest
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from backend.core.ap_behavior import APBehaviorBuilder,AP_FEATURES
from backend.core.ml_engine import InferenceSession
from backend.tests.test_detection_improvement import raw_fixture
from backend.train_precision import operating_point


class APBehaviorTests(unittest.TestCase):
    def test_causal_chunk_parity_and_no_identity_or_label_inputs(self):
        raw=raw_fixture(); raw['wlan.fc.protected']='0'; raw['wlan.fc.retry']='0'
        whole=APBehaviorBuilder(7).transform(raw)
        builder=APBehaviorBuilder(7)
        chunked=pd.concat([builder.transform(raw.iloc[:19]),builder.transform(raw.iloc[19:])])
        pd.testing.assert_frame_equal(whole,chunked)
        altered=raw.copy();altered['label']='anything';altered['timestamp_ns']+=100000000000
        altered['bssid']=altered['source_mac']='02:aa:bb:cc:dd:ee'
        pd.testing.assert_frame_equal(whole,APBehaviorBuilder(7).transform(altered))
        changed=raw.copy();changed.loc[changed.index[30]:,'frame.len']='999'
        pd.testing.assert_frame_equal(whole.iloc[:30],APBehaviorBuilder(7).transform(changed).iloc[:30])

    def test_window_expiration_and_changes(self):
        raw=raw_fixture().iloc[:4].copy()
        raw['bssid']=raw['source_mac']='02:00:00:00:00:01'
        raw['frame_type']=0;raw['frame_subtype']=[8,11,8,8]
        raw['wlan.fixed.capabilities.privacy']=['0','0','1','1']
        raw['wlan.ds.current_channel']=['1','1','6','6']
        raw['frame.len']=['100','200','300','400']
        out=APBehaviorBuilder(2).transform(raw)
        self.assertEqual(out.ap_length_mean.iloc[-1],350)
        self.assertEqual(out.ap_length_std.iloc[-1],50)
        self.assertEqual(out.ap_beacon_fraction.iloc[-1],1)
        self.assertEqual(out.ap_security_changes.iloc[-1],1)
        self.assertEqual(out.ap_channel_changes.iloc[-1],1)
        raw['bssid']=pd.NA
        self.assertTrue(APBehaviorBuilder().transform(raw).ap_window_count.isna().all())

    def test_multiclass_inference_uses_named_target_not_column_one(self):
        raw=raw_fixture();features=APBehaviorBuilder().transform(raw)
        labels=np.resize(np.array(['normal','evil_twin','cafe_latte','authentication_request']),len(raw))
        model=Pipeline([('imputer',SimpleImputer(keep_empty_features=True)),
                        ('model',RandomForestClassifier(n_estimators=8,random_state=42))]).fit(features,labels)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'model.joblib'
            joblib.dump({'format_version':3,'model':model,'features':AP_FEATURES,'threshold':.4,'rssi_window':100,'behavior_window':100},path)
            session=InferenceSession(path)
            actual=pd.concat([session.predict_chunk(raw.iloc[:23]),session.predict_chunk(raw.iloc[23:])])
            self.assertNotEqual(list(model.classes_).index('evil_twin'),1)
            expected=model.predict_proba(features)[:,list(model.classes_).index('evil_twin')]
            np.testing.assert_allclose(actual.detection_score,expected)
            np.testing.assert_array_equal(actual.rogue_ap_prediction,expected>=.4)

    def test_selection_reports_unmet_gates(self):
        ys=[np.array([0,0,1,1]),np.array([0,0,1,1])]
        _,met,_=operating_point(ys,[np.array([.1,.2,.8,.9])]*2)
        self.assertTrue(met)
        _,met,_=operating_point(ys,[np.array([.8,.9,.1,.2])]*2)
        self.assertFalse(met)


if __name__=='__main__':unittest.main()
