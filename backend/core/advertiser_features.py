"""Versioned advertisement-only history: client frames cannot distort AP evidence."""
import pandas as pd
import numpy as np
from backend.core.feature_builder import TemporalFeatureBuilder,FEATURE_DTYPES
from backend.core.ap_behavior import APBehaviorBuilder,AP_FEATURES

ADVERTISER_FEATURES=['ad_'+n for n in list(FEATURE_DTYPES)+AP_FEATURES]

class AdvertiserFeatureBuilder:
    def __init__(self,window=100):
        self.temporal=TemporalFeatureBuilder(window)
        self.behavior=APBehaviorBuilder(window)

    def transform(self,raw):
        output=pd.DataFrame(np.nan,index=raw.index,columns=ADVERTISER_FEATURES)
        advertisements=raw.loc[(raw.frame_type.eq(0)&raw.frame_subtype.isin([5,8])).fillna(False)]
        if advertisements.empty:return output
        temporal=self.temporal.transform(advertisements)
        behavior=self.behavior.transform(advertisements)
        for name in FEATURE_DTYPES:
            output.loc[advertisements.index,'ad_'+name]=temporal[name].astype(float)
        for name in AP_FEATURES:
            output.loc[advertisements.index,'ad_'+name]=behavior[name]
        return output
