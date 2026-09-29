"""Short advertisement windows complement the existing 100-frame history."""
from collections import deque
import numpy as np
import pandas as pd

MULTISCALE_FEATURES=[f'short_{name}_{w}' for w in (5,20) for name in ('rssi_std','rssi_shift','interval_cv','sequence_gap_mean')]

class MultiScaleFeatures:
    def __init__(self,max_bssids=100000):
        self.states={};self.last_time=None;self.max_bssids=max_bssids

    def transform(self,frame):
        output=np.full((len(frame),len(MULTISCALE_FEATURES)),np.nan)
        bssid='bssid' if 'bssid' in frame else '_bssid'
        columns=['timestamp_ns',bssid,'frame_type','frame_subtype','rssi_dbm','ad_beacon_interval_delta_ns','ad_sequence_gap']
        for i,(t,mac,kind,sub,rssi,interval,gap) in enumerate(frame[columns].itertuples(index=False,name=None)):
            t=int(t)
            if self.last_time is not None and t<self.last_time:raise ValueError('Unordered short history')
            self.last_time=t
            if pd.isna(kind) or pd.isna(sub) or kind!=0 or sub not in (5,8):continue
            if pd.isna(mac) or not mac or str(mac).lower()=='ff:ff:ff:ff:ff:ff':continue
            mac=str(mac).lower()
            if mac not in self.states:
                if len(self.states)>=self.max_bssids:raise ValueError('Short history AP limit exceeded')
                self.states[mac]=(t,deque(maxlen=20))
            previous,history=self.states[mac]
            if t-previous>5_000_000_000:history.clear()
            values=[np.nan if pd.isna(v) else float(v) for v in (rssi,interval,gap)]
            history.append(values);self.states[mac]=(t,history)
            arr=np.asarray(history)
            for j,w in enumerate((5,20)):
                r=arr[-w:,0];r=r[np.isfinite(r)]
                intervals=arr[-w:,1];intervals=intervals[np.isfinite(intervals)]
                gaps=arr[-w:,2];gaps=gaps[np.isfinite(gaps)]
                output[i,j*4:j*4+4]=[
                    float(r.std()) if len(r)>1 else np.nan,
                    values[0]-float(r.mean()) if len(r) else np.nan,
                    float(intervals.std()/intervals.mean()) if len(intervals)>1 and intervals.mean()>0 else np.nan,
                    float(gaps.mean()) if len(gaps) else np.nan]
        return pd.DataFrame(output,index=frame.index,columns=MULTISCALE_FEATURES)

def enrich_cache(frame):
    pieces=[]
    for _,f in frame.groupby('_block',sort=False):
        pieces.append(MultiScaleFeatures().transform(f))
    return frame.join(pd.concat(pieces))
