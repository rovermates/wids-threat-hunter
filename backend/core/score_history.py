"""Causal per-advertiser score history; never mix APs or look ahead."""
from collections import deque
import math
import numpy as np
import pandas as pd

class ScoreHistory:
    def __init__(self, window=9, alpha=.75, max_gap_ns=5_000_000_000, max_bssids=100000):
        if isinstance(window,bool) or not isinstance(window,int) or window<1:
            raise ValueError('window must be a positive integer')
        if not 0<=alpha<=1 or max_gap_ns<=0 or max_bssids<1:
            raise ValueError('Invalid score history settings')
        self.window=window;self.alpha=alpha;self.max_gap_ns=max_gap_ns;self.max_bssids=max_bssids
        self.states={};self.last_time=None

    def transform(self, scores, timestamps, bssids):
        if not len(scores)==len(timestamps)==len(bssids):raise ValueError('Unaligned score history inputs')
        out=np.asarray(scores,dtype=float).copy()
        for i,(score,t,mac) in enumerate(zip(out,timestamps,bssids)):
            t=int(t)
            if self.last_time is not None and t<self.last_time:raise ValueError('Unordered score history')
            self.last_time=t
            if not math.isfinite(score):continue
            if pd.isna(mac) or not mac or str(mac).lower()=='ff:ff:ff:ff:ff:ff':continue
            mac=str(mac).lower()
            if mac not in self.states:
                if len(self.states)>=self.max_bssids:raise ValueError('Score history AP limit exceeded')
                self.states[mac]=(t,deque(maxlen=self.window))
            previous,history=self.states[mac]
            if t-previous>self.max_gap_ns:history.clear()
            history.append(float(score));self.states[mac]=(t,history)
            out[i]=self.alpha*score+(1-self.alpha)*sum(history)/len(history)
        return out

def score_cached_blocks(frame,scores,policy):
    """Caches reset feature state at each block; match that boundary exactly."""
    output=np.asarray(scores,dtype=float).copy()
    blocks=frame['_block'].to_numpy() if '_block' in frame else np.zeros(len(frame))
    previous=object();history=None
    for i,(block,t,mac) in enumerate(zip(blocks,frame.timestamp_ns,frame['_bssid'])):
        if block!=previous:history=ScoreHistory(**policy);previous=block
        output[i]=history.transform([scores[i]],[t],[mac])[0]
    return output
