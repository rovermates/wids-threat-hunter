"""Precompute causal history indices for fast, exact full-pipeline selection."""
from collections import deque
import numpy as np
import pandas as pd

class CachedHistoryOperator:
    def __init__(self,frame,policy):
        self.alpha=policy['alpha'];w=policy['window'];gap=policy['max_gap_ns']
        self.indices=np.full((len(frame),w),-1,dtype=np.int64);states={};block_before=object()
        for i,(block,t,mac) in enumerate(zip(frame['_block'],frame.timestamp_ns,frame['_bssid'])):
            if block!=block_before:states={};block_before=block
            if pd.isna(mac) or not mac or str(mac).lower()=='ff:ff:ff:ff:ff:ff':
                self.indices[i,0]=i;continue
            mac=str(mac).lower();previous,history=states.get(mac,(int(t),deque(maxlen=w)))
            if int(t)-previous>gap:history.clear()
            history.append(i);states[mac]=(int(t),history)
            self.indices[i,:len(history)]=history
        self.valid=self.indices>=0;self.safe=np.maximum(self.indices,0);self.count=self.valid.sum(axis=1)

    def apply(self,scores):
        scores=np.asarray(scores,dtype=float)
        if scores.shape!=(len(self.indices),) or not np.isfinite(scores).all():raise ValueError('Expected finite advertisement scores')
        means=np.where(self.valid,scores[self.safe],0).sum(axis=1)/self.count
        return self.alpha*scores+(1-self.alpha)*means
