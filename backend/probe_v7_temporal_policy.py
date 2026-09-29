"""Validation-only feasibility check for causal score smoothing; does not deploy."""
import json
from pathlib import Path
import joblib,numpy as np,pandas as pd
from threadpoolctl import threadpool_limits
from backend.reduce_v7_errors import BASE,NAMES
from backend.core.score_history import score_cached_blocks

def run(artifact=BASE, output='docs/v7-temporal-policy-validation.json', cache_prefix='ad_'):
    bundle=joblib.load(artifact);frames=[joblib.load(f'data/processed/{cache_prefix}{n}.joblib')['data']['validation'].reset_index(drop=True) for n in NAMES]
    with threadpool_limits(limits=4):scores=[bundle['model'].predict_proba(f[bundle['features']].astype(float))[:,1] for f in frames]
    ys=[f.label.isin(bundle['target_labels']).to_numpy() for f in frames]
    base=[(int(((s>=.5)&y).sum()),int(((s>=.5)&~y).sum())) for s,y in zip(scores,ys)]
    results=[]
    for window in [3,5,9,15]:
        rolling=[]
        for f,s in zip(frames,scores):
            rolling.append(score_cached_blocks(f,s,{'window':window,'alpha':0,'max_gap_ns':5_000_000_000}))
        for alpha in [0,.25,.5,.75]:
            for instant in [False,True]:
                adjusted=[np.where(s>=.99,s,alpha*s+(1-alpha)*r) if instant else alpha*s+(1-alpha)*r for s,r in zip(scores,rolling)]
                thresholds=np.unique(np.concatenate(adjusted));good=np.ones(len(thresholds),bool);f1=[];counts=[]
                for s,y,(bt,bf) in zip(adjusted,ys,base):
                    pos=np.sort(s[y]);neg=np.sort(s[~y]);tp=len(pos)-np.searchsorted(pos,thresholds);fp=len(neg)-np.searchsorted(neg,thresholds)
                    good&=(tp>=bt)&(fp<=bf);counts.append((tp,fp))
                    if len(pos):f1.append(2*tp/np.maximum(tp+fp+len(pos),1))
                if not good.any():continue
                utility=np.mean(f1,axis=0);i=int(np.argmax(np.where(good,utility,-1)))
                results.append({'window':window,'alpha':alpha,'instant':instant,'threshold':float(thresholds[i]),'mean_f1':float(utility[i]),'tp_fp':[[int(t[i]),int(f[i])] for t,f in counts]})
    results.sort(key=lambda x:x['mean_f1'],reverse=True)
    Path(output).write_text(json.dumps(results,indent=2));print(json.dumps(results[:3]),flush=True)

if __name__=='__main__':run()
