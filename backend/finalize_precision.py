"""Save validation tradeoffs and optional model explanations before test scoring."""
import argparse,hashlib,json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance
from sklearn.metrics import average_precision_score,precision_recall_curve
from threadpoolctl import threadpool_limits
from backend.train_precision import target_scores
from backend.train_ensemble import metrics


def finalize(folder, awid_cache='behavior_train'):
    folder=Path(folder);artifact=folder/'trained_ensemble.joblib';bundle=joblib.load(artifact)
    frames=[joblib.load('data/processed/'+name+'.joblib')['data']['validation'] for name in [awid_cache,'behavior_wpa3']]
    if bundle.get('scope')=='ap_advertisements':
        frames=[f.loc[(f.frame_type==0)&f.frame_subtype.isin([5,8])] for f in frames]
    reports={}
    with threadpool_limits(limits=4):
        for name,frame in zip(['AWID','WPA3'],frames):
            y=frame.label.isin(bundle.get('target_labels',['evil_twin'])).to_numpy(dtype=int)
            s=target_scores(bundle['model'],frame[bundle['features']].astype(float))
            p,r,t=precision_recall_curve(y,s);indices=np.unique(np.linspace(0,len(t)-1,min(1000,len(t)),dtype=int))
            reports[name]={'pr_curve':{'threshold':t[indices].tolist(),'precision':p[indices].tolist(),'recall':r[indices].tolist()},
                'operating_points':[{ 'threshold':v,'metrics':metrics(y,s>=v,s)} for v in sorted(set([.1,.25,.5,.75,.9,.95,bundle['threshold']]))]}
        if not hasattr(bundle['model'].named_steps['model'],'feature_importances_'):
            sample=pd.concat([pd.concat([f[f.label.isin(bundle.get('target_labels',['evil_twin']))].sample(n=min(500,int(f.label.isin(bundle.get('target_labels',['evil_twin'])).sum())),random_state=42),
                            f[~f.label.isin(bundle.get('target_labels',['evil_twin']))].sample(n=min(4000,int((~f.label.isin(bundle.get('target_labels',['evil_twin']))).sum())),random_state=42)]) for f in frames])
            y=sample.label.isin(bundle.get('target_labels',['evil_twin'])).to_numpy(dtype=int)
            result=permutation_importance(bundle['model'],sample[bundle['features']].astype(float),y,
                scoring=lambda model,x,y:average_precision_score(y,target_scores(model,x)),n_repeats=3,random_state=42,n_jobs=1)
            positive=np.maximum(0,result.importances_mean);total=sum(positive)
            bundle['feature_importance']=sorted([{'feature':n,'importance':float(v/total) if total else 0.}
                for n,v in zip(bundle['features'],positive)],key=lambda v:v['importance'],reverse=True)
            bundle['importance_method']='Normalized positive validation permutation importance (average precision)'
            joblib.dump(bundle,artifact,compress=3)
    meta={k:v for k,v in bundle.items() if k!='model'}
    meta['artifact_sha256']=hashlib.sha256(artifact.read_bytes()).hexdigest()
    (folder/'metadata.json').write_text(json.dumps(meta,indent=2),encoding='utf8')
    (folder/'validation_tradeoffs.json').write_text(json.dumps(reports,indent=2),encoding='utf8')
    (folder/'FROZEN.json').write_text(json.dumps({'artifact_sha256':meta['artifact_sha256'],'test_predictions_used':False}),encoding='utf8')
    print('Finalized',meta['artifact_sha256'],flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder');p.add_argument('--awid-cache',default='behavior_train');a=p.parse_args();finalize(a.folder,a.awid_cache)
