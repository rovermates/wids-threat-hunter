"""Different model family, selected after the complete causal scoring pipeline."""
import json,time,hashlib
from pathlib import Path
import joblib,numpy as np,pandas as pd
from catboost import CatBoostClassifier
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from threadpoolctl import threadpool_limits
from backend.core.evidence_refiner import EvidenceRefiner,refine_scores
from backend.causal_selection import CachedHistoryOperator
from backend.train_additional_captures import TARGETS
from backend.reduce_v7_errors import NAMES as ORIGINAL_NAMES
NAMES=ORIGINAL_NAMES+['disasso']

BASE=Path('backend/models/v7_error_reduction_final/trained_ensemble.joblib')
OUT=Path('backend/models/v7_hard_negatives')

def counts(y,p):return [int((~y&~p).sum()),int((~y&p).sum()),int((y&~p).sum()),int((y&p).sum())]

def select_threshold(ys,scores,baseline,reference):
    # Every decision boundary is considered using sorted scores, without fitting
    # or looking at test rows. A threshold must satisfy every source constraint.
    thresholds=np.unique(np.r_[reference,np.concatenate(scores)])
    feasible=np.ones(len(thresholds),dtype=bool);matrices=[];f1=[]
    for y,s,old in zip(ys,scores,baseline):
        positives=np.sort(s[y]);negatives=np.sort(s[~y])
        tp=len(positives)-np.searchsorted(positives,thresholds,side='left')
        fp=len(negatives)-np.searchsorted(negatives,thresholds,side='left')
        fn=len(positives)-tp;tn=len(negatives)-fp
        feasible&=(fp<=old[1])&(fn<=old[2]);matrices.append((tn,fp,fn,tp))
        if len(positives):f1.append(2*tp/np.maximum(2*tp+fp+fn,1))
    if not feasible.any():return None
    mean=np.mean(f1,axis=0);utility=mean-.2*matrices[-1][1]/max(len(ys[-1]),1)
    indices=np.flatnonzero(feasible)
    i=max(indices,key=lambda i:(utility[i],-sum(m[1][i]+m[2][i] for m in matrices),-abs(thresholds[i]-reference)))
    return {'threshold':float(thresholds[i]),'mean_f1':float(mean[i]),'utility':float(utility[i]),
        'confusion':[[int(a[i]) for a in m] for m in matrices]}

def choose(ys,raw,bs,operators,baseline,threshold):
    grid=np.unique(np.r_[0,np.quantile(np.concatenate(bs),np.linspace(0,1,45))])
    best=None
    for recovery in [None,.5,.75,.9,.99]:
        for confirm in grid:
            scores=[op.apply(refine_scores(a,b,threshold,confirm,recovery)) for a,b,op in zip(raw,bs,operators)]
            point=select_threshold(ys,scores,baseline,threshold)
            if point is None:continue
            key=(point['utility'],-sum(c[1]+c[2] for c in point['confusion']),recovery is None,-float(confirm))
            if best is None or key>best[0]:best=(key,{**point,'confirmation':float(confirm),'recovery':recovery})
    return best[1] if best else None

def run():
    OUT.mkdir(exist_ok=False);old=joblib.load(BASE);features=old['features'];train=[];vals=[]
    for name in NAMES:
        d=joblib.load(f'data/processed/multi_{name}.joblib')['data'];f=d['train'].copy();f['_source']=name
        train.append(f);vals.append(d['validation'].reset_index(drop=True))
    train=pd.concat(train,ignore_index=True);y=train.label.isin(TARGETS).astype(int)
    ys=[f.label.isin(TARGETS).to_numpy() for f in vals];ops=[CachedHistoryOperator(f,old['score_history']) for f in vals]
    protocol={'baseline_sha256':hashlib.sha256(BASE.read_bytes()).hexdigest(),'test_rows_fitted':0,
        'new_development':'Disasso train and validation blocks; its test blocks and complete Aggreattack reserved.',
        'selection':'Full causal pipeline and validation-only decision threshold; no validation-source FP/FN increase.',
        'aspirational_target':'FNR <= 5% and FPR <= 1% on each source, not a promised result.',
        'limitations':'Previously consumed regression datasets; scenario labels are not verified rogue identities.'}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2));trials=[];best=-1
    with threadpool_limits(limits=4):
        raw=[old['model'].predict_proba(f[features].astype(float))[:,1] for f in vals]
        baseline=[counts(z,op.apply(a)>=old['threshold']) for z,a,op in zip(ys,raw,ops)]
        size=train.groupby('_source').size()
        for depth in [4,6]:
            for power in [0.,.5,1.]:
                start=time.perf_counter();weights=train['_source'].map((len(train)/len(size)/size)**power).to_numpy(copy=True)
                weights*=np.where(y,2.,1.);weights/=weights.mean()
                model=Pipeline([('imputer',SimpleImputer(strategy='median',add_indicator=True,keep_empty_features=True)),
                    ('model',CatBoostClassifier(iterations=450,depth=depth,learning_rate=.06,l2_leaf_reg=5,
                        thread_count=4,random_seed=211,verbose=False,allow_writing_files=False))])
                model.fit(train[features].astype(float),y,model__sample_weight=weights)
                bs=[model.predict_proba(f[features].astype(float))[:,1] for f in vals]
                point=choose(ys,raw,bs,ops,baseline,old['threshold'])
                trial={'name':f'cat450_depth{depth}_source{power}','seconds':time.perf_counter()-start,'selection':point}
                trials.append(trial);(OUT/'experiments.json').write_text(json.dumps(trials,indent=2));print(json.dumps(trial),flush=True)
                if point and point['utility']>best:
                    best=point['utility'];bundle={**old,'model':EvidenceRefiner(old['model'],model,features,old['threshold'],point['confirmation'],point['recovery']),
                        'threshold':point['threshold'],'model_name':'v7-hard-negative-catboost','selection':trial,'training_metadata':protocol}
                    bundle.pop('feature_importance',None);bundle.pop('importance_method',None)
                    joblib.dump(bundle,OUT/'trained_ensemble.joblib',compress=3)
    sha=hashlib.sha256((OUT/'trained_ensemble.joblib').read_bytes()).hexdigest()
    (OUT/'FROZEN.json').write_text(json.dumps({'sha256':sha,'test_predictions_used_for_selection':False},indent=2));print('FROZEN',sha,flush=True)

if __name__=='__main__':run()
