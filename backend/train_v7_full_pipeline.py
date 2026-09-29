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
from backend.reduce_v7_errors import NAMES

BASE=Path('backend/models/v7_error_reduction_final/trained_ensemble.joblib')
OUT=Path('backend/models/v7_full_pipeline')

def counts(y,p):return [int((~y&~p).sum()),int((~y&p).sum()),int((y&~p).sum()),int((y&p).sum())]

def choose(ys,raw,bs,operators,baseline,threshold):
    grid=np.unique(np.r_[0,np.quantile(np.concatenate(bs),np.linspace(0,1,45))])
    best=None
    for recovery in [None,.5,.75,.9,.99]:
        for confirm in grid:
            matrices=[]
            for y,a,b,op,old in zip(ys,raw,bs,operators,baseline):
                scores=op.apply(refine_scores(a,b,threshold,confirm,recovery))
                cm=counts(y,scores>=threshold)
                if cm[1]>old[1] or cm[2]>old[2]:break
                matrices.append(cm)
            if len(matrices)!=len(ys):continue
            f1=float(np.mean([2*c[3]/(2*c[3]+c[1]+c[2]) for c in matrices if c[2]+c[3]]))
            key=(f1,-sum(c[1]+c[2] for c in matrices),recovery is None,-float(confirm))
            if best is None or key>best[0]:best=(key,{'confirmation':float(confirm),'recovery':recovery,'mean_f1':f1,'confusion':matrices})
    return best[1] if best else None

def run():
    OUT.mkdir(exist_ok=False);old=joblib.load(BASE);features=old['features'];train=[];vals=[]
    for name in NAMES:
        d=joblib.load(f'data/processed/multi_{name}.joblib')['data'];f=d['train'].copy();f['_source']=name
        train.append(f);vals.append(d['validation'].reset_index(drop=True))
    train=pd.concat(train,ignore_index=True);y=train.label.isin(TARGETS).astype(int)
    ys=[f.label.isin(TARGETS).to_numpy() for f in vals];ops=[CachedHistoryOperator(f,old['score_history']) for f in vals]
    protocol={'baseline_sha256':hashlib.sha256(BASE.read_bytes()).hexdigest(),'test_rows_fitted':0,
        'selection':'Full causal pipeline, fixed deployed score threshold; no validation-source FP/FN increase.',
        'aspirational_target':'FNR <= 5% and FPR <= 1% on each source, not a promised result.',
        'limitations':'Previously consumed regression datasets; scenario labels are not verified rogue identities.'}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2));trials=[];best=-1
    with threadpool_limits(limits=4):
        raw=[old['model'].predict_proba(f[features].astype(float))[:,1] for f in vals]
        baseline=[counts(z,op.apply(a)>=old['threshold']) for z,a,op in zip(ys,raw,ops)]
        size=train.groupby('_source').size()
        for depth in [4,6,8]:
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
                if point and point['mean_f1']>best:
                    best=point['mean_f1'];bundle={**old,'model':EvidenceRefiner(old['model'],model,features,old['threshold'],point['confirmation'],point['recovery']),
                        'model_name':'v7-full-pipeline-catboost','selection':trial,'training_metadata':protocol}
                    bundle.pop('feature_importance',None);bundle.pop('importance_method',None)
                    joblib.dump(bundle,OUT/'trained_ensemble.joblib',compress=3)
    sha=hashlib.sha256((OUT/'trained_ensemble.joblib').read_bytes()).hexdigest()
    (OUT/'FROZEN.json').write_text(json.dumps({'sha256':sha,'test_predictions_used_for_selection':False},indent=2));print('FROZEN',sha,flush=True)

if __name__=='__main__':run()
