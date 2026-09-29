"""Source-balanced training, with validation-only confirmation/recovery selection."""
import hashlib,json,time
from pathlib import Path
import joblib,numpy as np,pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from threadpoolctl import threadpool_limits
from backend.core.confirmed_classifier import ConfirmedClassifier
from backend.core.multiscale_features import MULTISCALE_FEATURES
from backend.core.target_classifier import TargetFamilyClassifier
from backend.train_additional_captures import TARGETS
from backend.train_ensemble import metrics

OUT=Path('backend/models/v7_multiscale')
BASE=Path('backend/models/v7_advertiser_combined/trained_ensemble.joblib')
NAMES=['behavior_train','behavior_wpa3','round2_rogue','round2_beacon']

def select(labels,base,scores,baseline):
    confirms=np.unique(np.r_[1e-15,np.quantile(np.concatenate(scores),np.linspace(0,1,121))])
    recoveries=np.unique(np.r_[.25,.5,.75,.9,.99,1.000001,
        np.quantile(np.concatenate([s[y] for s,y in zip(scores,labels)]),np.linspace(.1,.99,15))])
    best=None
    for recover in recoveries:
        for confirm in confirms:
            counts=[]
            for y,a,b,m in zip(labels,base,scores,baseline):
                pred=((a>=.5)&(b>=confirm))|(b>=recover)
                tp=int((pred&y).sum());fp=int((pred&~y).sum())
                if tp<m[3] or fp>m[1]:break
                counts.append([int((~y).sum())-fp,fp,int(y.sum())-tp,tp])
            if len(counts)!=len(labels):continue
            # Equal source influence; constraints protect both error counts.
            value=float(np.mean([2*c[3]/(2*c[3]+c[1]+c[2]) for c in counts if c[2]+c[3]]))
            key=(value,-sum(c[1]+c[2] for c in counts))
            if best is None or key>best[0]:best=(key,{'confirmation':float(confirm),'recovery':float(recover),'mean_f1':value,'confusion':counts})
    return None if best is None else best[1]

def run():
    if (OUT/'experiments.json').exists():
        raise FileExistsError('Existing training run must not be overwritten')
    OUT.mkdir(parents=True,exist_ok=True)
    old=joblib.load(BASE);features=old['features']+MULTISCALE_FEATURES;train=[];vals=[];sources=[]
    for n in NAMES:
        path=Path(f'data/processed/multi_{n}.joblib');d=joblib.load(path)
        f=d['data']['train'].copy();f['_source']=n;train.append(f);vals.append(d['data']['validation'])
        sources.append({'cache':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    train=pd.concat(train,ignore_index=True);y=train.label.isin(TARGETS).astype(int)
    labels=[f.label.isin(TARGETS).to_numpy() for f in vals]
    protocol={'sources':sources,'baseline_sha256':hashlib.sha256(BASE.read_bytes()).hexdigest(),
        'test_rows_fitted':0,'selection':'Per source validation FP and FN must not increase; maximize mean positive-source F1.',
        'release_gate':'No regression FP/FN increase on any of five existing regression sets; strictly fewer RogueAP misses and false positives.',
        'limitation':'Adaptively examined same-session regression sets, not independent deployment accuracy.'}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2))
    trials=[];best=-1
    with threadpool_limits(limits=4):
        a=[old['model'].predict_proba(f[features].astype(float))[:,1] for f in vals]
        baseline=[metrics(z,s>=.5,s)['confusion_matrix_tn_fp_fn_tp'] for z,s in zip(labels,a)]
        for family in [False]:
            for power in [.5,1.]:
                for leaves in [15,31]:
                    name=f'hgb_source{power}_leaves{leaves}_family{family}'
                    start=time.perf_counter()
                    size=train.groupby('_source').size();weights=train['_source'].map((len(train)/len(size)/size)**power).to_numpy(copy=True)
                    weights*=np.where(y,2.,1.);weights/=weights.mean()
                    estimator=Pipeline([('imputer',SimpleImputer(strategy='median',add_indicator=True,keep_empty_features=True)),
                        ('model',HistGradientBoostingClassifier(max_iter=240,max_leaf_nodes=leaves,min_samples_leaf=12,
                            l2_regularization=3,learning_rate=.06,early_stopping=False,random_state=107))])
                    targets=train.label.astype(str) if family else y
                    estimator.fit(train[features].astype(float),targets,model__sample_weight=weights)
                    model=TargetFamilyClassifier(estimator,TARGETS) if family else estimator
                    b=[model.predict_proba(f[features].astype(float))[:,1] for f in vals]
                    point=select(labels,a,b,baseline)
                    trial={'name':name,'seconds':time.perf_counter()-start,'selection':point}
                    trials.append(trial);(OUT/'experiments.json').write_text(json.dumps(trials,indent=2))
                    print(json.dumps(trial),flush=True)
                    if point and point['mean_f1']>best:
                        best=point['mean_f1']
                        combined=ConfirmedClassifier(old['model'],model,features,features,.5,point['confirmation'],point['recovery'])
                        bundle={**old,'model':combined,'features':features,'model_name':'v7-multiscale-confirmation','selection':trial,
                            'training_metadata':protocol,'threshold':.5}
                        bundle.pop('feature_importance',None);bundle.pop('importance_method',None)
                        joblib.dump(bundle,OUT/'trained_ensemble.joblib',compress=3)
    if not (OUT/'trained_ensemble.joblib').exists():raise RuntimeError('No validation-safe candidate')
    sha=hashlib.sha256((OUT/'trained_ensemble.joblib').read_bytes()).hexdigest()
    (OUT/'FROZEN.json').write_text(json.dumps({'sha256':sha,'test_predictions_used_for_threshold_selection':False},indent=2))
    print('FROZEN',sha,flush=True)

if __name__=='__main__':run()
