"""Precision-oriented binary/multiclass selection with training-only hard negatives."""
import argparse,hashlib,json,time
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier,ExtraTreesClassifier,HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.metrics import precision_recall_curve
from threadpoolctl import threadpool_limits
from backend.core.ml_engine import FEATURE_SETS,PROTOCOL
from backend.core.detection_features import DETECTION_FEATURES
from backend.core.ap_behavior import AP_FEATURES,BEHAVIOR_FEATURES
from backend.train_ensemble import metrics


def target_scores(model,frame):
    classes=list(model.classes_)
    target='evil_twin' if 'evil_twin' in classes else 1
    return model.predict_proba(frame)[:,classes.index(target)]


def operating_point(ys,scores):
    ts=np.unique(np.concatenate(scores));ps=[];rs=[];fs=[];rates=[]
    for y,s in zip(ys,scores):
        p,r,t=precision_recall_curve(y,s);i=np.searchsorted(t,ts)
        p=p[i];r=r[i];tp=r*sum(y);fp=np.divide(tp,p,out=np.zeros_like(tp),where=p>0)-tp
        ps.append(p);rs.append(r);rates.append(np.maximum(0,fp)/(len(y)-sum(y)))
        fs.append(np.divide(2*p*r,p+r,out=np.zeros_like(p),where=p+r>0))
    minp=np.min(ps,axis=0);minr=np.min(rs,axis=0);maxrate=np.max(rates,axis=0)
    feasible=(minp>=.95)&(minr>=.90)&(maxrate<=.0001)
    eligible=np.flatnonzero(feasible)
    met=bool(len(eligible))
    if not met:
        eligible=np.flatnonzero(minr>=.80)
    if not len(eligible):eligible=np.arange(len(ts))
    meanf=np.mean(fs,axis=0);meanp=np.mean(ps,axis=0)
    best=max(eligible,key=lambda i:(meanf[i],meanp[i],-maxrate[i],ts[i]))
    return float(ts[best]),met,{'precision_floor':float(minp[best]),'recall_floor':float(minr[best]),
                              'max_false_positive_rate':float(maxrate[best]),'mean_f1':float(meanf[best])}


def models():
    for multiclass in [False,True]:
        for leaf in [2,8]:
            yield f'rf96_leaf{leaf}_'+('multi' if multiclass else 'binary'),multiclass,RandomForestClassifier(
                n_estimators=96,max_depth=24,min_samples_leaf=leaf,class_weight='balanced',n_jobs=4,random_state=42)
    yield 'extra96_multi',True,ExtraTreesClassifier(n_estimators=96,max_depth=28,min_samples_leaf=2,class_weight='balanced',n_jobs=4,random_state=42)
    yield 'hist160_binary',False,HistGradientBoostingClassifier(max_iter=160,max_leaf_nodes=15,
        learning_rate=.08,min_samples_leaf=25,l2_regularization=2,class_weight='balanced',early_stopping=False,random_state=42)


def train(awid,wpa3,output):
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    bundles=[joblib.load(awid),joblib.load(wpa3)];training=[]
    for bundle in bundles:
        f=bundle['data']['train'];attacks=f[f.label!='normal'];normal=f[f.label=='normal']
        # Preserve all attack families and a larger benign sample than the prior run.
        training.append(pd.concat([attacks,normal.sample(n=min(len(normal),max(50000,len(attacks)*3)),random_state=42)]))
    training=pd.concat(training,ignore_index=True)
    validation=[s['data']['validation'] for s in bundles]
    ys=[(v.label=='evil_twin').to_numpy(dtype=int) for v in validation]
    baseline=FEATURE_SETS['combined_plus_frame_length']
    sets={'behavior':baseline+BEHAVIOR_FEATURES,
          'behavior_headers':list(dict.fromkeys(baseline+AP_FEATURES+DETECTION_FEATURES+PROTOCOL))}
    protocol={'sources':[b['metadata'] for b in bundles],'feature_sets':sets,'validation_gates':{'precision':.95,'recall':.90,'false_positive_rate':.0001},
              'hard_negative_weight':3,'test_used_for_selection':False,'training_counts':training.label.value_counts().to_dict()}
    (output/'protocol.json').write_text(json.dumps(protocol,indent=2),encoding='utf8')
    trials=[];best_key=(-1,-1,-1)
    with threadpool_limits(limits=4):
        for feature_set,features in sets.items():
            x=training[features].astype(float);vs=[v[features].astype(float) for v in validation]
            for name,multiclass,estimator in models():
                y=training.label.to_numpy(dtype=str) if multiclass else (training.label=='evil_twin').to_numpy(dtype=int)
                model=Pipeline([('imputer',SimpleImputer(strategy='median',add_indicator=True,keep_empty_features=True)),('model',estimator)])
                start=time.perf_counter();model.fit(x,y)
                # Mine false positives only from training, then refit the same architecture.
                train_score=target_scores(model,x)
                hard=(training.label.to_numpy()!='evil_twin')&(train_score>=.25)
                weights=np.where(hard,3.,1.)
                if hard.any():model.fit(x,y,model__sample_weight=weights)
                scores=[target_scores(model,v) for v in vs]
                threshold,met,point=operating_point(ys,scores)
                reports=[metrics(y,s>=threshold,s) for y,s in zip(ys,scores)]
                trial={'model':name,'feature_set':feature_set,'threshold':threshold,'gates_met':met,'operating_point':point,
                       'hard_negative_rows':int(hard.sum()),'train_seconds':time.perf_counter()-start,
                       'validation':dict(zip(['AWID','WPA3'],reports))}
                print(json.dumps(trial),flush=True);trials.append(trial)
                (output/'experiments.json').write_text(json.dumps(trials,indent=2),encoding='utf8')
                key=(int(met),point['mean_f1'],point['precision_floor'])
                if key>best_key:
                    best_key=key
                    bundle={'format_version':3,'model':model,'features':features,'threshold':threshold,'rssi_window':100,
                            'behavior_window':100,'selection':trial,'training_metadata':protocol,'model_name':name,
                            'target':'evil_twin versus all other labeled traffic','score_semantics':'Uncalibrated evil-twin class score, not a probability guarantee'}
                    joblib.dump(bundle,output/'trained_ensemble.joblib',compress=3)
    bundle=joblib.load(output/'trained_ensemble.joblib');meta={k:v for k,v in bundle.items() if k!='model'}
    meta['artifact_sha256']=hashlib.sha256((output/'trained_ensemble.joblib').read_bytes()).hexdigest()
    (output/'metadata.json').write_text(json.dumps(meta,indent=2),encoding='utf8')
    print('FROZEN',json.dumps(bundle['selection']),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('awid');p.add_argument('wpa3');p.add_argument('output')
    a=p.parse_args();train(a.awid,a.wpa3,a.output)
