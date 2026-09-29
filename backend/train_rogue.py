"""Explicit AWID impersonation target; never compare its F1 to evil-twin-only F1."""
import argparse,hashlib,json,time
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier,HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.metrics import precision_recall_curve
from threadpoolctl import threadpool_limits
from backend.core.ml_engine import FEATURE_SETS,PROTOCOL
from backend.core.ap_behavior import AP_FEATURES
from backend.core.detection_features import DETECTION_FEATURES
from backend.train_ensemble import metrics

TARGET_LABELS=['evil_twin','cafe_latte','hirte']


def select(labels,scores):
    thresholds=np.unique(np.concatenate(scores));precisions=[];f1s=[];family_recalls=[];normal_rates=[]
    for labels,score in zip(labels,scores):
        y=labels.isin(TARGET_LABELS).to_numpy(dtype=int)
        p,r,t=precision_recall_curve(y,score);i=np.searchsorted(t,thresholds)
        p=p[i];r=r[i];precisions.append(p);f1s.append(np.divide(2*p*r,p+r,out=np.zeros_like(p),where=p+r>0))
        for family in TARGET_LABELS:
            subset=np.sort(score[(labels==family).to_numpy()])
            if len(subset):family_recalls.append((len(subset)-np.searchsorted(subset,thresholds,side='left'))/len(subset))
        normal=np.sort(score[(labels=='normal').to_numpy()])
        normal_rates.append((len(normal)-np.searchsorted(normal,thresholds,side='left'))/len(normal))
    p=np.min(precisions,axis=0);recall=np.min(family_recalls,axis=0);rate=np.max(normal_rates,axis=0);f1=np.mean(f1s,axis=0)
    gate=(p>=.95)&(recall>=.9)&(rate<=.0001);indices=np.flatnonzero(gate);met=bool(len(indices))
    if not met:indices=np.flatnonzero(recall>=.85)
    if not len(indices):indices=np.arange(len(thresholds))
    i=max(indices,key=lambda i:(f1[i],recall[i],p[i]))
    return float(thresholds[i]),met,{'mean_f1':float(f1[i]),'minimum_family_recall':float(recall[i]),'minimum_precision':float(p[i]),'maximum_normal_false_positive_rate':float(rate[i])}


def train(output, advertisements=False):
    output=Path(output);output.mkdir(exist_ok=False,parents=True)
    sources=[joblib.load('data/processed/'+name+'.joblib') for name in ['behavior_train','behavior_wpa3']]
    if advertisements:
        for source in sources:
            source['data']={k:f.loc[(f.frame_type==0)&f.frame_subtype.isin([5,8])].copy() for k,f in source['data'].items()}
    pieces=[]
    for source in sources:
        f=source['data']['train'];attacks=f[f.label!='normal'];normal=f[f.label=='normal']
        pieces.append(pd.concat([attacks,normal.sample(n=min(len(normal),max(50000,len(attacks)*3)),random_state=42)]))
    train=pd.concat(pieces,ignore_index=True);validation=[s['data']['validation'] for s in sources]
    y=train.label.isin(TARGET_LABELS).to_numpy(dtype=int)
    base=FEATURE_SETS['combined_plus_frame_length']
    sets={'portable':list(dict.fromkeys(base+PROTOCOL+DETECTION_FEATURES)),
          'behavior':list(dict.fromkeys(base+PROTOCOL+DETECTION_FEATURES+AP_FEATURES))}
    protocol={'scope':'ap_advertisements' if advertisements else 'all_frames','target_labels':TARGET_LABELS,'source':'AWID published impersonation category',
        'comparison_rule':'Rescore both baseline and candidate on this same target; evil-only F1 is not comparable',
        'training_counts':train.label.value_counts().to_dict(),'sources':[s['metadata'] for s in sources],
        'validation_gates':{'precision_each_source':.95,'recall_each_present_positive_family':.90,'normal_false_positive_rate':.0001},
        'test_rows_fitted':0,'features':sets}
    (output/'protocol.json').write_text(json.dumps(protocol,indent=2),encoding='utf8')
    trials=[];best=(-1,-1,-1)
    with threadpool_limits(limits=4):
        for feature_set,features in sets.items():
            for name,estimator in [('rf_impersonation',RandomForestClassifier(n_estimators=96,max_depth=24,min_samples_leaf=2,class_weight='balanced',n_jobs=4,random_state=42)),
                    ('hist_impersonation',HistGradientBoostingClassifier(max_iter=180,max_leaf_nodes=15,learning_rate=.07,min_samples_leaf=25,
                        l2_regularization=2,class_weight='balanced',early_stopping=False,random_state=42))]:
                model=Pipeline([('imputer',SimpleImputer(strategy='median',add_indicator=True,keep_empty_features=True)),('model',estimator)])
                start=time.perf_counter();model.fit(train[features].astype(float),y)
                scores=[model.predict_proba(v[features].astype(float))[:,1] for v in validation]
                threshold,met,point=select([v.label for v in validation],scores)
                reports={name:metrics(v.label.isin(TARGET_LABELS).to_numpy(dtype=int),score>=threshold,score) for name,v,score in zip(['AWID','WPA3'],validation,scores)}
                trial={'model':name,'feature_set':feature_set,'threshold':threshold,'gates_met':met,'operating_point':point,'validation':reports,'train_seconds':time.perf_counter()-start}
                trials.append(trial);print(json.dumps(trial),flush=True)
                (output/'experiments.json').write_text(json.dumps(trials,indent=2),encoding='utf8')
                key=(int(met),point['mean_f1'],point['minimum_family_recall'])
                if key>best:
                    best=key;bundle={'format_version':3,'model':model,'features':features,'threshold':threshold,'rssi_window':100,'behavior_window':100,
                        'scope':'ap_advertisements' if advertisements else 'all_frames',
                        'model_name':name,'selection':trial,'training_metadata':protocol,'target_labels':TARGET_LABELS,
                        'target':'AP impersonation activity (evil twin, cafe-latte, hirte)','positive_label':'Impersonation',
                        'attack_type':'suspected_rogue_ap','score_semantics':'Uncalibrated impersonation score; not verified AP identity'}
                    joblib.dump(bundle,output/'trained_ensemble.joblib',compress=3)
    bundle=joblib.load(output/'trained_ensemble.joblib');meta={k:v for k,v in bundle.items() if k!='model'}
    meta['artifact_sha256']=hashlib.sha256((output/'trained_ensemble.joblib').read_bytes()).hexdigest()
    (output/'metadata.json').write_text(json.dumps(meta,indent=2),encoding='utf8');print('FROZEN',bundle['selection'],flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('output');p.add_argument('--advertisements',action='store_true');a=p.parse_args();train(a.output,a.advertisements)
