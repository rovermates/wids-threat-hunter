"""Follow-up experiment: hold out a complete development attack episode; remove size/radio shortcuts."""
import argparse,hashlib,json,time
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier,HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from threadpoolctl import threadpool_limits
from backend.core.ap_behavior import BEHAVIOR_FEATURES
from backend.train_precision import target_scores,operating_point
from backend.train_ensemble import metrics


def train(output):
    output=Path(output);output.mkdir(exist_ok=False,parents=True)
    a=joblib.load('data/processed/behavior_train.joblib');w=joblib.load('data/processed/behavior_wpa3.joblib')
    awid=pd.concat(a['data'].values(),ignore_index=True).sort_values('packet_number')
    is_validation=(awid['_block']%5==3)|(awid['_block']>=102)
    sources=[{'train':awid.loc[~is_validation],'validation':awid.loc[is_validation]},w['data']]
    training=[]
    for s in sources:
        f=s['train'];attack=f[f.label!='normal'];normal=f[f.label=='normal']
        training.append(pd.concat([attack,normal.sample(n=min(len(normal),max(50000,len(attack)*3)),random_state=42)]))
    training=pd.concat(training,ignore_index=True);validation=[s['validation'] for s in sources]
    # Persist the development split for reproducible explanation and validation curves.
    joblib.dump({'data':{'train':sources[0]['train'],'validation':sources[0]['validation']},'metadata':a['metadata']},'data/processed/invariant_train.joblib',compress=3)
    behavior=[n for n in BEHAVIOR_FEATURES if n not in {'ap_length_mean','ap_length_std'}]
    structural=['frame_type','frame_subtype','source_is_bssid','destination_is_bssid','destination_multicast',
                'to_ds','from_ds','protected_flag','retry_flag','ssid_mac_count_60s','ssid_present']
    sets={'behavior_invariant':structural+behavior,
          'behavior_dynamics':structural+behavior+['rssi_std_db','rssi_delta_db','sequence_gap','ap_beacon_interval_cv']}
    sets={k:list(dict.fromkeys(v)) for k,v in sets.items()}
    protocol={'purpose':'v3 test failure motivates new research experiment; existing test sets are consumed diagnostics',
              'awid_validation':'mod5=3 plus all blocks>=102 (complete later attack episode)',
              'sources':[a['metadata'],w['metadata']],'features':sets,'test_rows_fitted':0,
              'validation_counts':[v.label.value_counts().to_dict() for v in validation],
              'training_counts':training.label.value_counts().to_dict(),
              'weighting':'non-target attack management frames x20; normal management frames x2; never test/validation rows'}
    (output/'protocol.json').write_text(json.dumps(protocol,indent=2),encoding='utf8')
    weights=np.ones(len(training));mgmt=(training.frame_type==0).to_numpy()
    weights[mgmt&(training.label.to_numpy()=='normal')]=2
    weights[mgmt&~training.label.isin(['normal','evil_twin']).to_numpy()]=20
    ys=[(v.label=='evil_twin').to_numpy(dtype=int) for v in validation]
    trials=[];best=(-1,-1,-1)
    with threadpool_limits(limits=4):
        for feature_set,features in sets.items():
            for name in ['hist','rf_binary','rf_multiclass']:
                multi=name=='rf_multiclass'
                estimator=(HistGradientBoostingClassifier(max_iter=200,max_leaf_nodes=15,learning_rate=.06,min_samples_leaf=30,
                            l2_regularization=5,class_weight='balanced',early_stopping=False,random_state=42) if name=='hist'
                    else RandomForestClassifier(n_estimators=96,max_depth=22,min_samples_leaf=3,class_weight='balanced',n_jobs=4,random_state=42))
                y=(training.label=='evil_twin').to_numpy(dtype=int)
                if multi:
                    y=np.where(training.label=='evil_twin','evil_twin',training.label.astype(str)+'_'+np.where(mgmt,'management','other'))
                model=Pipeline([('imputer',SimpleImputer(strategy='median',add_indicator=True,keep_empty_features=True)),('model',estimator)])
                start=time.perf_counter();model.fit(training[features].astype(float),y,model__sample_weight=weights)
                scores=[target_scores(model,v[features].astype(float)) for v in validation]
                threshold,met,point=operating_point(ys,scores)
                trial={'model':name,'feature_set':feature_set,'threshold':threshold,'gates_met':met,'operating_point':point,
                       'train_seconds':time.perf_counter()-start,'validation':dict(zip(['AWID','WPA3'],[metrics(y,s>=threshold,s) for y,s in zip(ys,scores)]))}
                trials.append(trial);print(json.dumps(trial),flush=True)
                (output/'experiments.json').write_text(json.dumps(trials,indent=2),encoding='utf8')
                key=(int(met),point['mean_f1'],point['precision_floor'])
                if key>best:
                    best=key;bundle={'format_version':3,'model':model,'features':features,'threshold':threshold,'rssi_window':100,'behavior_window':100,
                        'model_name':name,'selection':trial,'training_metadata':protocol,'target':'evil_twin versus other traffic',
                        'score_semantics':'Uncalibrated evil-twin score, not a probability guarantee'}
                    joblib.dump(bundle,output/'trained_ensemble.joblib',compress=3)
    bundle=joblib.load(output/'trained_ensemble.joblib');meta={k:v for k,v in bundle.items() if k!='model'}
    meta['artifact_sha256']=hashlib.sha256((output/'trained_ensemble.joblib').read_bytes()).hexdigest()
    (output/'metadata.json').write_text(json.dumps(meta,indent=2),encoding='utf8');print('FROZEN',bundle['selection'],flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('output');train(p.parse_args().output)
