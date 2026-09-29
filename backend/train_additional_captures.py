"""Retrain on additional publisher-labelled captures with heldout blocks excluded."""
import json,time,hashlib
from pathlib import Path
import joblib,numpy as np,pandas as pd
from sklearn.ensemble import RandomForestClassifier,HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from threadpoolctl import threadpool_limits
from backend.core.ml_engine import FEATURE_SETS,PROTOCOL
from backend.core.ap_behavior import AP_FEATURES
from backend.core.detection_features import DETECTION_FEATURES
from backend.train_ensemble import metrics
TARGETS=['evil_twin','cafe_latte','hirte','rogue_ap']
OUT=Path('backend/models/additional_captures_v7')

def operating_point(frames,scores):
 thresholds=np.unique(np.concatenate(scores));ps=[];rs=[];f1s=[];rates=[]
 for f,s in zip(frames,scores):
  y=f.label.isin(TARGETS).to_numpy();pos=np.sort(s[y]);neg=np.sort(s[~y]);tp=len(pos)-np.searchsorted(pos,thresholds);fp=len(neg)-np.searchsorted(neg,thresholds)
  if len(pos):
   p=np.divide(tp,tp+fp,out=np.zeros_like(tp,dtype=float),where=tp+fp>0);r=tp/len(pos);ps.append(p);f1s.append(np.divide(2*p*r,p+r,out=np.zeros_like(p),where=p+r>0))
   for name in TARGETS:
    a=np.sort(s[(f.label==name).to_numpy()])
    if len(a):rs.append((len(a)-np.searchsorted(a,thresholds))/len(a))
  normal=np.sort(s[(f.label=='normal').to_numpy()])
  if len(normal):rates.append((len(normal)-np.searchsorted(normal,thresholds))/len(normal))
  if not len(pos) and len(neg):rates.append(fp/len(neg))
 p=np.min(ps,axis=0);r=np.min(rs,axis=0);f=np.mean(f1s,axis=0);rate=np.max(rates,axis=0)
 good=(p>=.95)&(r>=.90)&(rate<=.001);ix=np.flatnonzero(good);passed=bool(len(ix))
 if not passed:ix=np.arange(len(thresholds))
 i=max(ix,key=lambda i:(f[i],r[i],p[i],-rate[i]))
 return float(thresholds[i]),passed,{'mean_positive_source_f1':float(f[i]),'minimum_precision':float(p[i]),'minimum_family_recall':float(r[i]),'maximum_false_positive_rate':float(rate[i])}

def run():
 OUT.mkdir(parents=True,exist_ok=False)
 names=['behavior_train','behavior_wpa3','round2_rogue','round2_beacon'];sources=[joblib.load('data/processed/'+n+'.joblib') for n in names];train=[];vals=[]
 for name,d in zip(names,sources):
  parts={k:f.loc[(f.frame_type==0)&f.frame_subtype.isin([5,8])].copy() for k,f in d['data'].items()}
  f=parts['train'];pos=f[f.label!='normal'];neg=f[f.label=='normal'];f=pd.concat([pos,neg.sample(min(len(neg),max(15000,3*len(pos))),random_state=29)]);f['_source']=name;train.append(f);vals.append(parts['validation'])
 train=pd.concat(train,ignore_index=True);y=train.label.isin(TARGETS).astype(int)
 base=list(dict.fromkeys(FEATURE_SETS['combined_plus_frame_length']+PROTOCOL+DETECTION_FEATURES));sets={'portable':base,'behavior':list(dict.fromkeys(base+AP_FEATURES))}
 protocol={'target_labels':TARGETS,'scope':'ap_advertisements','train_counts':{str(n):g.label.value_counts().to_dict() for n,g in train.groupby('_source')},'validation_counts':{n:f.label.value_counts().to_dict() for n,f in zip(names,vals)},'sources':[s['metadata'] for s in sources],'test_rows_fitted':0,'selection':'development only; blocked same-session holdouts, no independent-device claim'}
 (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2));trials=[];best=None
 with threadpool_limits(limits=4):
  for fname,features in sets.items():
   configs=[('rf64_leaf2',RandomForestClassifier(n_estimators=64,max_depth=24,min_samples_leaf=2,class_weight='balanced',random_state=29,n_jobs=4)),('rf96_leaf5',RandomForestClassifier(n_estimators=96,max_depth=24,min_samples_leaf=5,class_weight='balanced',random_state=29,n_jobs=4)),('rf128_leaf10',RandomForestClassifier(n_estimators=128,max_depth=24,min_samples_leaf=10,class_weight='balanced',random_state=29,n_jobs=4))]
   configs += [(f'hist{it}_leaves{leaves}',HistGradientBoostingClassifier(max_iter=it,max_leaf_nodes=leaves,min_samples_leaf=25,l2_regularization=2,learning_rate=.07,class_weight='balanced',early_stopping=False,random_state=29)) for it,leaves in [(100,7),(180,15),(250,31)]]
   for name,est in configs:
    start=time.perf_counter();model=Pipeline([('imputer',SimpleImputer(strategy='median',add_indicator=True,keep_empty_features=True)),('model',est)]);model.fit(train[features].astype(float),y)
    scores=[model.predict_proba(f[features].astype(float))[:,1] for f in vals];threshold,passed,point=operating_point(vals,scores)
    trial={'name':name,'features':fname,'threshold':threshold,'gates_met':passed,'point':point,'seconds':time.perf_counter()-start,'validation':{n:metrics(f.label.isin(TARGETS).astype(int),s>=threshold,s) for n,f,s in zip(names,vals,scores)}};trials.append(trial)
    (OUT/'experiments.json').write_text(json.dumps(trials,indent=2));print(json.dumps({k:v for k,v in trial.items() if k!='validation'}),flush=True)
    key=(passed,point['mean_positive_source_f1'],point['minimum_family_recall'])
    if best is None or key>best:
     best=key;bundle={'format_version':3,'model':model,'features':features,'threshold':threshold,'rssi_window':100,'behavior_window':100,'scope':'ap_advertisements','model_name':name,'selection':trial,'training_metadata':protocol,'target_labels':TARGETS,'target':'AP impersonation advertisements including publisher RogueAP labels','positive_label':'Impersonation','attack_type':'suspected_rogue_ap','score_semantics':'Uncalibrated classifier score, not verified identity'};joblib.dump(bundle,OUT/'trained_ensemble.joblib',compress=3)
 bundle=joblib.load(OUT/'trained_ensemble.joblib');meta={k:v for k,v in bundle.items() if k!='model'};meta['artifact_sha256']=hashlib.sha256((OUT/'trained_ensemble.joblib').read_bytes()).hexdigest();(OUT/'metadata.json').write_text(json.dumps(meta,indent=2));(OUT/'FROZEN.json').write_text(json.dumps({'sha256':meta['artifact_sha256'],'test_predictions_used':False},indent=2));print('FROZEN',meta['artifact_sha256'],flush=True)
if __name__=='__main__':run()
