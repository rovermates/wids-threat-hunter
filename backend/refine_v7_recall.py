"""Recall-constrained refinement after rejecting the first precision-heavy candidate.

Previously observed test results motivate this iteration; thresholds and model
selection still use validation rows only. No fresh-generalization claim is made.
"""
import hashlib,json,time
from pathlib import Path
import joblib,numpy as np,pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier,ExtraTreesClassifier
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from threadpoolctl import threadpool_limits
from backend.refine_v7 import TARGETS
from backend.core.ml_engine import FEATURE_SETS,PROTOCOL
from backend.core.detection_features import DETECTION_FEATURES
from backend.core.ap_behavior import AP_FEATURES
from backend.train_ensemble import metrics

OUT=Path('backend/models/refined_v7_balanced')

def select_recall_threshold(frames,scores):
    thresholds=np.unique(np.concatenate(scores)); ps=[];rs=[];fs=[];rates=[]
    for f,s in zip(frames,scores):
        y=f.label.isin(TARGETS).to_numpy();pos=np.sort(s[y]);neg=np.sort(s[~y])
        tp=len(pos)-np.searchsorted(pos,thresholds);fp=len(neg)-np.searchsorted(neg,thresholds)
        if len(pos):
            p=tp/np.maximum(tp+fp,1);r=tp/len(pos)
            ps.append(p);fs.append(2*p*r/np.maximum(p+r,1e-15))
            for label in TARGETS:
                values=np.sort(s[(f.label==label).to_numpy()])
                if len(values):rs.append((len(values)-np.searchsorted(values,thresholds))/len(values))
        if len(neg):rates.append(fp/len(neg))
    recall=np.min(rs,axis=0);precision=np.min(ps,axis=0);f1=np.mean(fs,axis=0);fpr=np.max(rates,axis=0)
    valid=np.flatnonzero(recall>=.90)
    if not len(valid):raise ValueError('No threshold satisfies recall floor')
    utility=f1-.2*fpr
    i=valid[np.argmax(utility[valid])]
    return float(thresholds[i]),float(utility[i]),{'mean_f1':float(f1[i]),'min_precision':float(precision[i]),'min_family_recall':float(recall[i]),'max_fpr':float(fpr[i])}

def run():
    OUT.mkdir(parents=True,exist_ok=False)
    names=['behavior_train','behavior_wpa3','round2_rogue','round2_beacon'];train=[];vals=[]
    for name in names:
        d=joblib.load(f'data/processed/{name}.joblib')['data']
        p={k:f.loc[(f.frame_type==0)&f.frame_subtype.isin([5,8])].copy() for k,f in d.items()}
        p['train']['_source']=name;train.append(p['train']);vals.append(p['validation'])
    train=pd.concat(train,ignore_index=True);y=train.label.isin(TARGETS).astype(int)
    features=list(dict.fromkeys(FEATURE_SETS['combined_plus_frame_length']+PROTOCOL+DETECTION_FEATURES+AP_FEATURES))
    protocol={'target_labels':TARGETS,'scope':'ap_advertisements',
        'train_counts':{str(n):g.label.value_counts().to_dict() for n,g in train.groupby('_source')},
        'selection':'Require each validation target family recall >= .90; maximize mean source F1 minus .2 maximum source FPR',
        'test_rows_fitted':0,'test_scores_used_for_threshold':False,
        'iteration_note':'Prior precision-heavy candidate rejected after consumed-test regression. Evaluation is adaptive regression evidence, not independent evidence.'}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2))
    configs=[]
    for iterations,leaves in [(240,15),(240,31),(400,31),(400,63),(600,31)]:
        for weight in [1,3]:
            configs.append((f'hgb{iterations}_l{leaves}_positive{weight}',
                HistGradientBoostingClassifier(max_iter=iterations,max_leaf_nodes=leaves,min_samples_leaf=15,
                l2_regularization=3,learning_rate=.07,early_stopping=False,random_state=73),weight))
    configs += [(f'extra240_leaf{leaf}',ExtraTreesClassifier(n_estimators=240,min_samples_leaf=leaf,
        max_features=.8,n_jobs=4,random_state=73),3) for leaf in [1,3]]
    trials=[];best=-np.inf
    with threadpool_limits(limits=4):
        for name,estimator,weight in configs:
            start=time.perf_counter()
            model=Pipeline([('imputer',SimpleImputer(strategy='median',add_indicator=True,keep_empty_features=True)),('model',estimator)])
            model.fit(train[features].astype(float),y,model__sample_weight=np.where(y,weight,1.))
            scores=[model.predict_proba(f[features].astype(float))[:,1] for f in vals]
            threshold,utility,point=select_recall_threshold(vals,scores)
            trial={'name':name,'features':'behavior','threshold':threshold,'utility':utility,'point':point,
                'seconds':time.perf_counter()-start,'validation':{n:metrics(f.label.isin(TARGETS).astype(int),s>=threshold,s) for n,f,s in zip(names,vals,scores)}}
            trials.append(trial);(OUT/'experiments.json').write_text(json.dumps(trials,indent=2))
            print(json.dumps({k:v for k,v in trial.items() if k!='validation'}),flush=True)
            if utility>best:
                best=utility
                bundle={'format_version':3,'model':model,'features':features,'threshold':threshold,
                    'rssi_window':100,'behavior_window':100,'scope':'ap_advertisements',
                    'model_name':'v7-refined-'+name,'selection':trial,'training_metadata':protocol,
                    'target_labels':TARGETS,'target':'AP impersonation advertisements including publisher RogueAP labels',
                    'positive_label':'Impersonation','attack_type':'suspected_rogue_ap',
                    'score_semantics':'Uncalibrated classifier score, not verified AP identity'}
                joblib.dump(bundle,OUT/'trained_ensemble.joblib',compress=3)
    b=joblib.load(OUT/'trained_ensemble.joblib');meta={k:v for k,v in b.items() if k!='model'}
    meta['artifact_sha256']=hashlib.sha256((OUT/'trained_ensemble.joblib').read_bytes()).hexdigest()
    (OUT/'metadata.json').write_text(json.dumps(meta,indent=2))
    print('FROZEN',meta['artifact_sha256'],flush=True)

if __name__=='__main__':run()
