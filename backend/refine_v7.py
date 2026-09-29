"""Development-only v7 refinement; regression captures are never fitted."""
import hashlib
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from threadpoolctl import threadpool_limits

from backend.core.ml_engine import FEATURE_SETS, PROTOCOL
from backend.core.detection_features import DETECTION_FEATURES
from backend.core.ap_behavior import AP_FEATURES
from backend.train_additional_captures import TARGETS
from backend.train_ensemble import metrics

OUT = Path('backend/models/refined_v7')

def select_threshold(frames, scores):
    thresholds = np.unique(np.concatenate(scores))
    recalls, precisions, f1s, fprs = [], [], [], []
    for f, s in zip(frames, scores):
        y = f.label.isin(TARGETS).to_numpy()
        pos, neg = np.sort(s[y]), np.sort(s[~y])
        tp = len(pos) - np.searchsorted(pos, thresholds)
        fp = len(neg) - np.searchsorted(neg, thresholds)
        if len(pos):
            p = tp / np.maximum(tp + fp, 1)
            r = tp / len(pos)
            precisions.append(p)
            recalls.append(r)
            f1s.append(2*p*r/np.maximum(p+r, 1e-15))
        if len(neg):
            fprs.append(fp/len(neg))
    p, r = np.min(precisions, axis=0), np.min(recalls, axis=0)
    f, rate = np.mean(f1s, axis=0), np.max(fprs, axis=0)
    # Explicit fallback objective penalizes false alerts, never silently pure F1.
    utility = f - 0.6*rate - 0.25*np.maximum(0, .90-p) - .25*np.maximum(0, .85-r)
    i = int(np.argmax(utility))
    return float(thresholds[i]), float(utility[i]), {
        'mean_f1': float(f[i]), 'min_precision':float(p[i]),
        'min_recall':float(r[i]), 'max_fpr':float(rate[i])}

def run():
    OUT.mkdir(parents=True, exist_ok=False)
    names = ['behavior_train','behavior_wpa3','round2_rogue','round2_beacon']
    train, vals = [], []
    for name in names:
        d = joblib.load(f'data/processed/{name}.joblib')
        parts = {k:f.loc[(f.frame_type==0)&f.frame_subtype.isin([5,8])].copy()
                 for k,f in d['data'].items()}
        parts['train']['_source'] = name
        train.append(parts['train']); vals.append(parts['validation'])
    train = pd.concat(train, ignore_index=True)
    y = train.label.isin(TARGETS).astype(int)
    base = list(dict.fromkeys(FEATURE_SETS['combined_plus_frame_length']+PROTOCOL+DETECTION_FEATURES))
    full = list(dict.fromkeys(base+AP_FEATURES))
    sets = {'portable':base, 'behavior':full,
            'invariant':[n for n in full if n not in ['rssi_dbm','advertised_channel','frame_length','ap_length_mean']]}
    protocol = {'target_labels':TARGETS, 'scope':'ap_advertisements',
        'train_counts': {str(n):g.label.value_counts().to_dict() for n,g in train.groupby('_source')},
        'all_development_negatives_retained':True, 'test_rows_fitted':0,
        'selection':'Validation utility = mean source F1 - .6 max source FPR - .25 precision deficit below .90 - .25 recall deficit below .85',
        'evaluation_limit':'Previously inspected same-session test captures; regression evidence only.'}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2))
    trials=[]; best=-np.inf
    with threadpool_limits(limits=4):
        for feature_name, features in sets.items():
            configs=[]
            for weight in [1,3,8]:
                for leaves in [15,31]:
                    configs.append((f'hgb240_l{leaves}_positive{weight}',
                        HistGradientBoostingClassifier(max_iter=240,max_leaf_nodes=leaves,
                        min_samples_leaf=20,l2_regularization=5,learning_rate=.07,
                        early_stopping=False,random_state=73),weight))
            for leaf in [2,8]:
                configs.append((f'extra160_leaf{leaf}',ExtraTreesClassifier(n_estimators=160,
                    min_samples_leaf=leaf,max_features=.8,n_jobs=4,random_state=73),3))
            for name, estimator, weight in configs:
                start=time.perf_counter()
                model=Pipeline([('imputer',SimpleImputer(strategy='median',add_indicator=True,
                    keep_empty_features=True)),('model',estimator)])
                model.fit(train[features].astype(float),y,model__sample_weight=np.where(y,weight,1.))
                scores=[model.predict_proba(f[features].astype(float))[:,1] for f in vals]
                threshold,utility,point=select_threshold(vals,scores)
                trial={'name':name,'features':feature_name,'threshold':threshold,'utility':utility,
                    'point':point,'seconds':time.perf_counter()-start,
                    'validation':{n:metrics(f.label.isin(TARGETS).astype(int),s>=threshold,s)
                                  for n,f,s in zip(names,vals,scores)}}
                trials.append(trial); (OUT/'experiments.json').write_text(json.dumps(trials,indent=2))
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
    b=joblib.load(OUT/'trained_ensemble.joblib')
    meta={k:v for k,v in b.items() if k!='model'}
    meta['artifact_sha256']=hashlib.sha256((OUT/'trained_ensemble.joblib').read_bytes()).hexdigest()
    (OUT/'metadata.json').write_text(json.dumps(meta,indent=2))
    (OUT/'FROZEN.json').write_text(json.dumps({'sha256':meta['artifact_sha256'],'test_predictions_used_for_selection':False},indent=2))
    print('FROZEN',meta['artifact_sha256'],flush=True)

if __name__=='__main__':
    run()
