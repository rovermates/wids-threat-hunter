"""Additional family-classification trials before freezing/evaluating refined v7."""
import hashlib,json,time
import joblib,numpy as np,pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from threadpoolctl import threadpool_limits
from backend.refine_v7 import OUT,TARGETS,select_threshold
from backend.core.ml_engine import FEATURE_SETS,PROTOCOL
from backend.core.detection_features import DETECTION_FEATURES
from backend.core.ap_behavior import AP_FEATURES
from backend.core.target_classifier import TargetFamilyClassifier
from backend.train_ensemble import metrics

def run():
    if (OUT/'new_rogue.json').exists():
        raise RuntimeError('Do not refit a previously evaluated release folder')
    names=['behavior_train','behavior_wpa3','round2_rogue','round2_beacon']
    train=[]; vals=[]
    for name in names:
        data=joblib.load(f'data/processed/{name}.joblib')['data']
        p={k:f.loc[(f.frame_type==0)&f.frame_subtype.isin([5,8])].copy() for k,f in data.items()}
        train.append(p['train']);vals.append(p['validation'])
    train=pd.concat(train,ignore_index=True)
    # Preserve distinct observed attack families, without using source identity.
    labels=train.label.astype(str)
    features=list(dict.fromkeys(FEATURE_SETS['combined_plus_frame_length']+PROTOCOL+DETECTION_FEATURES+AP_FEATURES))
    trials=json.loads((OUT/'experiments.json').read_text())
    bundle=joblib.load(OUT/'trained_ensemble.joblib'); best=bundle['selection']['utility']
    with threadpool_limits(limits=4):
        for leaves,weight in [(15,1),(31,1),(15,3),(31,3)]:
            start=time.perf_counter(); name=f'multiclass180_l{leaves}_positive{weight}'
            estimator=Pipeline([('imputer',SimpleImputer(strategy='median',add_indicator=True,keep_empty_features=True)),
                ('model',HistGradientBoostingClassifier(max_iter=180,max_leaf_nodes=leaves,min_samples_leaf=20,
                    l2_regularization=5,learning_rate=.07,early_stopping=False,random_state=73))])
            estimator.fit(train[features].astype(float),labels,model__sample_weight=np.where(labels.isin(TARGETS),weight,1.))
            model=TargetFamilyClassifier(estimator,TARGETS)
            scores=[model.predict_proba(f[features].astype(float))[:,1] for f in vals]
            threshold,utility,point=select_threshold(vals,scores)
            trial={'name':name,'features':'behavior_multiclass','threshold':threshold,'utility':utility,'point':point,
                'seconds':time.perf_counter()-start,'validation':{n:metrics(f.label.isin(TARGETS).astype(int),s>=threshold,s) for n,f,s in zip(names,vals,scores)}}
            trials.append(trial);(OUT/'experiments.json').write_text(json.dumps(trials,indent=2))
            print(json.dumps({k:v for k,v in trial.items() if k!='validation'}),flush=True)
            if utility>best:
                best=utility
                bundle.update(model=model,features=features,threshold=threshold,model_name='v7-refined-'+name,selection=trial)
                joblib.dump(bundle,OUT/'trained_ensemble.joblib',compress=3)
    bundle=joblib.load(OUT/'trained_ensemble.joblib')
    meta={k:v for k,v in bundle.items() if k!='model'}
    meta['artifact_sha256']=hashlib.sha256((OUT/'trained_ensemble.joblib').read_bytes()).hexdigest()
    (OUT/'metadata.json').write_text(json.dumps(meta,indent=2))
    (OUT/'FROZEN.json').write_text(json.dumps({'sha256':meta['artifact_sha256'],'test_predictions_used_for_selection':False},indent=2))

if __name__=='__main__':run()
