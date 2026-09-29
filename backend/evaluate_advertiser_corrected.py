"""Freeze dashboard importances, then compare v7 versions on unfitted regressions."""
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance
from threadpoolctl import threadpool_limits

from backend.benchmark_detection import evaluate
from backend.refine_v7 import OUT, TARGETS

def run(output=None):
    OUT = Path(output) if output else Path('backend/models/v7_advertiser_corrected')
    path=OUT/'trained_ensemble.joblib'
    bundle=joblib.load(path)
    validation=[]
    for name in ['behavior_train','behavior_wpa3','round2_rogue','round2_beacon']:
        f=joblib.load(f'data/processed/ad_{name}.joblib')['data']['validation']
        f=f.loc[(f.frame_type==0)&f.frame_subtype.isin([5,8])]
        validation.append(f.sample(min(len(f),3000),random_state=73))
    frame=pd.concat(validation,ignore_index=True)
    estimator=bundle['model'].named_steps['model']
    if hasattr(estimator,'feature_importances_'):
        names=bundle['model'].named_steps['imputer'].get_feature_names_out(bundle['features'])
        weights=estimator.feature_importances_
        method='Tree mean decrease in impurity'
    else:
        with threadpool_limits(limits=4):
            importance=permutation_importance(bundle['model'],frame[bundle['features']].astype(float),
                frame.label.isin(TARGETS).astype(int),scoring='average_precision',n_repeats=3,random_state=73,n_jobs=1)
        names=bundle['features']
        weights=np.maximum(0,importance.importances_mean)
        method='Validation permutation average-precision decrease (positive values normalized)'
    weights=weights/max(weights.sum(),1e-15)
    bundle['feature_importance']=sorted([{'feature':n,'importance':float(w)} for n,w in zip(names,weights)],key=lambda i:i['importance'],reverse=True)
    bundle['importance_method']=method
    joblib.dump(bundle,path,compress=3)
    sha=hashlib.sha256(path.read_bytes()).hexdigest()
    metadata={k:v for k,v in bundle.items() if k!='model'}
    metadata['artifact_sha256']=sha
    (OUT/'metadata.json').write_text(json.dumps(metadata,indent=2))
    (OUT/'FROZEN.json').write_text(json.dumps({'sha256':sha,'test_predictions_used_for_selection':False},indent=2))
    for cache,name in [('round2_rogue_holdout','new_rogue'),('round2_beacon_holdout','new_beacon'),
                       ('behavior_awid_test','awid_diagnostic'),('behavior_wpa3_holdout','test_metrics'),
                       ('behavior_negative','negative_control')]:
        evaluate(str(path),f'data/processed/ad_{cache}.joblib',str(OUT/(name+'.json')),
                 'backend/models/final_v7/trained_ensemble.joblib',
                 source=f'{cache}: consumed capture regression, excluded from fitting')
        if OUT.name.startswith('v7_advertiser_'):
            report_path=OUT/(name+'.json')
            report=json.loads(report_path.read_text())
            report['test_used_for_selection']=True
            report['selection_detail']='Earlier test regressions informed this training protocol. Current model and threshold selected on development validation only; no test rows fitted.'
            report['evaluation_note']='Adaptive regression check on previously inspected captures, not an independent final test.'
            report_path.write_text(json.dumps(report,indent=2))
    print('FINAL SHA',sha,flush=True)

if __name__=='__main__':
    run()
