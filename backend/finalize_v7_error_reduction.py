"""Freeze validation-selected short-window model and causal score policy."""
import hashlib,json
from pathlib import Path
import joblib,numpy as np,pandas as pd
from sklearn.inspection import permutation_importance
from threadpoolctl import threadpool_limits
from backend.reduce_v7_errors import NAMES,TARGETS
from backend.evaluate_v7_error_reduction import run as evaluate

def run():
    point=json.loads(Path('docs/v7-multiscale-policy-validation.json').read_text())[0]
    assert not point['instant']
    b=joblib.load('backend/models/v7_multiscale/trained_ensemble.joblib')
    b.update(score_history={'window':point['window'],'alpha':point['alpha'],'max_gap_ns':5_000_000_000},
             threshold=point['threshold'],model_name='v7-short-window-history',selection=point)
    b['training_metadata']['causal_policy_selection']='Validation only; no per-source FP/FN increase. Previously examined regressions remain adaptive evidence.'
    frames=[]
    for n in NAMES:
        f=joblib.load(f'data/processed/multi_{n}.joblib')['data']['validation']
        frames.append(f.sample(min(len(f),1000),random_state=107))
    frame=pd.concat(frames,ignore_index=True)
    with threadpool_limits(limits=4):
        imp=permutation_importance(b['model'],frame[b['features']].astype(float),frame.label.isin(TARGETS).astype(int),
            scoring='average_precision',n_repeats=1,random_state=107,n_jobs=1)
    weights=np.maximum(0,imp.importances_mean);weights/=max(weights.sum(),1e-15)
    b['feature_importance']=sorted([{'feature':n,'importance':float(w)} for n,w in zip(b['features'],weights)],key=lambda x:x['importance'],reverse=True)
    b['importance_method']='Underlying classifier validation permutation AP decrease; one repeat, positive normalized values; excludes score-history policy'
    out=Path('backend/models/v7_error_reduction_final');out.mkdir(exist_ok=False)
    joblib.dump(b,out/'trained_ensemble.joblib',compress=3)
    sha=hashlib.sha256((out/'trained_ensemble.joblib').read_bytes()).hexdigest()
    (out/'FROZEN.json').write_text(json.dumps({'sha256':sha,'test_predictions_used_for_threshold_selection':False},indent=2))
    print('FROZEN',sha,flush=True)
    evaluate(str(out),'multi_')

if __name__=='__main__':run()
