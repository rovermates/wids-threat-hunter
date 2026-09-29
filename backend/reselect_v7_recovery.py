"""Conservative validation tie-breaking; reuse fitted component, no test fitting."""
import json,hashlib
from pathlib import Path
import joblib,numpy as np
from threadpoolctl import threadpool_limits
from backend.reduce_v7_errors import BASE,NAMES,select,TARGETS
from backend.train_ensemble import metrics
from backend.core.confirmed_classifier import ConfirmedClassifier

def run():
    old=joblib.load(BASE);candidate=joblib.load('backend/models/v7_source_balanced/trained_ensemble.joblib')
    features=candidate['features'];model=candidate['model'].confirmer
    frames=[joblib.load(f'data/processed/ad_{n}.joblib')['data']['validation'] for n in NAMES]
    y=[f.label.isin(TARGETS).to_numpy() for f in frames]
    with threadpool_limits(limits=4):
        a=[old['model'].predict_proba(f[old['features']].astype(float))[:,1] for f in frames]
        b=[model.predict_proba(f[features].astype(float))[:,1] for f in frames]
    baseline=[metrics(z,s>=.5,s)['confusion_matrix_tn_fp_fn_tp'] for z,s in zip(y,a)]
    point=select(y,a,b,baseline);assert point is not None
    candidate.update(model=ConfirmedClassifier(old['model'],model,old['features'],features,.5,point['confirmation'],point['recovery']),selection=point,model_name='v7-conservative-recovery')
    candidate['training_metadata']['tie_break']='For equal validation decisions, maximize recovery threshold and then minimize confirmation threshold. Adaptive research motivated by prior regressions.'
    out=Path('backend/models/v7_conservative_recovery');out.mkdir(exist_ok=False)
    joblib.dump(candidate,out/'trained_ensemble.joblib',compress=3)
    (out/'FROZEN.json').write_text(json.dumps({'sha256':hashlib.sha256((out/'trained_ensemble.joblib').read_bytes()).hexdigest(),'test_rows_fitted':0},indent=2))
    print(json.dumps(point),flush=True)

if __name__=='__main__':run()
