"""Validation-only confirmation/recovery selection with per-source recall floors."""
import json,hashlib
from pathlib import Path
import joblib,numpy as np
from threadpoolctl import threadpool_limits
from backend.core.confirmed_classifier import ConfirmedClassifier
from backend.train_additional_captures import TARGETS
from backend.train_ensemble import metrics

def run():
    old=joblib.load('backend/models/final_v7/trained_ensemble.joblib')
    new=joblib.load('backend/models/v7_advertiser_corrected/trained_ensemble.joblib')
    names=['behavior_train','behavior_wpa3','round2_rogue','round2_beacon']
    frames=[joblib.load(f'data/processed/ad_{n}.joblib')['data']['validation'] for n in names]
    with threadpool_limits(limits=4):
        a=[old['model'].predict_proba(f[old['features']].astype(float))[:,1] for f in frames]
        b=[new['model'].predict_proba(f[new['features']].astype(float))[:,1] for f in frames]
    labels=[f.label.isin(TARGETS).to_numpy() for f in frames]
    base=[metrics(y,s>=old['threshold'],s) for y,s in zip(labels,a)]
    candidates=np.unique(np.r_[0,np.quantile(np.concatenate(b),np.linspace(0,1,101))])
    best=None; trials=[]
    for confirm in candidates:
        for recover in [.5,.7,.9,.99,1.000001]:
            ps=[((x>=old['threshold'])&(z>=confirm))|(z>=recover) for x,z in zip(a,b)]
            counts=[(int((p&y).sum()),int((p&~y).sum()),int(y.sum()),int((~y).sum())) for p,y in zip(ps,labels)]
            if any(tp < m['confusion_matrix_tn_fp_fn_tp'][3] or fp > m['confusion_matrix_tn_fp_fn_tp'][1] for (tp,fp,pos,neg),m in zip(counts,base)):continue
            f1=[2*tp/max(tp+fp+pos,1) for tp,fp,pos,neg in counts if pos]
            utility=float(np.mean(f1))
            record={'confirmation':float(confirm),'recovery':recover,'utility':utility,'counts_tp_fp_pos_neg':counts}
            trials.append(record)
            if best is None or utility>best['utility']:best=record
    if best is None:raise ValueError('No validation non-regressing combination')
    out=Path('backend/models/v7_advertiser_combined');out.mkdir(exist_ok=False)
    model=ConfirmedClassifier(old['model'],new['model'],old['features'],new['features'],old['threshold'],max(best['confirmation'],1e-15),best['recovery'])
    bundle={**old,'model':model,'features':list(dict.fromkeys(old['features']+new['features'])),'threshold':.5,
            'model_name':'v7-advertiser-confirmation','selection':best,'training_metadata':{'protocol':'Preserve every source validation TP count and do not increase any source FP count; maximize mean positive-source F1. Test rows not fitted. Adaptive regression evaluation.','feasible_trials':len(trials)}}
    bundle.pop('feature_importance',None)
    joblib.dump(bundle,out/'trained_ensemble.joblib',compress=3)
    (out/'experiments.json').write_text(json.dumps(trials,indent=2))
    print(json.dumps(best),flush=True)

if __name__=='__main__':run()
