"""Validation-only two-model confirmation/recovery operating-point search."""
import json,hashlib
from pathlib import Path
import joblib,numpy as np
from threadpoolctl import threadpool_limits
from backend.refine_v7 import TARGETS
from backend.core.confirmed_classifier import ConfirmedClassifier
from backend.train_ensemble import metrics

OUT=Path('backend/models/final_v7')

def run():
    OUT.mkdir(parents=True,exist_ok=False)
    a=joblib.load('backend/models/additional_captures_v7/trained_ensemble.joblib')
    b=joblib.load('backend/models/refined_v7/trained_ensemble.joblib')
    names=['behavior_train','behavior_wpa3','round2_rogue','round2_beacon'];frames=[];scores=[];baseline=[];baseline_recalls=[]
    with threadpool_limits(limits=4):
        for name in names:
            f=joblib.load(f'data/processed/{name}.joblib')['data']['validation']
            f=f.loc[(f.frame_type==0)&f.frame_subtype.isin([5,8])].copy();frames.append(f)
            s=a['model'].predict_proba(f[a['features']].astype(float))[:,1]
            t=b['model'].predict_proba(f[b['features']].astype(float))[:,1]
            scores.append((s,t));baseline.append(metrics(f.label.isin(TARGETS).astype(int),s>=a['threshold'],s))
            for label in TARGETS:
                mask=f.label.eq(label).to_numpy()
                if mask.any():baseline_recalls.append(float((s[mask]>=a['threshold']).mean()))
    trials=[];best=None
    # Include the original threshold and validation-score quantiles; never test scores.
    candidates_a=np.unique([a['threshold'],.15,.2,.25,.4,.5,.6])
    candidates_b=np.unique(np.r_[.00001,.0001,.001,.003,.01,.03,.05,.1,.2,.3,.5,
                                np.quantile(np.concatenate([t for s,t in scores]),[.1,.25,.5,.75])])
    candidates_recovery=[.7,.8,.9,.95,.98,.995,1.01]
    for low in candidates_a:
        for gate in candidates_b:
            for recovery in candidates_recovery:
                results=[];f1s=[];ratios=[];recalls=[]
                for f,(s,t),base in zip(frames,scores,baseline):
                    y=f.label.isin(TARGETS).to_numpy();pred=((s>=low)&(t>=gate))|(t>=recovery)
                    tp=int((pred&y).sum());fp=int((pred&~y).sum());fn=int((~pred&y).sum());tn=int((~pred&~y).sum())
                    results.append([tn,fp,fn,tp]);ratios.append(fp/max(tn+fp,1))
                    if y.any():
                        f1s.append(2*tp/max(2*tp+fp+fn,1))
                        for label in TARGETS:
                            mask=f.label.eq(label).to_numpy()
                            if mask.any():recalls.append(float(pred[mask].mean()))
                # Preserve the original validation target-family recall, penalize false alerts.
                valid=min(recalls)>=min(baseline_recalls)
                utility=float(np.mean(f1s)-.2*max(ratios))
                key=(valid,utility)
                trial={'alert':float(low),'confirm':float(gate),'recover':float(recovery),
                       'recall_floor_met':valid,'utility':utility,'min_family_recall':min(recalls),
                       'max_fpr':max(ratios),'validation_matrices':dict(zip(names,results))}
                trials.append(trial)
                if best is None or key>best[0]:best=(key,trial)
    chosen=best[1]
    model=ConfirmedClassifier(a['model'],b['model'],a['features'],b['features'],chosen['alert'],chosen['confirm'],chosen['recover'])
    bundle={k:v for k,v in b.items() if k not in ['model','feature_importance','importance_method']}
    bundle.update(model=model,threshold=.5,model_name='v7-refined-confirmed-ensemble',selection=chosen,
        score_semantics='Relative confirmation/recovery support, not a calibrated probability')
    protocol={'selection':'Validation only; original minimum target-family recall retained; mean F1 minus .2 max source FPR',
        'test_rows_fitted':0,'component_models':['additional_captures_v7','refined_v7'],
        'iteration_note':'Two consumed-test regressions motivated confirmation design; adaptive research evidence, not a blind test.',
        'development_baseline':dict(zip(names,baseline))}
    bundle['training_metadata']=protocol
    joblib.dump(bundle,OUT/'trained_ensemble.joblib',compress=3)
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2))
    (OUT/'experiments.json').write_text(json.dumps(trials,indent=2))
    meta={k:v for k,v in bundle.items() if k!='model'}
    meta['artifact_sha256']=hashlib.sha256((OUT/'trained_ensemble.joblib').read_bytes()).hexdigest()
    (OUT/'metadata.json').write_text(json.dumps(meta,indent=2))
    print(json.dumps(chosen,indent=2),flush=True)

if __name__=='__main__':run()
