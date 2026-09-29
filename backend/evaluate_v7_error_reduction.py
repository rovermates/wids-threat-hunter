"""Paired regression gate. Never tune candidate thresholds on these results."""
import hashlib,json
from pathlib import Path
import joblib
from backend.benchmark_detection import evaluate
from backend.reduce_v7_errors import BASE

def run(folder,cache_prefix='ad_',baseline=BASE):
    out=Path(folder);path=out/'trained_ensemble.joblib'
    bundle=joblib.load(path);sha=hashlib.sha256(path.read_bytes()).hexdigest()
    metadata={k:v for k,v in bundle.items() if k!='model'};metadata['artifact_sha256']=sha
    (out/'metadata.json').write_text(json.dumps(metadata,indent=2))
    pairs=[('round2_rogue_holdout','new_rogue'),('round2_beacon_holdout','new_beacon'),
        ('behavior_awid_test','awid_diagnostic'),('behavior_wpa3_holdout','test_metrics'),('behavior_negative','negative_control')]
    passed=True;summary={}
    for cache,name in pairs:
        report=out/(name+'.json')
        evaluate(str(path),f'data/processed/{cache_prefix}{cache}.joblib',str(report),str(baseline),source=f'{cache}: consumed regression; excluded from fitting')
        r=json.loads(report.read_text());r['test_used_for_selection']=True
        r['evaluation_note']='Adaptive regression check on previously inspected captures. Not independent generalization evidence.'
        report.write_text(json.dumps(r,indent=2))
        a=r['comparison']['baseline']['metrics'];b=r['ensemble'];ac=a['confusion_matrix_tn_fp_fn_tp'];bc=b['confusion_matrix_tn_fp_fn_tp']
        ok=bc[1]<=ac[1] and bc[2]<=ac[2]
        if name=='new_rogue':ok=ok and bc[1]<ac[1] and bc[2]<ac[2]
        passed &= ok;summary[name]={'before':a,'after':b,'passed':ok}
    decision={'all_error_gates_passed':bool(passed),'artifact_sha256':sha,'comparisons':summary}
    (out/'release_decision.json').write_text(json.dumps(decision,indent=2));print('RELEASE',json.dumps(decision),flush=True)

if __name__=='__main__':
    import sys
    run(sys.argv[1],sys.argv[2] if len(sys.argv)>2 else 'ad_')
