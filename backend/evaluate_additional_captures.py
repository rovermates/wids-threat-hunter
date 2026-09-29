"""Evaluate a frozen candidate once, retaining all prespecified datasets."""
import json,hashlib
from pathlib import Path
from backend.benchmark_detection import evaluate
P=Path('backend/models/additional_captures_v7')
BASE='backend/models/rogue_advertiser_v6/trained_ensemble.joblib'
def run():
 for cache,name,source in [('round2_rogue_holdout','new_rogue','New RogueAP same-session blocked holdout'),('round2_beacon_holdout','new_beacon','New BeaconFlood labeled-prefix same-session blocked holdout'),('behavior_awid_test','awid_diagnostic','AWID2 consumed-test diagnostic'),('behavior_wpa3_holdout','test_metrics','WPA3 consumed blocked holdout'),('behavior_negative','negative_control','WPA3 consumed negative control')]:
  evaluate(str(P/'trained_ensemble.joblib'),'data/processed/'+cache+'.joblib',str(P/(name+'.json')),BASE,source=source)
 r={n:json.loads((P/(n+'.json')).read_text()) for n in ['new_rogue','new_beacon','awid_diagnostic','test_metrics','negative_control']}
 m=lambda n:r[n]['ensemble'];b=lambda n:r[n]['comparison']['baseline']['metrics']
 fpr=lambda n:m(n)['confusion_matrix_tn_fp_fn_tp'][1]/max(1,m(n)['rows']-m(n)['positive_rows'])
 gates={'development_gates':json.loads((P/'metadata.json').read_text())['selection']['gates_met'],'new_rogue_precision':m('new_rogue')['precision']>=.95,'new_rogue_recall':m('new_rogue')['recall']>=.90,'awid_f1_nonregression':m('awid_diagnostic')['f1']>=b('awid_diagnostic')['f1']-.01,'awid_recall_nonregression':m('awid_diagnostic')['recall']>=b('awid_diagnostic')['recall']-.01,'old_wpa3_f1':m('test_metrics')['f1']>=.99,'beacon_negative_fpr':fpr('new_beacon')<=.001,'old_negative_fpr':fpr('negative_control')<=.001}
 decision={'numeric_gates':gates,'numeric_gates_passed':all(gates.values()),'promote':False,'reason':'New publisher labels are attack-period labels, not verified rogue AP identities; review alongside numeric gates. Current active v6 preserved unless a documented release decision supersedes this.'}
 (P/'release_decision.json').write_text(json.dumps(decision,indent=2));print('RELEASE',decision,flush=True)
if __name__=='__main__':run()
