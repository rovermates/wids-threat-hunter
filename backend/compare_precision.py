"""Release checks on frozen predictions, never threshold fitting."""
import csv,hashlib,json
from pathlib import Path


def compare(folder='backend/models/precision_v3'):
    folder=Path(folder)
    frozen=json.loads((folder/'FROZEN.json').read_text())['artifact_sha256']
    if hashlib.sha256((folder/'trained_ensemble.joblib').read_bytes()).hexdigest()!=frozen:
        raise ValueError('Artifact changed after freeze')
    reports={name:json.loads((folder/file).read_text()) for name,file in {
        'AWID':'awid_diagnostic.json','WPA3':'test_metrics.json','Negative control':'negative_control.json'}.items()}
    rows=[]
    for dataset,report in reports.items():
        if report['artifact_sha256']!=frozen:raise ValueError('Report/model hash mismatch')
        for model,result in report['comparison'].items():
            m=result['metrics'];tn,fp,fn,tp=m['confusion_matrix_tn_fp_fn_tp']
            rows.append({'dataset':dataset,'model':model,'rows':m['rows'],'precision':m['precision'],
                'recall':m['recall'],'f1':m['f1'],'false_positives':fp,'false_negatives':fn,
                'true_positives':tp,'false_positive_rate':fp/(tn+fp),'scoring_seconds':result['seconds_median']})
        if report['comparison']['candidate']['metrics']['rows']!=report['comparison']['baseline']['metrics']['rows']:
            raise ValueError('Mismatched comparison rows')
    a=reports['AWID']['comparison'];w=reports['WPA3']['comparison'];n=reports['Negative control']['comparison']
    checks={'awid_precision_gain_10pp':a['candidate']['metrics']['precision']>=a['baseline']['metrics']['precision']+.1,
            'awid_f1_gain_10pp':a['candidate']['metrics']['f1']>=a['baseline']['metrics']['f1']+.1,
            'awid_recall_85pct':a['candidate']['metrics']['recall']>=.85,
            'wpa3_f1_95pct':w['candidate']['metrics']['f1']>=.95,
            'negative_false_alerts_not_increased':n['candidate']['metrics']['confusion_matrix_tn_fp_fn_tp'][1]<=n['baseline']['metrics']['confusion_matrix_tn_fp_fn_tp'][1]}
    report={'artifact_sha256':frozen,'baseline_artifact_sha256':hashlib.sha256(Path('backend/models/detection_multisource_v2/trained_ensemble.joblib').read_bytes()).hexdigest(),
            'checks':checks,'promote':all(checks.values()),'results':rows}
    (folder/'comparison.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    with (folder/'comparison.csv').open('w',newline='',encoding='utf8') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    print(json.dumps(report,indent=2))
    return report


if __name__=='__main__':compare()
