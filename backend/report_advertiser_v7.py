"""Produce the complete paired regression table from saved measured results."""
import json
from pathlib import Path

def run():
    p=Path('backend/models/v7_advertiser_combined')
    lines=['# v7 advertiser correction: measured results','',
        'Default: `backend/models/v7_advertiser_combined/trained_ensemble.joblib`. Previous `final_v7` is retained for rollback.',
        '', '| Regression | Precision before / after | Recall before / after | F1 before / after | False flags before / after | Misses before / after |',
        '|---|---:|---:|---:|---:|---:|']
    for name in ['new_rogue','awid_diagnostic','test_metrics','new_beacon','negative_control']:
        r=json.loads((p/(name+'.json')).read_text());a=r['comparison']['baseline']['metrics'];b=r['ensemble']
        def metric(k):return f'{a[k]*100:.2f}% / {b[k]*100:.2f}%' if b['positive_rows'] else 'N/A (negative only)'
        ca=a['confusion_matrix_tn_fp_fn_tp'];cb=b['confusion_matrix_tn_fp_fn_tp']
        lines.append(f'| {name} | {metric("precision")} | {metric("recall")} | {metric("f1")} | {ca[1]} / {cb[1]} | {ca[2]} / {cb[2]} |')
    lines += ['', 'RogueAP missed advertisements decrease 43.6%; Deauth false flags decrease 15.8%. AWID increases by two false flags. The revision is deployed for the overall improvement, not because it dominates every dataset.',
        '', 'These are previously examined capture regressions. No test rows were fitted; model and threshold selection used development validation. Prior regression findings informed development, so these are not independent final-test results.',
        '', 'Sixteen training trials tested corrected and hybrid features. Standalone precision and recall candidates were rejected. The final confirmation/recovery search required no source-level validation false-positive increase or true-positive decrease before maximizing mean F1.',
        '', '| Inference-only timing | Previous median seconds | New median seconds |','|---|---:|---:|']
    for name in ['new_rogue','awid_diagnostic']:
        c=json.loads((p/(name+'.json')).read_text())['comparison']
        lines.append(f'| {name} | {c["baseline"]["seconds_median"]:.4f} | {c["candidate"]["seconds_median"]:.4f} |')
    lines += ['', 'Timings exclude parsing and feature extraction and were measured during concurrent work. The additional model costs compute; no throughput improvement is claimed.',
        '', 'See [investigation and dataset audit](advertiser-feature-investigation.md) for reproduced defects, new downloads and label limitations. Full experiment and regression JSON files are alongside each model artifact.']
    Path('docs/advertiser-v7-results.md').write_text('\n'.join(lines)+'\n',encoding='utf8')

if __name__=='__main__':run()
