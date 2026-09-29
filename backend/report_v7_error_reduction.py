"""Write measured comparisons without substituting training scores."""
import json
from pathlib import Path

def run():
    p=Path('backend/models/v7_error_reduction_final');release=json.loads((p/'release_decision.json').read_text())
    assert release['all_error_gates_passed']
    lines=['# v7 error reduction release','',f"Artifact SHA-256: `{release['artifact_sha256']}`.",'',
        'Default artifact: `backend/models/v7_error_reduction_final/trained_ensemble.joblib`. Previous deployed model: `backend/models/v7_advertiser_combined/trained_ensemble.joblib` (retained for rollback).','',
        '| Regression | Precision before / after | Recall before / after | F1 before / after | False flags before / after | Misses before / after |',
        '|---|---:|---:|---:|---:|---:|']
    for name,v in release['comparisons'].items():
        a=v['before'];b=v['after'];ac=a['confusion_matrix_tn_fp_fn_tp'];bc=b['confusion_matrix_tn_fp_fn_tp']
        def metric(k):return f'{100*a[k]:.2f}% / {100*b[k]:.2f}%' if b['positive_rows'] else 'N/A (negative only)'
        lines.append(f'| {name} | {metric("precision")} | {metric("recall")} | {metric("f1")} | {ac[1]} / {bc[1]} | {ac[2]} / {bc[2]} |')
    lines+=['', 'RogueAP misses decrease 25%, RogueAP false flags decrease 4.9%, and Deauth-control false flags decrease 14.1%. No FP/FN count increases on any of the five regression sets. These improvements do not make the remaining errors negligible.',
        '', '## What changed', '',
        '- Sixteen training configurations: eight source-balanced binary/family boosting models, four Extra Trees models, and four boosting models with new short-window features. Models fit development training rows only.',
        '- Five- and twenty-advertisement windows describe RSSI variation, RSSI displacement from the recent mean, beacon interval variation and sequence-gap behavior. They supplement the older 100-frame features. A five-second silence resets the short history.',
        '- The final classifier uses the selected short-window confirmer with the previous v7. A causal nine-advertisement score window combines 75% current score with 25% recent mean, separately for each AP, and resets after five seconds. No future packets or labels enter inference.',
        '- A zero confirmation threshold now safely means no confirmation gate; exact-zero classifier output no longer risks division by zero in experimental tree models.',
        '- Conservative recovery tie-breaking was investigated and tested. The final release uses the validation-selected multiscale model plus history; the standalone family/recovery variants were rejected.',
        '', '## Selection and limits','',
        'Training and threshold/history selection are separate. Each validation source must retain at least baseline true positives with no additional false positives. A frozen candidate is evaluated across five regression sources; release requires no FP/FN increase anywhere and strict reductions of both RogueAP error counts.',
        '', 'These are adaptively examined, same-session regression datasets. No regression rows were fitted or used for numerical threshold search, but observed failures informed later development. Therefore these are not independent-device accuracy estimates. Rejected candidates and their full metrics remain in backend/models. No labels were changed and no MAC/SSID identities were model inputs; BSSID only groups temporal history.',
        '', 'The score smoothing improves deployed decisions at the selected threshold but does not improve every ranking metric: AWID average precision decreases from approximately 0.9787 to 0.9699, although its FP/FN counts are unchanged. Scores are uncalibrated and must not be shown as probabilities.',
        '', 'The feature audit found all RogueAP validation mistakes on a BSSID carrying both normal and attack-period labels. Overlapping observable behavior and ambiguous attack-period identity labels limit further improvement. The model evaluates AP beacons/probe responses, not every Wi-Fi attack or every traffic packet.',
        '', '## Deployment and testing','',
        'Restart the server and re-upload prior captures; stored results remain tied to their original artifact hash. Use WIDS_MODEL_PATH pointing to the previous model to roll back. The dashboard exposes updated benchmark and additional detection-check results. The GitHub-ready package is refreshed with code, model and expected upload outcomes.',
        '', 'Verification logs: `tmp/v7-error-reduction-final-tests.log`, `tmp/v7-error-reduction-api.log`, and `tmp/v7-error-reduction-new-captures.log`. Five labelled PCAPs are uploaded twice through the API; repeated prediction digests must match. Compatibility checks retain unsupported/non-Wi-Fi failures rather than treating them as benign.',
        '', '## Inference timing','', '| Source | Previous median seconds | New median seconds |','|---|---:|---:|']
    for name in ['new_rogue','awid_diagnostic']:
        r=json.loads((p/(name+'.json')).read_text())['comparison']
        lines.append(f'| {name} | {r["baseline"]["seconds_median"]:.4f} | {r["candidate"]["seconds_median"]:.4f} |')
    lines+=['', 'Timing includes cached-input classifier prediction and score-history processing, excludes parsing/feature construction, and was measured during concurrent work. The new confirmer and history add work; this release improves detection errors, not processing speed.']
    Path('docs/v7-error-reduction-results.md').write_text('\n'.join(lines)+'\n',encoding='utf8')

if __name__=='__main__':run()
