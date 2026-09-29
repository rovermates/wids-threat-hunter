"""Generate a candid, reproducible release report from saved regression results."""
import json
from backend.refine_v7 import OUT
from pathlib import Path

def run(output=None):
    OUT=Path(output) if output else Path('backend/models/refined_v7')
    names={'new_rogue':'RogueAP blocked capture','new_beacon':'BeaconFlood blocked capture',
           'awid_diagnostic':'AWID advertising diagnostic','test_metrics':'Earlier WPA3 evil-twin capture',
           'negative_control':'Deauthentication negative control'}
    trials=json.loads((OUT/'experiments.json').read_text())
    metadata=json.loads((OUT/'metadata.json').read_text())
    text=['# Refined v7: training, regression results and dashboard release','',
          f"Trained 40 configurations across two passes, then compared {len(trials)} confirmation/recovery operating points. Selected `{metadata['model_name']}` using validation data only.",
          f"Decision threshold: {metadata['threshold']:.8f}. SHA256: `{metadata['artifact_sha256']}`.",'',
          'The user requested refined v7 as the final local dashboard default. Integration is not a certification of production detection quality.',
          'Original v7 and v6 are preserved. No hardware, live scanning or automatic mitigation changes were made.','',
          '**Outcome: marginal improvement only. RogueAP misses fell by one; false-alert counts are unchanged. The requested substantive reduction in both false alerts and misses was not achieved.**','',
          '## Like-for-like regression results','',
          'All counts below concern evaluated beacons/probe responses, not unique confirmed rogue APs.',
          'Each original/refined pair uses identical rows and publisher labels. None of these test rows was fitted.',
          'These captures were previously inspected; results are regression evidence, not fresh independent-device testing.',
          'A precision-heavy candidate reduced false alerts but increased misses. A recall-constrained candidate increased false alerts sharply. Both were rejected as standalone defaults. The final model confirms original-v7 alerts with the behavior model and permits strong behavior scores to recover missed alerts. Its validation minimum family recall must match or exceed original v7. This is adaptive model development, not a blind final test.','',
          '| Capture | Version | Precision | Recall | F1 | False alerts | Missed targets |',
          '|---|---|---:|---:|---:|---:|---:|']
    regressions=[]; summary={}; timings=[]
    for filename,name in names.items():
        report=json.loads((OUT/(filename+'.json')).read_text())
        current=report['ensemble']; old=report['comparison']['baseline']['metrics']
        summary[filename]={'original_v7':old,'refined_v7':current}
        timings.append(f"| {name} | {report['comparison']['baseline']['seconds_median']:.4f} s | {report['comparison']['candidate']['seconds_median']:.4f} s |")
        for version,m in [('Original v7',old),('Refined v7',current)]:
            tn,fp,fn,tp=m['confusion_matrix_tn_fp_fn_tp']
            prf=' | '.join(f'{m[k]*100:.2f}%' for k in ['precision','recall','f1']) if tp+fn else 'N/A | N/A | N/A'
            text.append(f'| {name} | {version} | {prf} | {fp} / {tn+fp} | {fn} / {tp+fn} |')
        for index,label in [(1,'false alerts'),(2,'missed targets')]:
            before=old['confusion_matrix_tn_fp_fn_tp'][index]; after=current['confusion_matrix_tn_fp_fn_tp'][index]
            if after>before:regressions.append(f'{name}: {label} increased from {before} to {after}.')
    text += ['', '## Inference timing', '', 'Median of three runs on the same extracted advertisements. Parsing and UI work are excluded.', '',
             '| Capture | Original v7 | Refined v7 |', '|---|---:|---:|'] + timings
    text += ['', '## Remaining limitations', '']
    text += [f'- {r}' for r in regressions]
    text += ['- Publisher RogueAP labels describe attack periods, including an AP also seen in normal periods; they do not certify AP identities.',
             '- Training and blocked WPA3 tests share sessions/devices. Detection on unseen networks remains unproven.',
             '- No alerts means no model detections within scope, not a safe network.','',
             '## What changed','',
             '- All normal development advertisements retained, instead of substantial negative undersampling.',
             '- Compared positive weights, tree complexity, AP behavior, feature ablations and multiclass family classification.',
             '- Validation selection explicitly penalizes false alerts and precision/recall deficits.',
             '- Dashboard model insights include the difficult RogueAP and negative-control checks, with hash-verified metrics.',
             f'- Active artifact is `{OUT.as_posix()}/trained_ensemble.joblib`. Restart the server and re-upload old captures.',
             '', '## Reproduction and rollback','',
             'Training requires the separately retained development caches. Output directories are write-once; preserve a release before retraining.',
             'Training trials: `python -m backend.refine_v7`, `python -m backend.extend_v7_multiclass`, and `python -m backend.refine_v7_recall`.',
             'Final selection: `python -m backend.select_confirmed_v7`. Evaluation: call `backend.evaluate_refined_v7.run` with `backend/models/final_v7`.',
             'Set `WIDS_MODEL_PATH` to `backend/models/rogue_advertiser_v6/trained_ensemble.joblib` before starting the server to restore v6.',
             'The original v7 remains at `backend/models/additional_captures_v7/trained_ensemble.joblib`.',
             'See `refined-v7-protocol.md` and the saved JSON trial/evaluation reports for selection and data provenance.','']
    Path('docs/refined-v7-results.md').write_text('\n'.join(text),encoding='utf8')
    decision={'deployment':'User-authorized final local dashboard default',
              'production_quality_certified':False,'artifact_sha256':metadata['artifact_sha256'],
              'regressions':regressions,'comparison':summary}
    (OUT/'release_decision.json').write_text(json.dumps(decision,indent=2))
    if OUT.name == 'final_v7':
        prior=Path('backend/models/refined_v7/release_decision.json')
        rejected=json.loads(prior.read_text())
        rejected['deployment']='Rejected; precision-heavy candidate increased missed targets'
        prior.write_text(json.dumps(rejected,indent=2))
        balanced=Path('backend/models/refined_v7_balanced/release_decision.json')
        balanced.write_text(json.dumps({'deployment':'Rejected; recall-focused candidate sharply increased false alerts','production_quality_certified':False},indent=2))
    print(json.dumps({'regressions':regressions,'comparison':summary},indent=2))

if __name__=='__main__':run()
