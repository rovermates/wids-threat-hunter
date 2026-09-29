"""Write the Phase 3 report from preserved experiment and evaluation evidence."""
import json
from pathlib import Path

import joblib
import numpy as np

from backend.train_ensemble import metrics


def report():
    root = Path(__file__).resolve().parents[1]
    models = root / 'backend/models/deployment'
    read = lambda name: json.loads((models / name).read_text(encoding='utf-8'))
    test, val, meta = read('test_metrics.json'), read('validation_metrics.json'), read('metadata.json')
    trials = read('experiments.json')
    data = joblib.load(root / 'data/processed/ml_test_full.joblib')['data']['test']
    predictions = np.load(models / 'test_metrics.npz')
    restricted = data.label.isin(['normal', 'evil_twin']).to_numpy()
    diagnostic = metrics((data.label[restricted] == 'evil_twin').to_numpy(dtype=int),
                         predictions['predictions'][restricted], predictions['vote_scores'][restricted])
    # This descriptive slice excludes other attack families; it is NOT model selection.
    (models / 'restricted_slice_diagnostic.json').write_text(json.dumps({
        'definition': 'Only normal and evil_twin test rows; excludes all other attacks',
        'not_primary_evaluation': True, 'metrics': diagnostic}, indent=2), encoding='utf-8')
    best = {}
    for trial in trials:
        name = trial['feature_set']
        if name not in best or trial['validation']['f1'] > best[name]['validation']['f1']:
            best[name] = trial
    f = lambda v: f'{v:.4f}'
    text = [
        '# Phase 3 training and independent evaluation results', '',
        'The ensemble engine is implemented, trained and saved. Its strongest validation model',
        'does not yet provide reliable evil-twin specificity across all attack families in the',
        'independent test capture. Treat the artifact as an experimental research model.', '',
        f"Completed {len(trials)} validation candidates over the acquired AWID ATK data.",
        'No final-test results were used to select features, parameters or the model.', '',
        '## Primary results', '',
        '| Dataset | Rows | Evil twin rows | Precision | Recall | F1 | PR-AUC trapezoid | Average precision |',
        '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
    for name, result in [('Chronological validation', val), ('Independent test', test)]:
        m = result['ensemble']
        text.append(f"| {name} | {m['rows']:,} | {m['positive_rows']:,} | " +
                    ' | '.join(f(m[k]) for k in ['precision', 'recall', 'f1', 'pr_auc_trapezoid', 'average_precision']) + ' |')
    tn, fp, fn, tp = test['ensemble']['confusion_matrix_tn_fp_fn_tp']
    text += ['', f'Test confusion counts: TN {tn:,}; FP {fp:,}; FN {fn:,}; TP {tp:,}.',
             f'Overall accuracy is {(tn + tp) / len(data):.4%}, but predicting every row negative',
             f"would already achieve {1 - test['ensemble']['positive_rows'] / len(data):.4%}.",
             'Accuracy therefore hides the rare-target errors and is not the selection metric.', '',
             'PR-AUC uses only the three hard-vote score levels. Its linear interpolation can',
             'look optimistic; average precision is reported alongside it. Scores are not probabilities.', '',
             '## Error analysis', '',
             '| Original test label | Rows | Predicted evil twin |', '| --- | ---: | ---: |']
    for label, counts in test['by_original_label'].items():
        if counts['predicted_rogue']:
            text.append(f"| {label} | {counts['rows']:,} | {counts['predicted_rogue']:,} |")
    normal = test['by_original_label']['normal']
    text += ['', f"Only {normal['predicted_rogue']} of {normal['rows']:,} normal frames were false alerts "
             f"({normal['predicted_rogue'] / normal['rows']:.4%}). Most false alerts came from other",
             'impersonation attacks (cafe_latte and hirte). Hirte is absent from the training capture.',
             'The classifier detects suspicious behavior but does not reliably distinguish these',
             'attack families from evil twin. They remain negatives for the declared target;',
             'relabeling them after seeing test results would change the question being evaluated.', '',
             f"On the restricted normal-versus-evil-twin slice, precision is {diagnostic['precision']:.2%},",
             f"recall {diagnostic['recall']:.2%}, and F1 {diagnostic['f1']:.2%}.",
             'This is a post-evaluation diagnostic that excludes other attacks, not the primary',
             'benchmark or evidence of general rogue-AP accuracy.', '',
             'The selected hard ensemble made exactly the same final-test decisions as its RF',
             'component. The SGD component did not remove the RF false positives on this capture.',
             'No ensemble improvement over RF should be claimed from this result.', '',
             '## Selected model', '',
             f"- Feature set: `{meta['selection']['feature_set']}` ({len(meta['features'])} inputs).",
             '- RF: 100 trees, balanced class weights, random_state 42, min_samples_leaf 2.',
             '- SGD: hinge loss, L2, max_iter 1000, balanced weights, alpha 0.001, random_state 42.',
             '- Equal hard votes; a tie predicts the non-target class.',
             '- RSSI history: 100 frames. Median imputers and SVM scaler fitted on training only.',
             '- Training: 1,526,238 chronological rows, reduced to 272,614 by benign undersampling.',
             '- Validation: 269,337 rows. Test: separate 575,643-row capture.',
             '- Default 70% training would contain no evil twin, so the documented coverage audit',
             '  selected an 85/15 training/validation division before experiments.', '',
             '## Feature search', '',
             '| Feature set | Best validation F1 |', '| --- | ---: |']
    for name, trial in best.items():
        text.append(f"| {name} | {trial['validation']['f1']:.4f} |")
    text += ['', 'The search was adaptive to validation results. Adding all headers failed, while',
             'adding frame length alone helped substantially. The independent test reveals the',
             'limits of this within-capture validation improvement.', '',
             '## Saved outputs and verification', '',
             '- [Complete inference artifact](../backend/models/deployment/trained_ensemble.joblib)',
             '- [Scaler](../backend/models/deployment/scaler.joblib) and [imputers](../backend/models/deployment/imputers.joblib)',
             '- [All 44 experiments](../backend/models/deployment/experiments.json)',
             '- [Test metrics and curve points](../backend/models/deployment/test_metrics.json)',
             '- [Metadata and source hashes](../backend/models/deployment/metadata.json)',
             '- [Implementation and reproduction guide](phase3-ensemble.md)', '',
             'Verification includes model serialization parity, temporal chunk equivalence,',
             'training-only preprocessing, protocol aliases, late-error export cleanup, and the',
             'existing ingestion/feature tests. Both AWID and native PCAP inference smoke tests ran.',
             'Synthetic PCAP output is an integration check, not accuracy evidence.', '',
             f"Prediction plus vote scoring on pre-extracted test features took {test['predict_and_score_seconds']:.2f} seconds",
             'on this machine; this excludes parsing and feature extraction and is not an API SLA.', '',
             '## What remains before a strong deployment claim', '',
             'Acquire independently labelled captures covering evil twins and confusable impersonation',
             'attacks, reserve new untouched evaluation captures, and use capture/session-level',
             'validation. Improve specificity using those development captures. The current test is',
             'now consumed and must not become a repeatedly tuned holdout. Separately validate PCAP',
             'domain transfer and the proposed low-duty/selective-beaconing and MAC-churn tactics.',
             'The acquired AWID copies still use a public compatibility schema pending official confirmation.', '']
    (root / 'docs/phase3-results.md').write_text('\n'.join(text), encoding='utf-8')
    print('Wrote docs/phase3-results.md')


if __name__ == '__main__':
    report()
