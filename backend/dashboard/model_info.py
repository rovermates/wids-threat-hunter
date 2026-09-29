"""Benchmark provenance and RF feature importance, never uploaded-data accuracy."""
import hashlib
import json

from backend.core.ml_engine import InferenceSession


def load_model_info(path):
    result = {"ready": False, "error": None, "benchmark": None, "feature_importance": [],
              "target": "Suspected evil twin", "score_semantics": "Positive vote fraction, not probability"}
    try:
        session = InferenceSession(path)
        bundle = session.bundle
        result['model_name'] = {'rf64': 'Random forest, 64 trees', 'hist160_binary': 'Histogram gradient boosting',
            'rf96_leaf2_binary': 'Random forest with AP behavior', 'rf96_leaf8_binary': 'Random forest with AP behavior',
            'rf96_leaf2_multi': 'Multiclass random forest', 'rf96_leaf8_multi': 'Multiclass random forest',
            'rf_impersonation':'Rogue-AP impersonation forest', 'hist_impersonation':'Rogue-AP impersonation boosting',
            'extra96_multi': 'Multiclass Extra Trees', 'hist': 'Behavior gradient boosting',
            'rf_binary': 'Behavior random forest', 'rf_multiclass': 'Multiclass behavior forest'}.get(bundle.get('model_name'), bundle.get('model_name', 'RF + linear SVM ensemble'))
        result['decision_threshold'] = bundle.get('threshold')
        result['target'] = bundle.get('target', result['target'])
        result['scope'] = bundle.get('scope', 'all_frames')
        if result['scope'] == 'ap_advertisements':
            result['target'] = 'Rogue AP advertisements: beacons and probe responses. Other frames provide context only.'
        result['score_semantics'] = bundle.get('score_semantics', result['score_semantics'])
        rf = bundle['model'].named_estimators_['rf'] if bundle['format_version'] == 1 else bundle['model']
        estimator = rf.named_steps['model']
        if hasattr(estimator, 'feature_importances_'):
            names = list(rf.named_steps['imputer'].get_feature_names_out(bundle['features']))
            weights = estimator.feature_importances_
            result['feature_importance'] = sorted(
                [{'feature': str(name), 'importance': float(weight)} for name, weight in zip(names, weights)],
                key=lambda item: item['importance'], reverse=True)
            result['importance_method'] = 'Tree mean decrease in impurity'
        else:
            result['feature_importance'] = bundle.get('feature_importance', [])
            result['importance_method'] = bundle.get('importance_method', 'Unavailable for this model')
        result['ready'] = True
        result["artifact_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        result['regression_benchmarks'] = []
        for filename in ['new_rogue.json', 'new_beacon.json', 'negative_control.json']:
            candidate_path = path.parent / filename
            if candidate_path.is_file():
                candidate = json.loads(candidate_path.read_text(encoding='utf8'))
                if candidate.get('artifact_sha256') == result['artifact_sha256']:
                    values = candidate['ensemble']
                    tn, fp, fn, tp = values['confusion_matrix_tn_fp_fn_tp']
                    result['regression_benchmarks'].append({
                        'source': candidate['evaluation_source'], 'rows': values['rows'],
                        'precision': values['precision'], 'recall': values['recall'],
                        'f1': values['f1'], 'false_positives': fp, 'false_negatives': fn,
                        'positive_rows': tp + fn, 'negative_rows': tn + fp})
        metrics_path = path.parent / "test_metrics.json"
        if (path.parent / 'awid_diagnostic.json').is_file():
            metrics_path = path.parent / 'awid_diagnostic.json'
        if metrics_path.is_file():
            report = json.loads(metrics_path.read_text(encoding="utf-8"))
            if report.get("artifact_sha256") == result["artifact_sha256"]:
                metrics = report["ensemble"]
                tn, fp, fn, tp = metrics["confusion_matrix_tn_fp_fn_tp"]
                result["benchmark"] = {
                    "source": report.get("evaluation_source", "Independent AWID ATK test"), "rows": metrics["rows"],
                    "accuracy": (tn + tp) / (tn + fp + fn + tp),
                    "f1": metrics["f1"], "precision": metrics["precision"], "recall": metrics["recall"],
                    "confusion_matrix": [[tn, fp], [fn, tp]],
                    "labels": report.get("class_labels", ["Non-target", "Evil twin"]),
                    "scope": report.get("scope", "all_frames"),
                    "note": report.get("evaluation_note", "Research benchmark, not this capture's accuracy. Other impersonation attacks cause false alerts.")}
            else:
                result["benchmark_note"] = "Benchmark unavailable: artifact hash does not match the saved evaluation."
        else:
            result["benchmark_note"] = "No verified test metrics accompany this model."
        external_path = path.parent / 'test_metrics.json'
        if metrics_path != external_path and external_path.is_file():
            external = json.loads(external_path.read_text(encoding='utf8'))
            if external.get('artifact_sha256') == result['artifact_sha256']:
                result['additional_benchmark'] = {'source': external['evaluation_source'],
                    'f1': external['ensemble']['f1'], 'note': external['evaluation_note']}

    except (OSError, ValueError, KeyError, AttributeError, TypeError) as exc:
        result["error"] = f"Model unavailable: {type(exc).__name__}. Check the trusted deployment artifact."
    return result
