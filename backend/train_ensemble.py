"""Reproducible chronological model selection; final test is a separate command."""
import argparse
import json
import platform
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.metrics import (auc, average_precision_score, confusion_matrix,
                             precision_recall_curve, precision_score, recall_score, f1_score)

from backend.core.class_balance import undersample_training
from backend.core.ml_engine import FEATURE_SETS, make_ensemble, numeric_features, vote_score


def metrics(y, predictions, scores):
    p, r, _ = precision_recall_curve(y, scores) if np.any(y) else (None, None, None)
    return {'rows': len(y), 'positive_rows': int(np.sum(y)),
            'precision': float(precision_score(y, predictions, zero_division=0)),
            'recall': float(recall_score(y, predictions, zero_division=0)),
            'f1': float(f1_score(y, predictions, zero_division=0)),
            'pr_auc_trapezoid': float(auc(r, p)) if np.any(y) else None,
            'average_precision': float(average_precision_score(y, scores)) if np.any(y) else None,
            'confusion_matrix_tn_fp_fn_tp': confusion_matrix(y, predictions, labels=[0, 1]).ravel().tolist()}


def evaluate(bundle, frame):
    x = numeric_features(frame, bundle['features'])
    y = (frame.label == 'evil_twin').to_numpy(dtype=int)
    model = bundle['model']
    start = time.perf_counter()
    pred, score = model.predict(x), vote_score(model, x)
    elapsed = time.perf_counter() - start
    curve_p, curve_r, curve_t = precision_recall_curve(y, score)
    result = {'ensemble': metrics(y, pred, score), 'components': {},
              'predict_and_score_seconds': elapsed,
              'pr_curve': {'precision': curve_p.tolist(), 'recall': curve_r.tolist(),
                           'thresholds': curve_t.tolist()},
              'by_original_label': {str(label): {'rows': int(mask.sum()),
                 'predicted_rogue': int(pred[mask].sum())}
                 for label in frame.label.unique() for mask in [(frame.label == label).to_numpy()]},
              'time_blocks': []}
    for name, estimator in model.named_estimators_.items():
        s = estimator.predict_proba(x)[:, 1] if name == 'rf' else estimator.decision_function(x)
        result['components'][name] = metrics(y, estimator.predict(x), s)
    for indices in np.array_split(np.arange(len(frame)), 5):
        if len(indices):
            result['time_blocks'].append(metrics(y[indices], pred[indices], score[indices]))
    return result, pred, score


def train(cache, output, feature_sets=('static', 'temporal', 'combined'),
          leaves=(1, 5), alphas=(0.00001, 0.0001, 0.001)):
    output = Path(output)
    if output.exists():
        raise FileExistsError(output)
    source = joblib.load(cache)
    parts = source['data']
    train_frame, balance = undersample_training(parts['train'], benign_to_attack_ratio=1.0)
    validation = parts['validation']
    for frame in [train_frame, validation]:
        if not (frame.label == 'evil_twin').any() or not (frame.label != 'evil_twin').any():
            raise ValueError('Both target classes required; never shuffle to repair chronology')
    output.mkdir(parents=True)
    y = (train_frame.label == 'evil_twin').to_numpy(dtype=int)
    vy = (validation.label == 'evil_twin').to_numpy(dtype=int)
    experiments = []
    best_key = (-1, -1, -1)
    best = None
    # Fixed search declared before looking at validation results; no test input here.
    for feature_set in feature_sets:
        features = FEATURE_SETS[feature_set]
        x = numeric_features(train_frame, features)
        vx = numeric_features(validation, features)
        for leaf in leaves:
            for alpha in alphas:
                start = time.monotonic()
                model = make_ensemble(alpha, leaf)
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    model.fit(x, y)
                m = metrics(vy, model.predict(vx), vote_score(model, vx))
                trial = {'feature_set': feature_set, 'min_samples_leaf': leaf, 'alpha': alpha,
                         'seconds': time.monotonic() - start, 'validation': m,
                         'warnings': sorted(set(str(w.message) for w in caught))}
                experiments.append(trial)
                print(json.dumps(trial), flush=True)
                (output / 'experiments.json').write_text(json.dumps(experiments, indent=2), encoding='utf-8')
                key = (m['f1'], m['average_precision'], m['precision'])
                if key > best_key:
                    best_key = key
                    best = {'format_version': 1, 'model': model, 'features': features,
                            'rssi_window': source['metadata']['rssi_window'],
                            'target': 'evil_twin versus all other AWID ATK labels',
                            'score_semantics': 'fraction of positive votes; not probability',
                            'selection': trial, 'training_metadata': source['metadata'],
                            'balance': balance, 'sklearn_version': sklearn.__version__,
                            'python_version': platform.python_version()}
    result, pred, score = evaluate(best, validation)
    joblib.dump(best, output / 'trained_ensemble.joblib', compress=3)
    joblib.dump(best['model'].named_estimators_['svm'].named_steps['scaler'],
                output / 'scaler.joblib', compress=3)
    joblib.dump({name: est.named_steps['imputer'] for name, est in best['model'].named_estimators_.items()},
                output / 'imputers.joblib', compress=3)
    (output / 'validation_metrics.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    metadata = {k: v for k, v in best.items() if k != 'model'}
    (output / 'metadata.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    forest = best['model'].named_estimators_['rf']
    importance = dict(zip(forest.named_steps['imputer'].get_feature_names_out(best['features']),
                          map(float, forest.named_steps['model'].feature_importances_)))
    audit = {'feature_importance_rf_impurity': importance,
             'missing_fraction': {name: {k: float(v) for k, v in
                numeric_features(frame, best['features']).isna().mean().items()}
                for name, frame in [('train_before_sampling', parts['train']), ('validation', validation)]}}
    (output / 'feature_audit.json').write_text(json.dumps(audit, indent=2), encoding='utf-8')
    reloaded = joblib.load(output / 'trained_ensemble.joblib')
    np.testing.assert_array_equal(reloaded['model'].predict(numeric_features(validation, best['features'])), pred)
    print('Model selected, saved and reload parity verified.', flush=True)


def test(artifact, cache, destination):
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError(destination)
    bundle = joblib.load(artifact)
    source = joblib.load(cache)
    if source['metadata']['rssi_window'] != bundle['rssi_window']:
        raise ValueError('Feature-window mismatch')
    if source['metadata']['sha256'] == bundle['training_metadata']['sha256']:
        raise ValueError('Test source matches training source')
    result, pred, score = evaluate(bundle, source['data']['test'])
    result['test_metadata'] = source['metadata']
    result['artifact_sha256'] = __import__('hashlib').sha256(Path(artifact).read_bytes()).hexdigest()
    destination.write_text(json.dumps(result, indent=2), encoding='utf-8')
    np.savez_compressed(destination.with_suffix('.npz'), predictions=pred, vote_scores=score,
                        source_rows=source['data']['test'].index.to_numpy())
    print(json.dumps(result, indent=2), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('train')
    p.add_argument('cache')
    p.add_argument('output')
    p.add_argument('--feature-sets', nargs='+', choices=list(FEATURE_SETS),
                   default=['static', 'temporal', 'combined'])
    p.add_argument('--leaves', nargs='+', type=int, default=[1, 5])
    p.add_argument('--alphas', nargs='+', type=float, default=[0.00001, 0.0001, 0.001])
    p = sub.add_parser('test')
    p.add_argument('artifact')
    p.add_argument('cache')
    p.add_argument('destination')
    a = parser.parse_args()
    if a.command == 'train':
        train(a.cache, a.output, a.feature_sets, a.leaves, a.alphas)
    else:
        test(a.artifact, a.cache, a.destination)
