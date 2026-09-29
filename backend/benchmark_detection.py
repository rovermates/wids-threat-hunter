"""Evaluate a frozen candidate once; consumed AWID test is explicitly diagnostic."""
import argparse
import hashlib
import json
from pathlib import Path
import time

import joblib
import numpy as np
from threadpoolctl import threadpool_limits

from backend.core.ml_engine import vote_score
from backend.train_ensemble import metrics


def score_bundle(bundle, frame):
    x = frame[bundle['features']].astype('float64')
    model = bundle['model']
    if bundle['format_version'] == 1:
        return model.predict(x), vote_score(model, x)
    classes = list(model.classes_)
    target = 'evil_twin' if 'evil_twin' in classes else 1
    scores = model.predict_proba(x)[:, classes.index(target)]
    if bundle.get('score_history'):
        from backend.core.score_history import score_cached_blocks
        scores = score_cached_blocks(frame, scores, bundle['score_history'])
    return (scores >= bundle['threshold']).astype(int), scores


def evaluate(artifact, cache, output, baseline=None, partition='test', source='AWID2 consumed-test diagnostic'):
    output = Path(output)
    if output.exists():
        raise FileExistsError(output)
    dataset = joblib.load(cache)
    frame = dataset['data'][partition]
    bundle = joblib.load(artifact)
    source_rows = len(frame)
    if bundle.get('scope') == 'ap_advertisements':
        frame = frame.loc[(frame.frame_type==0)&frame.frame_subtype.isin([5,8])]
    target_labels = bundle.get('target_labels', ['evil_twin'])
    y = frame.label.isin(target_labels).to_numpy(dtype=int)
    results = {}
    with threadpool_limits(limits=4):
        for name, current in [('candidate', bundle), *([('baseline', joblib.load(baseline))] if baseline else [])]:
            times = []
            for _ in range(3):
                start = time.perf_counter()
                pred, scores = score_bundle(current, frame)
                times.append(time.perf_counter() - start)
            results[name] = {'metrics': metrics(y, pred, scores), 'seconds_median': float(np.median(times)),
                'timing_repetitions': times, 'by_original_label': {
                    str(label): {'rows': int(mask.sum()), 'predicted_rogue': int(pred[mask].sum())}
                    for label in frame.label.unique() for mask in [(frame.label == label).to_numpy()]}}
            if name == 'candidate':
                np.savez_compressed(output.with_suffix('.npz'), predictions=pred, scores=scores, source_rows=frame.index.to_numpy())
    report = {'ensemble': results['candidate']['metrics'], 'comparison': results,
              'scope': bundle.get('scope','all_frames'), 'source_rows':source_rows, 'excluded_rows':source_rows-len(frame),
              'target_labels': target_labels, 'classification_target': bundle.get('target', 'evil_twin'),
              'class_labels': ['Non-target', bundle.get('positive_label','Evil twin')],
              'artifact_sha256': hashlib.sha256(Path(artifact).read_bytes()).hexdigest(),
              'evaluation_source': source, 'evaluation_note': 'Previously evaluated capture; diagnostic comparison, not fresh independent evidence.'
                  if 'consumed' in source else 'Publisher labels; see dataset audit and split limitations.',
              'test_used_for_selection': False, 'data_metadata': dataset['metadata']}
    output.write_text(json.dumps(report, indent=2), encoding='utf8')
    print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('artifact')
    p.add_argument('cache')
    p.add_argument('output')
    p.add_argument('--baseline')
    p.add_argument('--partition', default='test')
    p.add_argument('--source', default='AWID2 consumed-test diagnostic')
    a = p.parse_args()
    evaluate(a.artifact, a.cache, a.output, a.baseline, a.partition, a.source)
