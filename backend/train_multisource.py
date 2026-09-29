"""Select a model on two development sources; never open external holdout files."""
import argparse
import hashlib
import json
from pathlib import Path
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_curve
from threadpoolctl import threadpool_limits
from backend.core.class_balance import undersample_training
from backend.core.ml_engine import FEATURE_SETS
from backend.core.detection_features import DETECTION_FEATURES
from backend.improve_detection import candidates
from backend.train_ensemble import metrics


def macro_threshold(targets, scores):
    thresholds = np.unique(np.concatenate(scores))
    fs, ps = [], []
    for y, s in zip(targets, scores):
        p, r, t = precision_recall_curve(y, s)
        i = np.searchsorted(t, thresholds, side='left')
        f = np.divide(2*p*r, p+r, out=np.zeros_like(p), where=p+r != 0)
        fs.append(f[i]); ps.append(p[i])
    f = np.mean(fs, axis=0)
    p = np.mean(ps, axis=0)
    best = np.lexsort((thresholds, p, f))[-1]
    return float(thresholds[best])


def train(awid, external, output):
    output = Path(output); output.mkdir(exist_ok=False, parents=True)
    sources = [joblib.load(awid), joblib.load(external)]
    training = pd.concat([undersample_training(s['data']['train'])[0] for s in sources], ignore_index=True)
    validation = [s['data']['validation'] for s in sources]
    y = (training.label == 'evil_twin').to_numpy(dtype=int)
    ys = [(v.label == 'evil_twin').to_numpy(dtype=int) for v in validation]
    base = FEATURE_SETS['combined_plus_frame_length']
    protocol = {'selection': 'mean validation F1 across AWID and WPA3; ties mean precision',
                'sources': [s['metadata'] for s in sources], 'test_used_for_selection': False,
                'features': {'baseline': base, 'portable': base + DETECTION_FEATURES},
                'candidates': ['rf64', 'rf128', 'hist120']}
    (output/'protocol.json').write_text(json.dumps(protocol, indent=2), encoding='utf8')
    trials = []; best_key = (-1, -1)
    with threadpool_limits(limits=4):
        for feature_set, features in protocol['features'].items():
            for name, model in candidates():
                if name not in protocol['candidates']:
                    continue
                start = time.perf_counter()
                model.fit(training[features].astype(float), y)
                seconds = time.perf_counter()-start
                scores = [model.predict_proba(v[features].astype(float))[:,1] for v in validation]
                threshold = macro_threshold(ys, scores)
                reports = [metrics(t, s >= threshold, s) for t,s in zip(ys,scores)]
                key = tuple(float(np.mean([m[k] for m in reports])) for k in ['f1','precision'])
                trial = {'model':name,'features':feature_set,'threshold':threshold,'macro_f1':key[0],
                         'train_seconds':seconds,'validation':dict(zip(['AWID','WPA3'],reports))}
                trials.append(trial)
                print(json.dumps(trial), flush=True)
                (output/'experiments.json').write_text(json.dumps(trials,indent=2),encoding='utf8')
                if key > best_key:
                    best_key = key
                    bundle = {'format_version':2,'model':model,'features':features,'threshold':threshold,
                              'rssi_window':100,'selection':trial,'training_metadata':protocol,
                              'model_name':name,'target':'evil_twin versus other labeled traffic',
                              'score_semantics':'Uncalibrated positive-class score; not a probability guarantee'}
                    joblib.dump(bundle,output/'trained_ensemble.joblib',compress=3)
    bundle = joblib.load(output/'trained_ensemble.joblib')
    metadata = {k:v for k,v in bundle.items() if k != 'model'}
    metadata['artifact_sha256'] = hashlib.sha256((output/'trained_ensemble.joblib').read_bytes()).hexdigest()
    (output/'metadata.json').write_text(json.dumps(metadata,indent=2),encoding='utf8')
    print('FROZEN', bundle['selection'], flush=True)


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('awid');p.add_argument('external');p.add_argument('output')
    a=p.parse_args();train(a.awid,a.external,a.output)
