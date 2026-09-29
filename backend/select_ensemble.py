"""Freeze the best completed validation run before opening final-test results."""
import argparse
import json
import shutil
from pathlib import Path


def select(runs, output):
    output = Path(output)
    if output.exists():
        raise FileExistsError(output)
    candidates = []
    trials = []
    for run in map(Path, runs):
        metadata = json.loads((run / 'metadata.json').read_text(encoding='utf-8'))
        if not (run / 'trained_ensemble.joblib').is_file():
            raise ValueError(f'Incomplete run: {run}')
        candidates.append((run, metadata))
        for trial in json.loads((run / 'experiments.json').read_text(encoding='utf-8')):
            trials.append({'run': str(run), **trial})
    if len({m['training_metadata']['sha256'] for _, m in candidates}) != 1:
        raise ValueError('Runs use different source captures')
    if len({m['training_metadata']['cutoff_ns'] for _, m in candidates}) != 1:
        raise ValueError('Runs use different validation splits')
    run, metadata = max(candidates, key=lambda pair: tuple(pair[1]['selection']['validation'][key]
                                                        for key in ('f1', 'average_precision', 'precision')))
    output.mkdir(parents=True)
    for name in ['trained_ensemble.joblib', 'scaler.joblib', 'imputers.joblib',
                 'metadata.json', 'validation_metrics.json', 'feature_audit.json']:
        shutil.copy2(run / name, output / name)
    selection = {'selected_run': str(run), 'trial_count': len(trials),
                 'criterion': 'validation F1, then average precision, then precision',
                 'test_used_for_selection': False, 'selection': metadata['selection']}
    (output / 'selection.json').write_text(json.dumps(selection, indent=2), encoding='utf-8')
    (output / 'experiments.json').write_text(json.dumps(trials, indent=2), encoding='utf-8')
    print(json.dumps(selection, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('runs', nargs='+')
    p.add_argument('--output', default='backend/models/deployment')
    a = p.parse_args()
    select(a.runs, a.output)
