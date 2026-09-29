"""Build compact full-traffic Phase 2 features with isolated split state."""
import argparse
import hashlib
import json
from pathlib import Path

import joblib
import pandas as pd

from backend.core.awid_loader import IngestionReport, iter_awid_chunks
from backend.core.awid_schema import COLUMNS
from backend.core.feature_builder import TemporalFeatureBuilder
from backend.core.ml_engine import STATIC, TEMPORAL


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def prepare(source, destination, *, training=False, rssi_window=100):
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError(destination)
    cutoff = None
    if training:
        times = pd.read_csv(source, header=None, usecols=[COLUMNS.index('frame.time_epoch')],
                            dtype=str).iloc[:, 0]
        # Exact decimal conversion; do not round epoch values through float.
        value = times.iloc[int(len(times) * .85)]
        sec, _, fraction = value.partition('.')
        cutoff = int(sec) * 10**9 + int(fraction.ljust(9, '0'))
        del times
    builders = {}
    pieces = {}
    report = IngestionReport()
    for raw in iter_awid_chunks(source, variant='ATK', chunk_size=10000, report=report):
        partitions = ({'train': raw[raw.timestamp_ns < cutoff],
                       'validation': raw[raw.timestamp_ns >= cutoff]} if training else {'test': raw})
        for name, part in partitions.items():
            if part.empty:
                continue
            if name not in builders:
                builders[name] = TemporalFeatureBuilder(rssi_window)
                pieces[name] = []
            out = builders[name].transform(part)
            pieces[name].append(out[STATIC + TEMPORAL + ['label', 'timestamp_ns']])
        if report.rows % 100000 == 0:
            print(f'{Path(source).name}: {report.rows:,} rows', flush=True)
    if not report.complete:
        raise RuntimeError('Incomplete ingestion')
    data = {name: pd.concat(parts) for name, parts in pieces.items()}
    expected = {'train', 'validation'} if training else {'test'}
    if set(data) != expected:
        raise ValueError('Empty partition')
    if training and data['train'].timestamp_ns.max() >= data['validation'].timestamp_ns.min():
        raise ValueError('Overlapping chronological partitions')
    meta = {'source': str(Path(source).resolve()), 'sha256': sha256(source),
            'rssi_window': rssi_window, 'cutoff_ns': cutoff, 'ingestion': report.to_dict(),
            'partitions': {name: {'rows': len(d), 'labels': d.label.value_counts().to_dict(),
                'start_ns': int(d.timestamp_ns.min()), 'end_ns': int(d.timestamp_ns.max())}
                for name, d in data.items()}}
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix('.partial')
    try:
        joblib.dump({'data': data, 'metadata': meta}, temporary, compress=3)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    destination.with_suffix('.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
    print(json.dumps(meta, indent=2), flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source')
    p.add_argument('destination')
    p.add_argument('--training', action='store_true')
    p.add_argument('--rssi-window', type=int, default=100)
    a = p.parse_args()
    prepare(a.source, a.destination, training=a.training, rssi_window=a.rssi_window)
