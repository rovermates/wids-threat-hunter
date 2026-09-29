"""Join existing packet header fields to verified temporal caches by source row."""
import argparse
from pathlib import Path

import joblib
import pandas as pd

from backend.core.awid_schema import COLUMNS
from backend.core.ml_engine import PROTOCOL_FIELDS, protocol_features
from backend.prepare_ml_data import sha256


def augment(cache, destination):
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError(destination)
    bundle = joblib.load(cache)
    source = bundle['metadata']['source']
    if sha256(source) != bundle['metadata']['sha256']:
        raise ValueError('Source changed since temporal extraction')
    columns = [pair[0] for pair in PROTOCOL_FIELDS.values()]
    positions = [COLUMNS.index(name) for name in columns]
    raw = pd.read_csv(source, header=None, usecols=positions, dtype='string',
                       keep_default_na=False)
    raw.columns = [COLUMNS[int(i)] for i in raw.columns]
    raw.index = pd.RangeIndex(1, len(raw) + 1, name='source_row')
    extra = protocol_features(raw)
    if len(extra) != bundle['metadata']['ingestion']['rows']:
        raise ValueError('Row coverage mismatch')
    for name, frame in bundle['data'].items():
        bundle['data'][name] = frame.join(extra, validate='one_to_one')
    bundle['metadata']['protocol_fields'] = columns
    joblib.dump(bundle, destination, compress=3)
    print(f'Added {len(columns)} protocol features to {destination}', flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('cache')
    p.add_argument('destination')
    a = p.parse_args()
    augment(a.cache, a.destination)
