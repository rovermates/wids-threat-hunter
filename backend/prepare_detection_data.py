"""Add portable features to existing audited AWID temporal caches, retaining row alignment."""
import argparse
import json
from pathlib import Path

import joblib
import pandas as pd

from backend.core.awid_schema import COLUMNS, STRING_FIELDS
from backend.core.detection_features import detection_features, HEADER_FIELDS
from backend.prepare_ml_data import sha256


def prepare(cache, destination):
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError(destination)
    bundle = joblib.load(cache)
    source = bundle['metadata']['source']
    if sha256(source) != bundle['metadata']['sha256']:
        raise ValueError('Raw source hash differs from the temporal cache')
    names = [*(name for name in HEADER_FIELDS.values() if name in COLUMNS), 'wlan.fc.ds',
             *(STRING_FIELDS[name] for name in ['source_mac', 'destination_mac', 'bssid', 'ssid'])]
    positions = [COLUMNS.index(name) for name in names]
    pieces = []
    for raw in pd.read_csv(source, header=None, usecols=positions, dtype='string', keep_default_na=False, chunksize=100000):
        raw.columns = [COLUMNS[int(i)] for i in raw.columns]
        raw = raw.replace({'?': pd.NA})
        for name in ['source_mac', 'destination_mac', 'bssid', 'ssid']:
            raw[name] = raw[STRING_FIELDS[name]]
        raw.index = raw.index + 1
        pieces.append(detection_features(raw))
    extra = pd.concat(pieces)
    if len(extra) != bundle['metadata']['ingestion']['rows']:
        raise ValueError('Incomplete source coverage')
    for name, frame in bundle['data'].items():
        bundle['data'][name] = frame.join(extra, validate='one_to_one')
    bundle['metadata']['detection_feature_version'] = 1
    joblib.dump(bundle, destination, compress=3)
    destination.with_suffix('.json').write_text(json.dumps(bundle['metadata'], indent=2), encoding='utf8')
    print('Saved', destination, {k: len(v) for k, v in bundle['data'].items()}, flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('cache')
    p.add_argument('destination')
    a = p.parse_args()
    prepare(a.cache, a.destination)
