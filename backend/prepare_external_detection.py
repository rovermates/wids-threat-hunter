"""Align publisher CSV labels to native PCAP frames; build isolated time blocks."""
import argparse
import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from backend.core.pcap_parser import iter_pcap_chunks, PcapReport
from backend.core.feature_builder import TemporalFeatureBuilder
from backend.core.ml_engine import STATIC, TEMPORAL, protocol_features
from backend.core.detection_features import detection_features
from backend.prepare_ml_data import sha256


def prepare(pcap, csv, output, negative=False):
    output = Path(output)
    if output.exists():
        raise FileExistsError(output)
    labels = pd.read_csv(csv, usecols=['frame.number', 'frame.len', 'Label']).set_index('frame.number')
    if not labels.index.is_unique:
        raise ValueError('Duplicate publisher packet numbers')
    mapping = {'Normal': 'normal', 'EvilTwin': 'evil_twin', 'Deauth': 'deauthentication',
               'Deauthentication': 'deauthentication'}
    if not set(labels.Label.unique()) <= set(mapping):
        raise ValueError(f'Unknown publisher labels: {labels.Label.unique()}')
    report = PcapReport()
    parts = {'train': [], 'validation': [], 'test': []}
    origin = None
    last_block = None
    builder = None
    aligned = 0
    for raw in iter_pcap_chunks(pcap, chunk_size=10000, report=report):
        number = raw.packet_number.to_numpy(dtype=int)
        matched = labels.loc[number]
        if not np.array_equal(matched['frame.len'].to_numpy(), raw.original_length.to_numpy()):
            raise ValueError('CSV/PCAP packet lengths disagree')
        raw['label'] = matched.Label.map(mapping).to_numpy()
        aligned += len(raw)
        if origin is None:
            origin = int(raw.timestamp_ns.iloc[0])
        relative = (raw.timestamp_ns - origin) / 1e9
        raw['_block'] = (relative // 30).astype(int)
        raw = raw.loc[((relative % 30) >= 1) & ((relative % 30) < 29)].copy()
        for block, group in raw.groupby('_block', sort=False):
            if block != last_block:
                builder = TemporalFeatureBuilder(100)
                last_block = block
            frame = builder.transform(group)
            for name, values in protocol_features(group).items():
                frame[name] = values
            for name, values in detection_features(group).items():
                frame[name] = values
            features = list(dict.fromkeys(STATIC + TEMPORAL + list(protocol_features(group)) + list(detection_features(group))))
            frame = frame[features + ['label', 'timestamp_ns', 'packet_number', '_block']]
            part = 'test' if negative or block % 5 == 4 else 'validation' if block % 5 == 3 else 'train'
            parts[part].append(frame)
        if aligned % 100000 == 0:
            print('Aligned', aligned, flush=True)
    if not report.complete or report.timestamp_decreases:
        raise ValueError('Incomplete or unordered capture')
    metadata = {'source': str(pcap), 'pcap_sha256': sha256(pcap), 'csv_sha256': sha256(csv),
                'rssi_window': 100, 'parser': report.to_dict(), 'aligned_wifi_frames': aligned,
                'publisher_rows': len(labels), 'split': '30s blocks modulo5, 1s guard, history reset per block',
                'limitation': 'Within-capture blocks share devices/session; publisher scenario labels',
                'counts': {k: pd.concat(v).label.value_counts().to_dict() for k,v in parts.items() if v}}
    combined = {k: pd.concat(v, ignore_index=True) for k,v in parts.items() if v}
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({'data': {k:v for k,v in combined.items() if k != 'test'}, 'metadata': metadata}, output, compress=3)
    joblib.dump({'data': {'test': combined['test']}, 'metadata': metadata}, output.with_name(output.stem + '_holdout.joblib'), compress=3)
    output.with_suffix('.json').write_text(json.dumps(metadata, indent=2), encoding='utf8')
    print(json.dumps(metadata, indent=2), flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('pcap'); p.add_argument('csv'); p.add_argument('output')
    p.add_argument('--negative', action='store_true')
    a = p.parse_args()
    prepare(a.pcap, a.csv, a.output, a.negative)
