"""Stream offline AWID/PCAP predictions through a trusted Phase 3 artifact."""
import argparse
import os
import tempfile
from pathlib import Path

from backend.core.awid_loader import iter_awid_chunks
from backend.core.ml_engine import InferenceSession
from backend.core.pcap_parser import iter_pcap_chunks
from backend.config import DashboardSettings


def predict_file(source, artifact, destination, *, source_format, variant=None, chunk_size=10000):
    destination = Path(destination).resolve()
    if destination.exists():
        raise FileExistsError(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    session = InferenceSession(artifact)
    chunks = (iter_awid_chunks(source, variant=variant, chunk_size=chunk_size)
              if source_format == 'awid' else iter_pcap_chunks(source, chunk_size=chunk_size))
    temporary = None
    count = 0
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n',
                                         dir=destination.parent, suffix='.partial', delete=False) as stream:
            temporary = Path(stream.name)
            for raw in chunks:
                predictions = session.predict_chunk(raw)
                predictions.insert(0, 'source_row', raw.index)
                predictions.insert(1, 'timestamp_ns', raw.timestamp_ns)
                stream.write(predictions.to_json(orient='records', lines=True))
                count += len(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, destination)
    finally:
        chunks.close()
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return count


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source')
    p.add_argument('--model', default=str(DashboardSettings().model_path))
    p.add_argument('--output', required=True)
    p.add_argument('--format', choices=['awid', 'pcap'], required=True)
    p.add_argument('--variant', choices=['ATK', 'CLS'])
    p.add_argument('--chunk-size', type=int, default=10000)
    a = p.parse_args()
    print(f'Exported {predict_file(a.source, a.model, a.output, source_format=a.format, variant=a.variant, chunk_size=a.chunk_size)} predictions')
