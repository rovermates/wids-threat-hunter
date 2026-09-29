"""Stream AWID or saved Wi-Fi captures to a new temporal-feature JSONL file."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

from backend.core.awid_loader import IngestionReport, iter_awid_chunks
from backend.core.pcap_parser import PcapReport, iter_pcap_chunks
from backend.core.feature_builder import iter_temporal_chunks


def export_features(source, destination, *, input_format, rssi_window=100,
                    chunk_size=10_000, variant=None, tshark_path=None):
    destination = Path(destination).resolve()
    if destination.exists():
        raise FileExistsError(f"Output already exists: {destination}")
    if input_format == "awid":
        report = IngestionReport()
        chunks = iter_awid_chunks(source, variant=variant, chunk_size=chunk_size, report=report)
    elif input_format == "pcap":
        report = PcapReport()
        chunks = iter_pcap_chunks(source, chunk_size=chunk_size,
                                  tshark_path=tshark_path, report=report)
    else:
        raise ValueError("input_format must be awid or pcap")
    features = iter_temporal_chunks(chunks, rssi_window=rssi_window)
    temporary = None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=destination.parent, suffix=".partial",
                                         delete=False) as stream:
            temporary = Path(stream.name)
            for frame in features:
                stream.write(frame.to_json(orient="records", lines=True,
                                           date_format="iso", date_unit="ns"))
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, destination)
    finally:
        features.close()
        chunks.close()
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return {"input": report.to_dict(), "output": str(destination),
            "rssi_window": rssi_window, "churn_window_seconds": 60}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path")
    parser.add_argument("--output", required=True)
    parser.add_argument("--format", choices=("awid", "pcap"), required=True)
    parser.add_argument("--rssi-window", type=int, default=100)
    parser.add_argument("--chunk-size", type=int, default=10_000)
    parser.add_argument("--variant", choices=("CLS", "ATK"))
    parser.add_argument("--tshark")
    args = parser.parse_args()
    try:
        result = export_features(args.path, args.output, input_format=args.format,
                                 rssi_window=args.rssi_window, chunk_size=args.chunk_size,
                                 variant=args.variant, tshark_path=args.tshark)
    except (ValueError, OSError) as exc:
        print(f"Temporal feature extraction failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
