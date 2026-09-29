"""Command-line validation of an offline Wi-Fi capture."""
import argparse
import json
import sys
from backend.config import DEFAULT_CHUNK_SIZE
from backend.core.pcap_parser import inspect_pcap
from backend.core.frame_export import export_pcap_frames


def main():
    parser = argparse.ArgumentParser(description="Extract saved Wi-Fi PCAP/PCAPNG with native tshark")
    parser.add_argument("path")
    parser.add_argument("--output", help="New JSONL file for extracted frame attributes (never overwritten)")
    parser.add_argument("--tshark", help="Path to tshark executable")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    parser.add_argument("--idle-timeout", type=float, default=120.0)
    args = parser.parse_args()
    try:
        options = dict(tshark_path=args.tshark, chunk_size=args.chunk_size, idle_timeout=args.idle_timeout)
        report = (export_pcap_frames(args.path, args.output, **options) if args.output
                  else inspect_pcap(args.path, **options))
    except (ValueError, OSError) as exc:
        print(f"PCAP extraction failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
