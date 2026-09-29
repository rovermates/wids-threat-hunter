"""CLI: python -m backend.ingest_awid data/raw/awid2/AWID-CLS-R-Trn.csv"""
import argparse
import json
import sys

from backend.config import DEFAULT_CHUNK_SIZE
from backend.core.awid_loader import inspect_awid


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate one headerless AWID2 CSV in bounded chunks")
    parser.add_argument("path", help="Path to one extracted CLS or ATK CSV")
    parser.add_argument("--variant", choices=["CLS", "ATK"], help="Required for unnamed/sample CSVs")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    args = parser.parse_args()
    try:
        report = inspect_awid(args.path, variant=args.variant, chunk_size=args.chunk_size)
    except (ValueError, OSError) as exc:
        print(f"AWID ingestion failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
