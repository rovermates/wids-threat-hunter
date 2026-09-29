"""Opt-in full-file integration check; not part of fast unit discovery.

Run from project root: python -m backend.tests.validate_downloaded_awid
"""
import json
import platform
import time

import pandas as pd

from backend.config import AWID_DATA_DIR, PROJECT_ROOT
from backend.core.awid_loader import IngestionReport, iter_awid_chunks


def main():
    cls_manifest = json.loads((AWID_DATA_DIR / "acquisition-manifest.json").read_text())
    atk_manifest = json.loads((AWID_DATA_DIR / "atk-acquisition-manifest.json").read_text())
    expected_cls = next(item for item in cls_manifest["files"] if item["name"] == "AWID-CLS-R-Trn.csv")
    results = {"python": platform.python_version(), "pandas": pd.__version__, "files": []}
    for name, expected in (("AWID-CLS-R-Trn.csv", expected_cls), ("AWID-ATK-R-Trn.csv", atk_manifest)):
        report = IngestionReport()
        started = time.perf_counter()
        for chunk in iter_awid_chunks(AWID_DATA_DIR / name, report=report):
            if report.rows % 100_000 == 0:
                print(f"{name}: {report.rows:,} records validated", flush=True)
            assert len(chunk) <= 10_000
        assert report.complete and report.rows == expected["rows"], report.to_dict()
        assert report.labels == expected["labels"], report.to_dict()
        result = report.to_dict()
        result["elapsed_seconds"] = round(time.perf_counter() - started, 2)
        results["files"].append(result)
        print(f"PASS {name}: {report.rows:,} records; {result['elapsed_seconds']} seconds", flush=True)
    destination = PROJECT_ROOT / "docs" / "phase1-awid-validation.json"
    destination.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
