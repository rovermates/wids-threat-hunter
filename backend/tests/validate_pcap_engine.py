"""Opt-in native integration check on generated offline packets, not ML data."""
import hashlib
import json
import platform
import time

import pandas as pd

from backend.config import PROJECT_ROOT
from backend.core.pcap_parser import PcapReport, iter_pcap_chunks
from backend.tests.pcap_fixtures import write_pcap


def main():
    folder = PROJECT_ROOT / ".tools" / "pcap-validation"
    folder.mkdir(parents=True, exist_ok=True)
    capture = write_pcap(folder / "scale.pcap", count=100_000)
    report = PcapReport()
    started = time.perf_counter()
    max_frame_bytes = 0
    for chunk in iter_pcap_chunks(capture, chunk_size=4096, report=report):
        assert len(chunk) <= 4096
        assert (chunk["sequence_number"].to_numpy() == ((chunk.index.to_numpy() - 1) % 4096)).all()
        assert chunk["label"].isna().all()
        max_frame_bytes = max(max_frame_bytes, int(chunk.memory_usage(deep=True).sum()))
    assert report.complete and report.wifi_packets == 100_000
    assert report.chunks == 25 and report.timestamp_decreases == 0
    result = {
        "fixture": "Synthetic Radiotap + 802.11 beacon PCAP; not attack/training ground truth",
        "python": platform.python_version(), "pandas": pd.__version__,
        "capture_bytes": capture.stat().st_size,
        "capture_sha256": hashlib.sha256(capture.read_bytes()).hexdigest(),
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "max_dataframe_bytes": max_frame_bytes,
        "memory_note": "Largest yielded DataFrame only, not total Python/tshark peak RAM",
        "report": report.to_dict(),
    }
    (PROJECT_ROOT / "docs/phase1-pcap-validation.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
