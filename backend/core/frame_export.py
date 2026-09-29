"""Bounded, lossless JSON Lines export of offline 802.11 frame attributes."""
import os
from pathlib import Path
import tempfile

from backend.core.pcap_parser import PcapReport, iter_pcap_chunks


def export_pcap_frames(source, destination, **options):
    """Publish a new JSONL file only after full native parsing succeeds.

    JSON null distinguishes missing attributes from empty/hidden SSIDs. Integer
    timestamps remain exact; consumers must not coerce them to float/JS Number.
    Existing destinations are never overwritten, including concurrent writers.
    """
    destination = Path(destination).resolve()
    if destination.exists():
        raise FileExistsError(f"Output already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    report = PcapReport()
    temporary = None
    chunks = iter_pcap_chunks(source, report=report, **options)
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=destination.parent, suffix=".partial",
                                         delete=False) as stream:
            temporary = Path(stream.name)
            for frame in chunks:
                stream.write(frame.to_json(orient="records", lines=True,
                                           date_format="iso", date_unit="ns"))
            stream.flush()
            os.fsync(stream.fileno())
        # A same-filesystem hard link atomically publishes without overwriting.
        os.link(temporary, destination)
    finally:
        chunks.close()
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return report
