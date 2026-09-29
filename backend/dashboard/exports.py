"""Write bounded-memory exports from one committed SQLite snapshot."""
import csv
import json
from pathlib import Path
import tempfile

from backend.dashboard.rules import csv_cell
from backend.dashboard.store import AnalysisChanged


FIELDS = ["id", "timestamp", "source_mac", "destination_mac", "bssid", "ssid", "rssi_dbm",
          "attack_type", "evaluated", "ap_advertising_evidence", "severity", "positive_vote_fraction", "detection_score", "ground_truth", "evasion_tags"]


def create_export(store, directory, *, format, expected, **filters):
    where, values = store.filters(**filters)
    path = None
    try:
        with store.snapshot(expected) as (db, capture):
            if capture is None:
                raise AnalysisChanged("Analyze a capture before exporting results.")
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="", suffix="." + format,
                                             prefix="export-", dir=directory, delete=False) as stream:
                path = Path(stream.name)
                rows = db.execute("SELECT data FROM packets" + where + " ORDER BY id", values)
                if format == "json":
                    stream.write('{"analysis":' + json.dumps(capture) + ',"packets":[')
                    separator = ""
                    for row in rows:
                        stream.write(separator + row[0])
                        separator = ","
                    stream.write("]}")
                else:
                    writer = csv.writer(stream)
                    writer.writerow(FIELDS)
                    for row in rows:
                        packet = json.loads(row[0])
                        packet["evasion_tags"] = "; ".join(packet["evasion_tags"])
                        writer.writerow([csv_cell(packet.get(field)) if isinstance(packet.get(field), str)
                                         else packet.get(field) for field in FIELDS])
        return path
    except Exception:
        if path:
            path.unlink(missing_ok=True)
        raise
