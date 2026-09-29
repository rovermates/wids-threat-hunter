"""SQLite snapshots: readers only see fully processed captures."""
from contextlib import contextmanager
import json
import math
import sqlite3


class AnalysisChanged(ValueError):
    pass


SCHEMA = """
CREATE TABLE IF NOT EXISTS analysis (singleton INTEGER PRIMARY KEY CHECK(singleton=1), data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY, timestamp_ns INTEGER NOT NULL,
    bssid TEXT, source_mac TEXT, destination_mac TEXT,
    attack_type TEXT NOT NULL, severity TEXT NOT NULL,
    prediction INTEGER NOT NULL, rssi_variance REAL, data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS packets_prediction ON packets(prediction, bssid);
CREATE INDEX IF NOT EXISTS packets_filters ON packets(attack_type, severity);
CREATE TABLE IF NOT EXISTS threats (bssid TEXT PRIMARY KEY, data TEXT NOT NULL);
"""


class DashboardStore:
    def __init__(self, path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(SCHEMA)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def current(db, expected=None):
        row = db.execute("SELECT data FROM analysis WHERE singleton=1").fetchone()
        result = json.loads(row[0]) if row else None
        if expected and (not result or result["id"] != expected):
            raise AnalysisChanged("The capture changed. Refresh the dashboard and try again.")
        return result

    @contextmanager
    def snapshot(self, expected=None):
        with self.connect() as db:
            db.execute("BEGIN")
            capture = self.current(db, expected)
            yield db, capture

    def capture(self):
        with self.snapshot() as (_, capture):
            return capture

    @staticmethod
    def filters(mac="", attack_type="", severity=""):
        clauses, values = [], []
        if mac:
            # instr is literal substring matching, unlike wildcard-sensitive LIKE.
            clauses.append("(instr(lower(coalesce(bssid,'')),?)>0 OR instr(lower(coalesce(source_mac,'')),?)>0 OR instr(lower(coalesce(destination_mac,'')),?)>0)")
            values.extend([mac.lower()] * 3)
        if attack_type:
            clauses.append("attack_type=?")
            values.append(attack_type)
        if severity:
            clauses.append("severity=?")
            values.append(severity)
        return (" WHERE " + " AND ".join(clauses) if clauses else ""), values

    def packets(self, *, page=1, page_size=10, expected=None, **filters):
        where, values = self.filters(**filters)
        with self.snapshot(expected) as (db, capture):
            total = db.execute("SELECT COUNT(*) FROM packets" + where, values).fetchone()[0]
            rows = db.execute("SELECT data FROM packets" + where + " ORDER BY id LIMIT ? OFFSET ?",
                              [*values, page_size, (page - 1) * page_size])
            return {"analysis_id": capture["id"] if capture else None, "total": total,
                    "page": page, "page_size": page_size, "pages": math.ceil(total / page_size),
                    "items": [json.loads(row[0]) for row in rows]}

    def threats(self, expected=None, limit=None):
        with self.snapshot(expected) as (db, capture):
            rows = [json.loads(row[0]) for row in db.execute("SELECT data FROM threats ORDER BY bssid")]
            rows.sort(key=lambda row: (row["severity"] == "high", row["last_seen"], row["packets"]), reverse=True)
            return {"analysis_id": capture["id"] if capture else None, "total": len(rows), "items": rows[:limit] if limit else rows}

    def traffic(self, expected=None, max_points=120):
        with self.snapshot(expected) as (db, capture):
            if not capture:
                return {"analysis_id": None, "bin_seconds": 1, "items": []}
            start = int(capture["first_timestamp_ns"]) // 1_000_000_000
            end = int(capture["last_timestamp_ns"]) // 1_000_000_000
            width = max(1, math.ceil((end - start + 1) / max_points))
            rows = db.execute("""SELECT ((timestamp_ns / 1000000000 - ?) / ?) AS bucket,
                count(*) AS packets, avg(rssi_variance) AS variance, sum(prediction) AS detections
                FROM packets GROUP BY bucket ORDER BY bucket""", (start, width))
            buckets = {row["bucket"]: dict(row) for row in rows}
            items = []
            for bucket in range((end - start) // width + 1):
                row = buckets.get(bucket, {})
                seconds = min(width, end - (start + bucket * width) + 1)
                items.append({"timestamp": (start + bucket * width) * 1000,
                              "rssi_variance": row.get("variance"),
                              "frame_rate": row.get("packets", 0) / seconds,
                              "detections": row.get("detections", 0)})
            return {"analysis_id": capture["id"], "bin_seconds": width, "items": items}
