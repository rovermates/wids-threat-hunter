import csv
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import pandas as pd

from backend.core.awid_loader import (
    AwidValidationError, IngestionReport, inspect_awid, iter_awid_chunks,
)
from backend.core.awid_schema import COLUMNS


def packet(timestamp="1393661302.645757001", label="normal", ssid="pnet"):
    # Independent one-based positions from the acquired compatibility contract.
    values = ["?"] * 155
    for position, value in {
        4: timestamp, 61: "-47", 66: "0", 67: "8", 77: "ff:ff:ff:ff:ff:ff",
        79: "b0:48:7a:e2:62:23", 80: "b0:48:7a:e2:62:23", 82: "2851",
        119: ssid, 150: "1", 153: "2", 155: label,
    }.items():
        values[position - 1] = value
    return values


class AwidLoaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "AWID-CLS-R-Trn.csv"

    def write(self, rows, path=None):
        path = path or self.path
        with path.open("w", encoding="utf-8", newline="") as stream:
            csv.writer(stream).writerows(rows)
        return path

    def test_preserves_first_packet_raw_columns_precision_and_types(self):
        self.write([packet()])
        chunk = next(iter_awid_chunks(self.path))
        self.assertEqual(list(chunk.columns[:155]), list(COLUMNS))
        self.assertEqual(chunk.index.tolist(), [1])
        self.assertEqual(chunk.iloc[0]["frame.time_epoch"], "1393661302.645757001")
        self.assertEqual(chunk.iloc[0]["timestamp_ns"], 1393661302645757001)
        self.assertEqual(chunk.iloc[0]["timestamp_utc"].value, 1393661302645757001)
        self.assertEqual(str(chunk["rssi_dbm"].dtype), "Int16")
        self.assertEqual(chunk.iloc[0]["sequence_number"], 2851)
        self.assertEqual(chunk.iloc[0]["ssid"], "pnet")

    def test_duplicate_field_positions_remain_distinct(self):
        self.write([packet()])
        row = next(iter_awid_chunks(self.path)).iloc[0]
        self.assertEqual(row["wlan.qos.buf_state_indicated"], "1")
        self.assertEqual(row["wlan.qos.buf_state_indicated__2"], "2")

    def test_chunk_boundaries_equal_timestamps_and_report(self):
        self.write([packet(label=label) for label in ("normal", "injection", "normal")])
        report = IngestionReport()
        chunks = list(iter_awid_chunks(self.path, chunk_size=2, report=report))
        self.assertEqual([len(c) for c in chunks], [2, 1])
        self.assertEqual(chunks[1].index.tolist(), [3])
        self.assertEqual(report.labels, {"normal": 2, "injection": 1})
        self.assertTrue(report.complete)
        self.assertEqual(report.max_chunk_rows, 2)

    def test_partial_scan_is_not_complete(self):
        self.write([packet(), packet()])
        report = IngestionReport()
        stream = iter_awid_chunks(self.path, chunk_size=1, report=report)
        next(stream)
        stream.close()
        self.assertFalse(report.complete)
        self.assertEqual(report.rows, 1)

    def test_missing_fields_and_literal_ssids(self):
        rows = [packet(ssid=s) for s in ("NA", "null", "", "?", "a,b\"c\nnext")]
        rows[0][60] = "?"
        rows[1][81] = ""
        self.write(rows)
        chunk = next(iter_awid_chunks(self.path))
        self.assertTrue(pd.isna(chunk.iloc[0]["rssi_dbm"]))
        self.assertTrue(pd.isna(chunk.iloc[1]["sequence_number"]))
        self.assertEqual(chunk["ssid"].iloc[:3].tolist(), ["NA", "null", ""])
        self.assertTrue(pd.isna(chunk.iloc[3]["ssid"]))
        self.assertEqual(chunk.iloc[4]["ssid"], 'a,b"c\nnext')

    def test_both_variants_share_capture_identity_without_collapsing_labels(self):
        atk = self.write([packet(label="evil_twin")], Path(self.temp.name) / "AWID-ATK-R-Trn.csv")
        cls = self.write([packet(label="impersonation")])
        a, c = inspect_awid(atk), inspect_awid(cls)
        self.assertEqual(a.dataset_id, c.dataset_id)
        self.assertEqual(a.labels, {"evil_twin": 1})
        self.assertEqual(c.labels, {"impersonation": 1})

    def test_variant_required_for_generic_filename_and_conflicts_rejected(self):
        generic = self.write([packet()], Path(self.temp.name) / "1")
        with self.assertRaisesRegex(AwidValidationError, "Specify variant"):
            inspect_awid(generic)
        self.assertEqual(inspect_awid(generic, variant="CLS").rows, 1)
        self.write([packet()])
        with self.assertRaisesRegex(AwidValidationError, "conflicts"):
            inspect_awid(self.path, variant="ATK")

    def test_bad_width_never_padded_or_skipped(self):
        for record in (packet()[:-1], packet() + ["extra"], []):
            with self.subTest(width=len(record)):
                self.write([packet(), record])
                with self.assertRaisesRegex(AwidValidationError, "record 2: expected 155"):
                    inspect_awid(self.path, chunk_size=1)

    def test_header_and_empty_file_rejected(self):
        for rows, message in (([list(COLUMNS)], "found a header"), ([], "empty CSV")):
            with self.subTest(message=message):
                self.write(rows)
                with self.assertRaisesRegex(AwidValidationError, message):
                    inspect_awid(self.path)

    def test_wrong_or_missing_labels_rejected(self):
        for label in ("evil_twin", "?", "", "unknown"):
            with self.subTest(label=label):
                self.write([packet(label=label)])
                with self.assertRaisesRegex(AwidValidationError, "label"):
                    inspect_awid(self.path)

    def test_invalid_timestamp_rejected_without_rounding(self):
        for timestamp in ("?", "", "nan", "inf", "-1", "1.0000000001", "9999999999"):
            with self.subTest(timestamp=timestamp):
                self.write([packet(timestamp=timestamp)])
                with self.assertRaisesRegex(AwidValidationError, "frame.time_epoch"):
                    inspect_awid(self.path)

    def test_backwards_timestamps_within_and_between_chunks(self):
        self.write([packet("2"), packet("1.999999999")])
        for size in (1, 10):
            with self.subTest(chunk_size=size):
                with self.assertRaisesRegex(AwidValidationError, "record 2: timestamp goes backwards"):
                    inspect_awid(self.path, chunk_size=size)

    def test_bad_numeric_values(self):
        for position, value in ((61, "nan"), (61, "-129"), (82, "4096"), (66, "x"), (67, "1.5")):
            with self.subTest(position=position, value=value):
                row = packet()
                row[position - 1] = value
                self.write([row])
                with self.assertRaises(AwidValidationError):
                    inspect_awid(self.path)

    def test_invalid_chunk_size(self):
        self.write([packet()])
        for size in (0, -1, True, 1.5):
            with self.subTest(size=size), self.assertRaises(ValueError):
                inspect_awid(self.path, chunk_size=size)

    def test_malformed_quotes_and_encoding(self):
        for content in (b'"unclosed', b'\xff'):
            self.path.write_bytes(content)
            with self.subTest(content=content), self.assertRaisesRegex(AwidValidationError, "invalid CSV/UTF-8"):
                inspect_awid(self.path)

    def test_cli_nonzero_on_invalid_input(self):
        self.write([packet()[:-1]])
        result = subprocess.run(
            [sys.executable, "-m", "backend.ingest_awid", str(self.path)],
            cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("record 1", result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
