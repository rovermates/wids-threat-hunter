import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pandas as pd
from pandas.testing import assert_frame_equal

from backend.core.feature_builder import TemporalFeatureBuilder, iter_temporal_chunks
from backend.extract_features import export_features


def frames(rows):
    data = pd.DataFrame(rows, columns=["timestamp_ns", "bssid", "ssid", "rssi_dbm",
                                      "sequence_number", "frame_type", "frame_subtype"])
    for name in ("timestamp_ns", "rssi_dbm", "sequence_number", "frame_type", "frame_subtype"):
        data[name] = pd.array(data[name], dtype="Int64")
    return data


class TemporalFeatureTests(unittest.TestCase):
    def test_rssi_frame_window_missing_and_groups(self):
        data = frames([(0, "a", "x", -50, 1, 0, 8),
                       (1, "b", "x", -90, 5, 0, 8),
                       (2, "a", "x", -40, 2, 0, 8),
                       (3, "a", "x", None, 3, 0, 8),
                       (4, "a", "x", -30, 4, 0, 8)])
        result = TemporalFeatureBuilder(3).transform(data)
        self.assertTrue(pd.isna(result.rssi_std_db.iloc[0]))
        self.assertEqual(result.rssi_std_db.iloc[2], 5)
        self.assertEqual(result.rssi_delta_db.iloc[4], 10)
        self.assertEqual(result.rssi_window_count.iloc[4], 2)
        self.assertEqual(result.rssi_std_db.iloc[4], 5)

    def test_sequence_wrap_duplicate_reverse_and_missing(self):
        data = frames([(i, "a", "x", -40, seq, 0, 8)
                       for i, seq in enumerate([4095, 0, 0, 4, 2, None, 8])])
        result = TemporalFeatureBuilder().transform(data)
        self.assertEqual(result.sequence_delta.iloc[1], -4095)
        self.assertEqual(result.sequence_gap.iloc[1:5].tolist(), [1, 0, 4, 4094])
        self.assertTrue(result.sequence_gap.iloc[5:].isna().all())

    def test_beacons_only_and_exact_large_timestamp(self):
        base = 1_700_000_000_000_000_001
        data = frames([(base, "a", "x", -40, 1, 0, 8),
                       (base + 1, "a", "x", -40, 2, 0, 5),
                       (base + 2, "b", "x", -40, 1, 0, 8),
                       (base + 103, "a", "x", -40, 3, 0, 8)])
        result = TemporalFeatureBuilder().transform(data)
        self.assertTrue(result.beacon_interval_delta_ns.iloc[:3].isna().all())
        self.assertEqual(result.beacon_interval_delta_ns.iloc[3], 103)

    def test_churn_boundary_repeats_hidden_and_client_probe(self):
        second = 1_000_000_000
        data = frames([(0, "AA", "x", -40, 1, 0, 8),
                       (second, "aa", "x", -40, 2, 0, 8),
                       (2 * second, "b", "x", -40, 1, 0, 5),
                       (3 * second, "client", "x", -40, 1, 0, 4),
                       (4 * second, "c", "", -40, 1, 0, 8),
                       (60 * second, None, "x", None, None, 1, 0),
                       (61 * second, None, "x", None, None, 1, 0),
                       (62 * second, None, "x", None, None, 1, 0)])
        result = TemporalFeatureBuilder().transform(data)
        self.assertEqual(result.ssid_mac_count_60s.iloc[:4].tolist(), [1, 1, 2, 2])
        self.assertTrue(pd.isna(result.ssid_mac_count_60s.iloc[4]))
        self.assertEqual(result.ssid_mac_count_60s.iloc[5:].tolist(), [2, 1, 0])

    def test_chunk_invariance_causality_and_metadata(self):
        data = frames([(i, "a", "x", -40 + i, i, 0, 8) for i in range(8)])
        data.index = [10, 20, 30, 40, 50, 60, 70, 80]
        data.attrs["source"] = "fixture"
        before = data.copy(deep=True)
        whole = TemporalFeatureBuilder(3).transform(data)
        for size in (1, 2, 5):
            pieces = (data.iloc[i:i + size] for i in range(0, len(data), size))
            assert_frame_equal(whole, pd.concat(iter_temporal_chunks(pieces, rssi_window=3)))
        assert_frame_equal(whole.iloc[:4], TemporalFeatureBuilder(3).transform(data.iloc[:4]))
        assert_frame_equal(data, before)
        self.assertEqual(whole.attrs["source"], "fixture")

    def test_invalid_time_limits_and_missing_fields(self):
        builder = TemporalFeatureBuilder()
        builder.transform(frames([(2, "a", "x", -40, 1, 0, 8)]))
        with self.assertRaisesRegex(ValueError, "nondecreasing"):
            builder.transform(frames([(1, "a", "x", -40, 1, 0, 8)]))
        with self.assertRaisesRegex(ValueError, "Discard"):
            builder.transform(frames([]))
        for value in (0, -1, 1.5, True):
            with self.assertRaises(ValueError):
                TemporalFeatureBuilder(value)
        for limits in ({"max_bssids": 1}, {"max_churn_events": 1}):
            with self.assertRaisesRegex(ValueError, "exceeded"):
                TemporalFeatureBuilder(**limits).transform(frames([
                    (0, "a", "x", -40, 1, 0, 8), (1, "b", "x", -40, 1, 0, 8)]))
        with self.assertRaisesRegex(ValueError, "Missing"):
            TemporalFeatureBuilder().transform(pd.DataFrame())

    def test_upstream_closed_on_early_stop(self):
        closed = []
        def source():
            try:
                while True:
                    yield frames([(0, "a", "x", -40, 1, 0, 8)])
            finally:
                closed.append(True)
        output = iter_temporal_chunks(source())
        next(output)
        output.close()
        self.assertEqual(closed, [True])

    def test_awid_export_and_no_overwrite(self):
        source = Path(__file__).resolve().parents[2] / "data/sample_awid.csv"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "features.jsonl"
            result = export_features(source, target, input_format="awid", variant="CLS", chunk_size=7)
            rows = [json.loads(line) for line in target.read_text().splitlines()]
            self.assertEqual(len(rows), 100)
            self.assertTrue(result["input"]["complete"])
            self.assertIn("rssi_std_db", rows[0])
            with self.assertRaises(FileExistsError):
                export_features(source, target, input_format="awid", variant="CLS")

    def test_export_failure_removes_partial_and_closes_source(self):
        closed = []
        def broken(*args, **kwargs):
            try:
                yield frames([(10, "a", "x", -40, 1, 0, 8)])
                yield frames([(9, "a", "x", -40, 2, 0, 8)])
            finally:
                closed.append(True)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "features.jsonl"
            with patch("backend.extract_features.iter_awid_chunks", broken):
                with self.assertRaisesRegex(ValueError, "nondecreasing"):
                    export_features("unused", target, input_format="awid")
            self.assertEqual(list(Path(directory).iterdir()), [])
            self.assertEqual(closed, [True])


if __name__ == "__main__":
    unittest.main()
