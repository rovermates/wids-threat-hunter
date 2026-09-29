import unittest

import pandas as pd
from pandas.testing import assert_frame_equal

from backend.core.chronological_split import (
    chronological_split, iter_chronological_chunks, split_temporal_features,
)
from backend.tests.test_feature_builder import frames


def sample(times):
    return frames([(t, "a", "network", -40 + i % 10, i, 0, 8)
                   for i, t in enumerate(times)])


class ChronologicalSplitTests(unittest.TestCase):
    def test_default_coverage_order_and_preserved_input(self):
        data = sample(range(100))
        data.index = [i // 2 for i in range(100)]  # Labels are not positions.
        data.attrs["dataset_id"] = "fixture"
        original = data.copy(deep=True)
        parts = chronological_split(data)
        self.assertEqual([len(p) for p in parts.values()], [70, 15, 15])
        assert_frame_equal(pd.concat(parts.values()), original)
        assert_frame_equal(data, original)
        for left, right in (("train", "validation"), ("validation", "test")):
            self.assertLess(parts[left].timestamp_ns.max(), parts[right].timestamp_ns.min())
        parts["train"].iloc[0, 0] = 999
        assert_frame_equal(data, original)

    def test_ties_go_to_later_partition(self):
        data = sample([0, 1, 2, 2, 2, 3, 4, 4, 4, 5])
        parts = chronological_split(data, train_fraction=.4, validation_fraction=.4)
        self.assertEqual([p.timestamp_ns.tolist() for p in parts.values()],
                         [[0, 1], [2, 2, 2, 3], [4, 4, 4, 5]])

    def test_bad_inputs_and_empty_partitions(self):
        for data in (sample([]), sample([1, 1, 1, 1]), sample([3, 2, 1]),
                     pd.DataFrame(), pd.DataFrame({"timestamp_ns": [0.0, 1.0, 2.0]}),
                     pd.DataFrame({"timestamp_ns": [0, None, 2]}),
                     pd.DataFrame({"timestamp_ns": [False, 1, 2]})):
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    chronological_split(data)
        for train, validation in ((0, .1), (.9, .1), (float("nan"), .1),
                                  (.7, float("inf")), (True, .1), (.5, -.1)):
            with self.assertRaises(ValueError):
                chronological_split(sample(range(100)), train_fraction=train,
                                    validation_fraction=validation)

    def test_exact_nanoseconds_and_streaming_chunk_invariance(self):
        base = 1_700_000_000_000_000_001
        data = sample([base + i for i in range(20)])
        expected = split_temporal_features(data, train_fraction=.5, validation_fraction=.25)
        for size in (1, 3, 20):
            chunks = (data.iloc[i:i+size] for i in range(0, 20, size))
            groups = {name: [] for name in expected}
            for name, part in iter_chronological_chunks(chunks, validation_start_ns=base+10,
                                                       test_start_ns=base+15, temporal_features=True):
                groups[name].append(part)
            for name in groups:
                assert_frame_equal(pd.concat(groups[name]), expected[name])

    def test_temporal_state_resets_and_future_cannot_change_training(self):
        data = sample(range(100))
        result = split_temporal_features(data)
        for part in result.values():
            self.assertTrue(pd.isna(part.sequence_gap.iloc[0]))
            self.assertTrue(pd.isna(part.beacon_interval_delta_ns.iloc[0]))
            self.assertEqual(part.rssi_window_count.iloc[0], 1)
        altered = data.copy()
        altered.loc[70:, "rssi_dbm"] = -100
        altered.loc[70:, "bssid"] = "future"
        assert_frame_equal(result["train"], split_temporal_features(altered)["train"])

    def test_stream_errors_close_upstream(self):
        closed = []
        def source():
            try:
                yield sample([0, 1, 2])
                yield sample([1, 3, 4])
            finally:
                closed.append(True)
        with self.assertRaisesRegex(ValueError, "nondecreasing"):
            list(iter_chronological_chunks(source(), validation_start_ns=2, test_start_ns=3))
        self.assertEqual(closed, [True])
        with self.assertRaisesRegex(ValueError, "Empty"):
            list(iter_chronological_chunks(iter([sample([0, 1])]), validation_start_ns=2, test_start_ns=3))
        with self.assertRaises(ValueError):
            list(iter_chronological_chunks(iter([]), validation_start_ns=3, test_start_ns=2))

    def test_equal_timestamp_groups_across_chunks(self):
        chunks = iter([sample([0, 1, 2]), sample([2, 2, 3]), sample([3, 4])])
        result = list(iter_chronological_chunks(chunks, validation_start_ns=2, test_start_ns=3))
        collected = {name: [] for name in ("train", "validation", "test")}
        for name, part in result:
            collected[name].extend(part.timestamp_ns.tolist())
        self.assertEqual(collected, {"train": [0, 1], "validation": [2, 2, 2], "test": [3, 3, 4]})


if __name__ == "__main__":
    unittest.main()
