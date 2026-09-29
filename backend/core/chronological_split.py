"""Ordered holdout splits with strict timestamp separation and no shuffling."""
from bisect import bisect_left
from math import isfinite
from numbers import Integral, Real

from backend.core.feature_builder import TemporalFeatureBuilder


def _timestamp(value):
    if isinstance(value, bool) or not isinstance(value, Integral) or not 0 <= value <= 2**63 - 1:
        raise ValueError("timestamp_ns must contain nonnegative Int64 integers, never floats or nulls")
    return int(value)


def _times(frame, previous=None):
    if "timestamp_ns" not in frame.columns:
        raise ValueError("Missing timestamp_ns column")
    values = []
    for value in frame["timestamp_ns"]:
        value = _timestamp(value)
        if previous is not None and value < previous:
            raise ValueError("Chronological splits require nondecreasing timestamps; input is not sorted")
        values.append(value)
        previous = value
    return values


def chronological_split(frame, *, train_fraction=0.70, validation_fraction=0.15):
    """Return train/validation/test copies using positional chronological slicing.

    Nominal row-count boundaries move left to the start of their timestamp
    group. Ties belong entirely to the later partition. Fail if any partition
    would be empty. Fractions are targets, not exact counts or time durations.
    Split raw ingestion rows before feature extraction for isolated evaluation.
    """
    for value in (train_fraction, validation_fraction):
        if isinstance(value, bool) or not isinstance(value, Real) or not isfinite(value) or not 0 < value < 1:
            raise ValueError("Split fractions must be finite numbers strictly between 0 and 1")
    if train_fraction + validation_fraction >= 1:
        raise ValueError("Split fractions must leave a positive test fraction")
    times = _times(frame)
    size = len(times)
    first = int(size * train_fraction)
    second = int(size * (train_fraction + validation_fraction))
    if not 0 < first < second < size:
        raise ValueError("Not enough rows for three nonempty partitions")
    first = bisect_left(times, times[first])
    second = bisect_left(times, times[second])
    if not 0 < first < second < size:
        raise ValueError("Timestamp ties leave an empty partition; choose different fractions or more data")
    return {name: frame.iloc[start:stop].copy() for name, start, stop in
            (("train", 0, first), ("validation", first, second), ("test", second, size))}


def split_temporal_features(frame, *, train_fraction=0.70,
                            validation_fraction=0.15, rssi_window=100):
    """Split raw rows first, then build features with independent state."""
    partitions = chronological_split(frame, train_fraction=train_fraction,
                                     validation_fraction=validation_fraction)
    return {name: TemporalFeatureBuilder(rssi_window).transform(part)
            for name, part in partitions.items()}


def iter_chronological_chunks(chunks, *, validation_start_ns, test_start_ns,
                              temporal_features=False, rssi_window=100):
    """Yield (partition_name, DataFrame) with bounded per-chunk slicing.

    Train: t < validation_start; validation: validation_start <= t < test_start;
    test: t >= test_start. Require nonempty partitions on full exhaustion.
    When requested, features are built from raw input with fresh state per split.
    Consumers must discard partial work on failure and close on early exit.
    """
    try:
        validation_start_ns = _timestamp(validation_start_ns)
        test_start_ns = _timestamp(test_start_ns)
        if validation_start_ns >= test_start_ns:
            raise ValueError("validation_start_ns must be earlier than test_start_ns")
        counts = dict.fromkeys(("train", "validation", "test"), 0)
        previous = None
        active_name = None
        builder = None
        for frame in chunks:
            times = _times(frame, previous)
            if not times:
                continue
            previous = times[-1]
            first = bisect_left(times, validation_start_ns)
            second = bisect_left(times, test_start_ns)
            for name, start, stop in (("train", 0, first),
                                      ("validation", first, second),
                                      ("test", second, len(times))):
                if start == stop:
                    continue
                part = frame.iloc[start:stop].copy()
                if temporal_features:
                    if name != active_name:
                        builder = TemporalFeatureBuilder(rssi_window)
                        active_name = name
                    part = builder.transform(part)
                counts[name] += len(part)
                yield name, part
        empty = [name for name, count in counts.items() if not count]
        if empty:
            raise ValueError(f"Empty chronological partitions: {', '.join(empty)}")
    finally:
        close = getattr(chunks, "close", None)
        if close is not None:
            close()
