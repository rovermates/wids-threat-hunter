"""Causal temporal features shared by the AWID and PCAP ingestion paths."""
from collections import Counter, deque
from numbers import Integral
from math import sqrt

import pandas as pd


FEATURE_DTYPES = {
    "rssi_window_count": "Int64", "rssi_std_db": "Float64",
    "rssi_delta_db": "Float64", "sequence_delta": "Int64",
    "sequence_gap": "Int64", "beacon_interval_delta_ns": "Int64",
    "ssid_mac_count_60s": "Int64",
}
REQUIRED = ("timestamp_ns", "bssid", "ssid", "rssi_dbm", "sequence_number",
            "frame_type", "frame_subtype")


def _value(value):
    return None if pd.isna(value) else value


class _RssiWindow:
    """Exact integer moments with constant-time insertion and expiration."""
    def __init__(self, size):
        self.size = size
        self.frames = deque()
        self.valid = deque()
        self.total = self.squares = 0

    def append(self, value):
        if len(self.frames) == self.size:
            expired = self.frames.popleft()
            if expired is not None:
                self.valid.popleft()
                self.total -= expired
                self.squares -= expired * expired
        value = None if value is None else int(value)
        self.frames.append(value)
        if value is not None:
            self.valid.append(value)
            self.total += value
            self.squares += value * value

    def summary(self):
        count = len(self.valid)
        if count < 2:
            return count, None, None
        # Integer numerator avoids cancellation for near-constant RSSI windows.
        variance = (count * self.squares - self.total * self.total) / (count * count)
        return count, sqrt(variance), self.valid[-1] - self.valid[0]


class TemporalFeatureBuilder:
    """One instance per ordered capture/dataset; never share across splits.

    RSSI uses the last N BSSID frames, including missing RSSI positions.
    Churn counts AP BSSIDs in beacon/probe responses in (t-60s, t].
    Resource limits fail explicitly rather than silently evicting history.
    """

    def __init__(self, rssi_window=100, *, max_bssids=100_000,
                 max_churn_events=1_000_000):
        for name, value in (("rssi_window", rssi_window),
                            ("max_bssids", max_bssids),
                            ("max_churn_events", max_churn_events)):
            if isinstance(value, bool) or not isinstance(value, Integral) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        self.rssi_window = rssi_window
        self.max_bssids = max_bssids
        self.max_churn_events = max_churn_events
        self._states = {}
        self._events = deque()
        self._ssids = {}
        self._last_time = None
        self._failed = False

    def transform(self, frame):
        """Return a copy with nullable features; retain index, raw fields and attrs.

        After an error discard this builder: its stream may be partly consumed.
        """
        if self._failed:
            raise ValueError("Discard the builder after a failed transform")
        try:
            return self._transform(frame)
        except Exception:
            self._failed = True
            raise

    def _transform(self, frame):
        missing = set(REQUIRED) - set(frame.columns)
        if missing:
            raise ValueError(f"Missing temporal input columns: {sorted(missing)}")
        if set(FEATURE_DTYPES) & set(frame.columns):
            raise ValueError("Input already contains temporal feature columns")
        columns = {name: [] for name in FEATURE_DTYPES}
        for row in frame.loc[:, REQUIRED].itertuples(index=False, name=None):
            timestamp, bssid, ssid, rssi, seq, kind, subtype = map(_value, row)
            if (isinstance(timestamp, bool) or not isinstance(timestamp, Integral)
                    or not 0 <= timestamp <= 2**63 - 1):
                raise ValueError("timestamp_ns must be a nonnegative Int64 integer")
            timestamp = int(timestamp)
            if self._last_time is not None and timestamp < self._last_time:
                raise ValueError("Temporal features require nondecreasing timestamps")
            self._last_time = timestamp
            for name, value, low, high in (("rssi_dbm", rssi, -128, 127),
                                          ("sequence_number", seq, 0, 4095),
                                          ("frame_type", kind, 0, 3),
                                          ("frame_subtype", subtype, 0, 15)):
                if value is not None and (isinstance(value, bool) or
                        not isinstance(value, Integral) or not low <= value <= high):
                    raise ValueError(f"Invalid {name}: {value!r}")
            for name, value in (("bssid", bssid), ("ssid", ssid)):
                if value is not None and not isinstance(value, str):
                    raise ValueError(f"{name} must be a string or missing")
            bssid = bssid.lower() if bssid else None
            if bssid == "ff:ff:ff:ff:ff:ff":
                bssid = None
            # Expire globally, including while no SSID is present in frames.
            while self._events and self._events[0][0] <= timestamp - 60_000_000_000:
                _, old_ssid, old_mac = self._events.popleft()
                counts = self._ssids[old_ssid]
                counts[old_mac] -= 1
                if not counts[old_mac]:
                    del counts[old_mac]
                if not counts:
                    del self._ssids[old_ssid]
            result = dict.fromkeys(FEATURE_DTYPES)
            if bssid is not None:
                if bssid not in self._states:
                    if len(self._states) >= self.max_bssids:
                        raise ValueError("max_bssids exceeded")
                    self._states[bssid] = (_RssiWindow(self.rssi_window), None, None)
                window, previous_seq, previous_beacon = self._states[bssid]
                window.append(rssi)
                count, std, drift = window.summary()
                result["rssi_window_count"] = count
                result["rssi_std_db"] = std
                result["rssi_delta_db"] = drift
                if seq is not None and previous_seq is not None:
                    result["sequence_delta"] = int(seq) - previous_seq
                    result["sequence_gap"] = (int(seq) - previous_seq) % 4096
                if kind == 0 and subtype == 8:
                    if previous_beacon is not None:
                        result["beacon_interval_delta_ns"] = timestamp - previous_beacon
                    previous_beacon = timestamp
                self._states[bssid] = (window, seq, previous_beacon)
                if ssid and kind == 0 and subtype in (5, 8):
                    if len(self._events) >= self.max_churn_events:
                        raise ValueError("max_churn_events exceeded")
                    self._events.append((timestamp, ssid, bssid))
                    self._ssids.setdefault(ssid, Counter())[bssid] += 1
            if ssid:
                result["ssid_mac_count_60s"] = len(self._ssids.get(ssid, {}))
            for name in columns:
                columns[name].append(result[name])
        output = frame.copy()
        for name, dtype in FEATURE_DTYPES.items():
            output[name] = pd.array(columns[name], dtype=dtype)
        output.attrs["temporal_features"] = {
            "version": 1, "rssi_window": self.rssi_window,
            "churn_window_seconds": 60, "churn_mac": "advertising BSSID",
        }
        return output


def iter_temporal_chunks(chunks, *, rssi_window=100, **limits):
    """Enrich an ingestion iterator and close it on failure or early close."""
    builder = TemporalFeatureBuilder(rssi_window, **limits)
    try:
        for frame in chunks:
            yield builder.transform(frame)
    finally:
        close = getattr(chunks, "close", None)
        if close is not None:
            close()
