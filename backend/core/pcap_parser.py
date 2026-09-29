"""Offline Wi-Fi extraction using tshark's native dissector and bounded chunks."""
import csv
from dataclasses import asdict, dataclass, field
from functools import lru_cache
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Iterator, Optional, Union

import pandas as pd

from backend.config import DEFAULT_CHUNK_SIZE, PROJECT_ROOT
from backend.core.native_stream import NativeLineStream, NativeProcessError

FIELDS = (
    "frame.number", "frame.time_epoch", "wlan.fc.type", "wlan.fc.subtype",
    "wlan.sa", "wlan.da", "wlan.bssid", "wlan.ssid", "wlan.seq",
    "radiotap.dbm_antsignal", "frame.cap_len", "frame.len", "wlan.tag.number",
    "_ws.malformed",
    "wlan.ta", "wlan.ra", "wlan.fc.retry", "wlan.fc.tods", "wlan.fc.fromds",
    "wlan.fc.protected", "wlan.frag", "wlan.qos.tid", "wlan.fixed.beacon",
    "wlan.fixed.timestamp", "wlan.fixed.capabilities.ess",
    "wlan.fixed.capabilities.privacy", "wlan.ds.current_channel",
    "radiotap.channel.freq", "wlan.rsn.akms.type", "wlan.rsn.pcs.type",
    "wlan.fc.pwrmgt", "wlan.fc.frag", "wlan.fc.moredata", "wlan.duration", "wlan.fixed.auth.alg",
)
_MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
           b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}
_NUMERIC = {
    "packet_number": ("frame.number", "Int64", 1, 2**63 - 1),
    "frame_type": ("wlan.fc.type", "Int8", 0, 3),
    "frame_subtype": ("wlan.fc.subtype", "Int8", 0, 15),
    "sequence_number": ("wlan.seq", "Int16", 0, 4095),
    "rssi_dbm": ("radiotap.dbm_antsignal", "Int16", -128, 127),
    "captured_length": ("frame.cap_len", "Int64", 0, 2**32 - 1),
    "original_length": ("frame.len", "Int64", 0, 2**32 - 1),
    "fragment_number": ("wlan.frag", "Int8", 0, 15),
    "qos_tid": ("wlan.qos.tid", "Int8", 0, 15),
    "beacon_interval_tu": ("wlan.fixed.beacon", "Int64", 0, 65535),
    "advertised_channel": ("wlan.ds.current_channel", "Int16", 0, 255),
    "capture_frequency_mhz": ("radiotap.channel.freq", "Int32", 0, 65535),
}


class PcapError(ValueError):
    """Unsupported/invalid capture or failure of native decoding."""


@dataclass
class PcapReport:
    source: str = ""
    tshark: str = ""
    version: str = ""
    wifi_packets: int = 0
    chunks: int = 0
    max_chunk_rows: int = 0
    missing_core: dict = field(default_factory=dict)
    timestamp_decreases: int = 0
    truncated_packets: int = 0
    malformed_packets: int = 0
    first_timestamp_ns: Optional[int] = None
    last_timestamp_ns: Optional[int] = None
    warnings: str = ""
    complete: bool = False

    def to_dict(self):
        return asdict(self)


def resolve_tshark(explicit=None) -> str:
    """Prefer explicit configuration, then PATH, then project-local portable build."""
    configured = explicit or os.environ.get("TSHARK_PATH")
    if configured:
        candidate = shutil.which(str(configured))
        if candidate:
            return str(Path(candidate).resolve())
        raise PcapError(f"Configured tshark executable is unavailable: {configured}")
    candidates = [shutil.which("tshark"),
                  PROJECT_ROOT / ".tools/WiresharkPortable/App/Wireshark/tshark.exe"]
    if os.name == "nt":
        candidates.append(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Wireshark/tshark.exe")
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(Path(candidate).resolve())
    raise PcapError("tshark 4.4+ is required. Install Wireshark/tshark or set TSHARK_PATH "
                    "to its executable. Offline parsing does not require capture drivers.")


@lru_cache(maxsize=8)
def _version(executable):
    try:
        result = subprocess.run(
            [executable, "--version"], stdin=subprocess.DEVNULL, capture_output=True,
            timeout=15, text=True, encoding="utf-8", errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PcapError(f"Cannot start tshark: {exc}") from exc
    match = re.search(r"TShark \(Wireshark\) (\d+)\.(\d+)\.(\d+)", result.stdout)
    if result.returncode or not match or tuple(map(int, match.groups()[:2])) < (4, 4):
        raise PcapError("A working tshark 4.4+ executable is required")
    return ".".join(match.groups())


def _command(executable, path, advertisements_only=False):
    display_filter = 'wlan.fc.type == 0 && (wlan.fc.subtype == 5 || wlan.fc.subtype == 8)' if advertisements_only else 'wlan'
    command = [executable, "-n", "-l", "-r", str(path), "-Y", display_filter, "-T", "fields",
               "-E", "separator=/t", "-E", "quote=d", "-E", "escape=y",
               "-E", "occurrence=a", "-E", "aggregator=,"]
    for name in FIELDS:
        command.extend(["-e", name])
    return command


def _epoch_ns(value):
    if not re.fullmatch(r"[0-9]{1,10}(?:\.[0-9]{1,9})?", value):
        raise PcapError("Invalid/missing capture epoch timestamp")
    seconds, _, fraction = value.partition(".")
    value = int(seconds) * 1_000_000_000 + int(fraction.ljust(9, "0"))
    if value > 2**63 - 1:
        raise PcapError("Capture timestamp exceeds nanosecond range")
    return value


def _frame(records, source):
    raw = pd.DataFrame(records, columns=FIELDS, dtype="string")
    # tshark reports repeated values comma-separated; keep raw values for audit.
    first = {name: raw[name].str.split(",", n=1).str[0] for name in FIELDS}
    for alias, (name, dtype, low, high) in _NUMERIC.items():
        value = first[name].mask(first[name].eq(""), pd.NA)
        invalid = value.notna() & ~value.str.fullmatch(r"-?[0-9]+", na=False)
        number = pd.to_numeric(value, errors="coerce")
        invalid |= value.notna() & (number.isna() | number.lt(low) | number.gt(high))
        if invalid.any():
            raise PcapError(f"Invalid tshark field {name} at output row {int(invalid[invalid].index[0]) + 1}")
        raw[alias] = number.astype(dtype)
    if raw["packet_number"].isna().any():
        raise PcapError("Wi-Fi output lacks packet number")
    for alias, name in (("source_mac", "wlan.sa"), ("destination_mac", "wlan.da"), ("bssid", "wlan.bssid"),
                        ("transmitter_mac", "wlan.ta"), ("receiver_mac", "wlan.ra")):
        raw[alias] = first[name].mask(first[name].eq(""), pd.NA)
    for alias, name in (("retry", "wlan.fc.retry"), ("to_ds", "wlan.fc.tods"),
                        ("from_ds", "wlan.fc.fromds"), ("protected", "wlan.fc.protected"),
                        ("ess_capable", "wlan.fixed.capabilities.ess"),
                        ("privacy_capable", "wlan.fixed.capabilities.privacy")):
        values = first[name].str.lower()
        if not values.isin(["", "0", "1", "true", "false"]).all():
            raise PcapError(f"Invalid boolean field {name}")
        raw[alias] = values.map({"0": False, "1": True, "false": False, "true": True}).astype("boolean")
    # Parse unsigned TSF directly as integers, never through floating point.
    tsf = []
    for value in first["wlan.fixed.timestamp"]:
        if not value:
            tsf.append(pd.NA)
        elif value.isdecimal() and int(value) <= 2**64 - 1:
            tsf.append(int(value))
        else:
            raise PcapError("Invalid advertised TSF timestamp")
    raw["advertised_tsf_us"] = pd.array(tsf, dtype="UInt64")
    raw["beacon_interval_us"] = raw["beacon_interval_tu"] * 1024
    raw["is_beacon"] = raw["frame_type"].eq(0) & raw["frame_subtype"].eq(8)
    raw["is_probe_response"] = raw["frame_type"].eq(0) & raw["frame_subtype"].eq(5)
    ssids = []
    for value, tags in zip(first["wlan.ssid"], raw["wlan.tag.number"]):
        # Wireshark's zero-length FT_BYTES marker differs from absent field output.
        if not value or value == "<MISSING>":
            ssids.append("" if "0" in tags.split(",") else pd.NA)
        else:
            try:
                ssids.append(bytes.fromhex(value).decode("utf-8", errors="backslashreplace"))
            except ValueError as exc:
                raise PcapError("Expected hexadecimal wlan.ssid output from tshark 4.4+") from exc
    raw["ssid"] = pd.array(ssids, dtype="string")
    timestamps = [_epoch_ns(v) for v in first["frame.time_epoch"]]
    raw["timestamp_ns"] = pd.array(timestamps, dtype="Int64")
    raw["timestamp_utc"] = pd.to_datetime(timestamps, unit="ns", utc=True)
    raw["label"] = pd.Series(pd.NA, index=raw.index, dtype="string")
    raw["truncated"] = raw["captured_length"].lt(raw["original_length"]).fillna(False)
    raw["malformed"] = raw["_ws.malformed"].ne("") | raw['frame_type'].isna()
    raw.index = pd.Index(raw["packet_number"].to_numpy(dtype="int64"), name="source_packet")
    raw.attrs.update(source=str(source), schema_id="pcap-tshark-fields-v2",
                     repeated_field_policy="first occurrence; raw fields retain all occurrences")
    return raw


def iter_pcap_chunks(path: Union[str, Path], *, chunk_size=DEFAULT_CHUNK_SIZE,
                     tshark_path=None, idle_timeout=120.0,
                     report: Optional[PcapReport] = None, advertisements_only=False) -> Iterator[pd.DataFrame]:
    """Read one saved PCAP/PCAPNG. Close the generator when stopping early.

    Chunks are provisional until complete=True. Input order is preserved; a
    nonzero timestamp_decreases count requires attention before temporal ML.
    idle_timeout bounds waits for native output, not time spent by the consumer.
    """
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer")
    if not math.isfinite(idle_timeout) or idle_timeout <= 0:
        raise ValueError("idle_timeout must be finite and positive")
    source = Path(path).resolve()
    if not source.is_file():
        raise PcapError(f"Capture file does not exist: {source}")
    with source.open("rb") as stream:
        if stream.read(4) not in _MAGICS:
            raise PcapError(f"{source.name}: expected PCAP or PCAPNG file signature")
    state = report if report is not None else PcapReport()
    if state.source or state.complete:
        raise ValueError("Use a fresh PcapReport for each capture")
    executable = resolve_tshark(tshark_path)
    state.source, state.tshark, state.version = str(source), executable, _version(executable)
    previous_time = None
    previous_packet = 0

    def consume(records):
        nonlocal previous_time, previous_packet
        frame = _frame(records, source)
        numbers = frame["packet_number"]
        if int(numbers.iloc[0]) <= previous_packet or numbers.diff().le(0).any():
            raise PcapError("Decoder returned repeated or backwards packet numbers")
        previous_packet = int(numbers.iloc[-1])
        times = frame["timestamp_ns"]
        state.timestamp_decreases += int(times.diff().lt(0).sum())
        if previous_time is not None and int(times.iloc[0]) < previous_time:
            state.timestamp_decreases += 1
        previous_time = int(times.iloc[-1])
        if state.first_timestamp_ns is None:
            state.first_timestamp_ns = int(times.iloc[0])
        state.last_timestamp_ns = previous_time
        state.wifi_packets += len(frame)
        state.chunks += 1
        state.max_chunk_rows = max(state.max_chunk_rows, len(frame))
        state.truncated_packets += int(frame["truncated"].sum())
        state.malformed_packets += int(frame["malformed"].sum())
        for name in ("frame_subtype", "source_mac", "destination_mac", "bssid", "ssid", "sequence_number", "rssi_dbm"):
            state.missing_core[name] = state.missing_core.get(name, 0) + int(frame[name].isna().sum())
        return frame

    try:
        with NativeLineStream(_command(executable, source, advertisements_only), idle_timeout=idle_timeout) as native:
            records = []
            for line in native:
                values = next(csv.reader([line], delimiter="\t", strict=True))
                if len(values) != len(FIELDS):
                    raise PcapError(f"Unexpected tshark output: expected {len(FIELDS)} fields, got {len(values)}")
                records.append(values)
                if len(records) == chunk_size:
                    chunk = consume(records)
                    records = []
                    yield chunk
            # NativeLineStream checks the exit code before yielding the final partial batch.
            if records:
                yield consume(records)
            state.warnings = native.stderr_tail[-4096:]
        if not state.wifi_packets:
            raise PcapError("Capture contains no decodable IEEE 802.11 frames")
        state.complete = True
    except (NativeProcessError, csv.Error, OSError) as exc:
        raise PcapError(f"{source.name}: {exc}") from exc


def inspect_pcap(path, **options) -> PcapReport:
    """Fully validate/extract without retaining packet DataFrames."""
    report = PcapReport()
    for _ in iter_pcap_chunks(path, report=report, **options):
        pass
    return report
