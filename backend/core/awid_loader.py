"""Strict, streaming ingestion of headerless AWID2 CLS and ATK CSVs.

No feature engineering, imputation, sampling or label collapsing occurs here.
All original columns are retained; typed aliases support subsequent phases.
"""
from collections import Counter
import csv
from dataclasses import dataclass, field, asdict
from pathlib import Path
import re
from typing import Iterator, Optional, Union

import pandas as pd

from backend.config import DEFAULT_CHUNK_SIZE
from backend.core.awid_schema import (
    ATK_LABELS, CLS_LABELS, COLUMNS, INTEGER_FIELDS, SCHEMA_ID, STRING_FIELDS,
)

PathLike = Union[str, Path]
_FILENAME = re.compile(r"AWID-(CLS|ATK)-R-(Trn|Tst)(?:\.csv)?", re.IGNORECASE)
_EPOCH = re.compile(r"[0-9]{1,10}(?:\.[0-9]{1,9})?\Z")


class AwidValidationError(ValueError):
    """An input record does not satisfy the selected AWID contract."""


@dataclass
class IngestionReport:
    source: str = ""
    variant: str = ""
    dataset_id: str = ""
    schema_id: str = SCHEMA_ID
    schema_status: str = "public compatibility schema; official confirmation pending"
    rows: int = 0
    chunks: int = 0
    labels: dict = field(default_factory=dict)
    missing_core: dict = field(default_factory=dict)
    first_timestamp_ns: Optional[int] = None
    last_timestamp_ns: Optional[int] = None
    max_chunk_rows: int = 0
    max_chunk_dataframe_bytes: int = 0
    complete: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _error(path: Path, row: int, message: str) -> AwidValidationError:
    return AwidValidationError(f"{path.name}: record {row}: {message}")


def _identity(path: Path, variant: Optional[str]) -> tuple:
    match = _FILENAME.fullmatch(path.name)
    selected = variant.upper() if isinstance(variant, str) else variant
    if selected is None and match:
        selected = match[1].upper()
    if selected not in {"CLS", "ATK"}:
        raise AwidValidationError("Specify variant='CLS' or 'ATK' for an unnamed CSV")
    if match and selected != match[1].upper():
        raise AwidValidationError(f"Variant {selected} conflicts with filename {path.name}")
    # Both label variants identify the same capture, preventing implied independence.
    dataset_id = f"AWID2-R-{match[2].title()}" if match else f"custom:{path.resolve()}"
    return selected, dataset_id


def _timestamp(value: str, path: Path, row: int) -> int:
    if not _EPOCH.fullmatch(value):
        raise _error(path, row, "frame.time_epoch must be nonnegative decimal seconds "
                     "with at most 9 fractional digits; missing timestamps are not usable")
    seconds, _, fraction = value.partition(".")
    ns = int(seconds) * 1_000_000_000 + int(fraction.ljust(9, "0"))
    if ns > 9_223_372_036_854_775_807:
        raise _error(path, row, "frame.time_epoch exceeds the nanosecond timestamp range")
    return ns


def _normalize(records: list, start: int, path: Path, variant: str,
               dataset_id: str) -> pd.DataFrame:
    # Disable broad NA inference: SSIDs such as 'NA', 'null', and '' are data.
    frame = pd.DataFrame(records, columns=COLUMNS, dtype="string")
    frame.index = pd.RangeIndex(start, start + len(frame), name="source_row")
    frame = frame.mask(frame.eq("?"), pd.NA)
    allowed = CLS_LABELS if variant == "CLS" else ATK_LABELS
    bad_label = ~frame["class"].isin(allowed)
    if bad_label.any():
        row = int(bad_label[bad_label].index[0])
        raise _error(path, row, f"missing or unknown {variant} label {frame.at[row, 'class']!r}")

    for alias, (source, low, high, dtype) in INTEGER_FIELDS.items():
        values = frame[source].mask(frame[source].eq(""), pd.NA)
        invalid = values.notna() & ~values.str.fullmatch(r"[+-]?[0-9]+", na=False)
        if invalid.any():
            row = int(invalid[invalid].index[0])
            raise _error(path, row, f"{source} must be an integer or missing")
        numeric = pd.to_numeric(values, errors="coerce")
        invalid = values.notna() & (numeric.isna() | (numeric < low) | (numeric > high))
        if invalid.any():
            row = int(invalid[invalid].index[0])
            raise _error(path, row, f"{source} is outside [{low}, {high}]")
        frame[alias] = numeric.astype(dtype)
    for alias, source in STRING_FIELDS.items():
        frame[alias] = frame[source]
    timestamps = [_timestamp(record[3], path, start + offset)
                  for offset, record in enumerate(records)]
    frame["timestamp_ns"] = pd.array(timestamps, dtype="Int64")
    frame["timestamp_utc"] = pd.to_datetime(timestamps, unit="ns", utc=True)
    frame.attrs.update(source=str(path.resolve()), variant=variant,
                       dataset_id=dataset_id, schema_id=SCHEMA_ID)
    return frame


def iter_awid_chunks(path: PathLike, *, variant: Optional[str] = None,
                     chunk_size: int = DEFAULT_CHUNK_SIZE,
                     report: Optional[IngestionReport] = None) -> Iterator[pd.DataFrame]:
    """Yield validated, chronologically ordered chunks from one label variant.

    `source_row` is a one-based CSV record index, not a physical line number.
    A report is complete only after exhaustion. Earlier yielded chunks do not
    certify the rest of a file. Explicitly close the generator if stopping early.
    """
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer")
    path = Path(path)
    selected, dataset_id = _identity(path, variant)
    state = report if report is not None else IngestionReport()
    if state.source or state.rows or state.complete:
        raise ValueError("Use a fresh IngestionReport for each scan")
    state.source, state.variant, state.dataset_id = str(path.resolve()), selected, dataset_id
    previous = None
    total = 0

    def consume(records: list) -> pd.DataFrame:
        nonlocal previous
        start = state.rows + 1
        frame = _normalize(records, start, path, selected, dataset_id)
        times = frame["timestamp_ns"]
        if previous is not None and int(times.iloc[0]) < previous:
            raise _error(path, start, "timestamp goes backwards across chunks; input is not chronological")
        backwards = times.diff().lt(0).fillna(False)
        if backwards.any():
            row = int(backwards[backwards].index[0])
            raise _error(path, row, "timestamp goes backwards; input is not chronological")
        previous = int(times.iloc[-1])
        if state.first_timestamp_ns is None:
            state.first_timestamp_ns = int(times.iloc[0])
        state.last_timestamp_ns = previous
        state.rows += len(frame)
        state.chunks += 1
        state.max_chunk_rows = max(state.max_chunk_rows, len(frame))
        state.max_chunk_dataframe_bytes = max(
            state.max_chunk_dataframe_bytes, int(frame.memory_usage(deep=True).sum()))
        for key, count in Counter(frame["label"]).items():
            state.labels[key] = state.labels.get(key, 0) + count
        for alias in (*INTEGER_FIELDS, *STRING_FIELDS):
            state.missing_core[alias] = state.missing_core.get(alias, 0) + int(frame[alias].isna().sum())
        return frame

    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle, strict=True)
            batch = []
            for total, record in enumerate(reader, 1):
                if len(record) != len(COLUMNS):
                    raise _error(path, total, f"expected 155 fields, found {len(record)}")
                if total == 1 and record[3] == "frame.time_epoch":
                    raise _error(path, total, "expected headerless AWID CSV, found a header")
                batch.append(record)
                if len(batch) == chunk_size:
                    chunk = consume(batch)
                    batch = []
                    yield chunk
            if batch:
                yield consume(batch)
    except (csv.Error, UnicodeError) as exc:
        raise _error(path, total + 1, f"invalid CSV/UTF-8: {exc}") from exc
    if total == 0:
        raise _error(path, 1, "empty CSV")
    state.complete = True


def inspect_awid(path: PathLike, *, variant: Optional[str] = None,
                 chunk_size: int = DEFAULT_CHUNK_SIZE) -> IngestionReport:
    """Validate a complete file without retaining its DataFrames."""
    report = IngestionReport()
    for _ in iter_awid_chunks(path, variant=variant, chunk_size=chunk_size, report=report):
        pass
    return report
