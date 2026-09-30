"""Tabular dataset importer and parser supporting CSV, JSON, and JSONL formats."""

import io
import csv
import json
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple, Iterator
from securelink.sources.base import BaseTelemetrySource
from securelink.core.types import TelemetryData


class DatasetError(Exception):
    """Raised when dataset formatting, parsing, or validation fails."""
    def __init__(self, message: str, row_number: Optional[int] = None):
        super().__init__(message)
        self.message = message
        self.row_number = row_number

    def __str__(self) -> str:
        if self.row_number is not None:
            return f"Row {self.row_number}: {self.message}"
        return self.message


@dataclass
class ParsedDataset:
    format: str
    columns: List[str]
    rows: List[Dict[str, Any]]
    warnings: List[str]


def detect_format(text: str) -> str:
    """Auto-detect format: json, jsonl, or csv."""
    stripped = text.strip()
    if not stripped:
        raise DatasetError("Empty dataset")
    if stripped.startswith("["):
        return "json"
    if stripped.startswith("{"):
        return "jsonl"
    return "csv"


def _detect_csv_delimiter(first_line: str) -> str:
    """Detect delimiter among standard tactical delimiters: comma, semicolon, tab, pipe."""
    counts = {d: first_line.count(d) for d in [",", ";", "\t", "|"]}
    best = max(counts, key=counts.get)
    return best if counts[best] > 0 else ","


def parse_dataset(
    text: str,
    fmt: str = "auto",
    columns: Optional[List[str]] = None,
    max_bytes: int = 5242880,
    max_rows: int = 5000,
    max_columns: int = 64,
) -> ParsedDataset:
    """Parse raw text dataset (.csv, .json, .jsonl) into validated canonical rows."""
    raw_bytes = text.encode("utf-8")
    if len(raw_bytes) > max_bytes:
        raise DatasetError(f"Dataset size ({len(raw_bytes)} bytes) exceeds maximum limit of {max_bytes} bytes")

    # Strip UTF-8 BOM
    clean_text = text.lstrip("\ufeff")
    if not clean_text.strip():
        raise DatasetError("Empty dataset")

    resolved_fmt = detect_format(clean_text) if fmt == "auto" else fmt.lower()
    warnings: List[str] = []
    rows: List[Dict[str, Any]] = []
    all_columns: List[str] = []

    if resolved_fmt == "csv":
        lines = clean_text.splitlines()
        if not lines:
            raise DatasetError("Empty dataset")
        delimiter = _detect_csv_delimiter(lines[0])
        reader = csv.reader(io.StringIO(clean_text), delimiter=delimiter)
        try:
            raw_headers = next(reader, None)
        except Exception as e:
            raise DatasetError(f"Failed to read CSV header: {e}") from e

        if not raw_headers:
            raise DatasetError("CSV header row is required")

        headers = [h.strip() for h in raw_headers]
        seen_headers = set()
        for idx, h in enumerate(headers):
            if not h:
                raise DatasetError(f"Header column {idx + 1} is empty", row_number=1)
            if h in seen_headers:
                raise DatasetError(f"Duplicate column header '{h}'", row_number=1)
            seen_headers.add(h)

        all_columns = headers

        for row_idx, raw_row in enumerate(reader, start=2):
            if not raw_row:
                continue
            if len(raw_row) > len(headers):
                raise DatasetError(
                    f"Expected {len(headers)} columns, got {len(raw_row)}",
                    row_number=row_idx,
                )
            if len(raw_row) < len(headers):
                missing = len(headers) - len(raw_row)
                padded_row = raw_row + [""] * missing
                warnings.append(f"Row {row_idx}: padded {missing} missing column(s)")
            else:
                padded_row = raw_row

            rows.append({h: str(v) for h, v in zip(headers, padded_row)})

    elif resolved_fmt == "json":
        try:
            data = json.loads(clean_text)
        except Exception as e:
            raise DatasetError(f"Invalid JSON: {e}") from e

        if not isinstance(data, list) or not data:
            raise DatasetError("JSON dataset must be a non-empty array of objects")

        col_dict: Dict[str, None] = {}
        for idx, item in enumerate(data, start=1):
            if not isinstance(item, dict):
                raise DatasetError("JSON array elements must be objects", row_number=idx)
            for k in item.keys():
                col_dict[str(k)] = None
            rows.append(item)

        all_columns = list(col_dict.keys())

    elif resolved_fmt == "jsonl":
        lines = clean_text.splitlines()
        col_dict: Dict[str, None] = {}
        for line_num, line in enumerate(lines, start=1):
            s_line = line.strip()
            if not s_line:
                continue
            try:
                item = json.loads(s_line)
            except Exception as e:
                raise DatasetError(f"Invalid JSON on line {line_num}: {e}", row_number=line_num) from e

            if not isinstance(item, dict):
                raise DatasetError("Each line must be a JSON object", row_number=line_num)

            for k in item.keys():
                col_dict[str(k)] = None
            rows.append(item)

        if not rows:
            raise DatasetError("Empty dataset")

        all_columns = list(col_dict.keys())
    else:
        raise DatasetError(f"Unsupported dataset format '{resolved_fmt}'")

    if not rows:
        raise DatasetError("Dataset contains no data rows")

    # Column filtering if requested
    if columns is not None:
        for req_col in columns:
            if req_col not in all_columns:
                raise DatasetError(f"Requested column '{req_col}' not found in dataset")
        selected_columns = columns
        filtered_rows = []
        for r in rows:
            filtered_rows.append({col: r.get(col) for col in selected_columns})
        rows = filtered_rows
    else:
        selected_columns = all_columns

    if len(rows) > max_rows:
        raise DatasetError(f"Row count ({len(rows)}) exceeds limit of {max_rows} rows")
    if len(selected_columns) > max_columns:
        raise DatasetError(f"Column count ({len(selected_columns)}) exceeds limit of {max_columns} columns")

    return ParsedDataset(
        format=resolved_fmt,
        columns=selected_columns,
        rows=rows,
        warnings=warnings,
    )


def row_to_payload(row: Dict[str, Any]) -> bytes:
    """Serialize a dataset row into canonical UTF-8 JSON bytes."""
    return json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def validate_payload_sizes(rows: List[Dict[str, Any]], max_payload_bytes: int = 1024) -> None:
    """Verify all rows stay within max_payload_bytes limit, raising error on violations."""
    offending_rows = []
    for idx, row in enumerate(rows, start=1):
        payload = row_to_payload(row)
        if len(payload) > max_payload_bytes:
            offending_rows.append(idx)

    if offending_rows:
        first_five = ", ".join(str(r) for r in offending_rows[:5])
        raise DatasetError(
            f"Payload exceeds {max_payload_bytes} bytes limit in {len(offending_rows)} rows (first offenders: rows {first_five})"
        )


class TabularSource(BaseTelemetrySource):
    """Source that streams pre-parsed tabular dataset rows with simulated timestamps."""

    def __init__(
        self,
        rows: List[Dict[str, Any]],
        rate_pps: int = 100,
        t0: float = 1700000000.0,
        sender_id: int = 1,
    ):
        self.rows = rows
        self.rate_pps = max(1, rate_pps)
        self.t0 = t0
        self.sender_id = sender_id

    def stream_payloads(self) -> Iterator[Tuple[float, bytes, int]]:
        """Yield (timestamp, payload_bytes, row_index) with simulated arrival clocking."""
        interval = 1.0 / self.rate_pps
        for i, row in enumerate(self.rows):
            ts = self.t0 + (i * interval)
            payload = row_to_payload(row)
            yield ts, payload, i

    def generate_packet(self, seq: int) -> TelemetryData:
        """Fallback for BaseTelemetrySource contract."""
        idx = (seq - 1) % len(self.rows) if self.rows else 0
        r = self.rows[idx] if self.rows else {}
        return TelemetryData(
            seq=seq,
            sender_id=self.sender_id,
            timestamp=self.t0 + (seq / self.rate_pps),
            lat=float(r.get("lat") or 0.0),
            lon=float(r.get("lon") or 0.0),
            alt=float(r.get("alt") or 0.0),
            speed=float(r.get("speed") or 0.0),
            heading=float(r.get("heading") or 0.0),
            battery=float(r.get("battery") or 100.0),
        )

    def generate_stream(self, count: int) -> Iterator[TelemetryData]:
        """Stream count telemetry packets."""
        for seq in range(1, count + 1):
            yield self.generate_packet(seq)
