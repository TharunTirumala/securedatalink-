"""Unit tests for Tabular dataset parser and TabularSource."""

import pytest
from securelink.sources.tabular import (
    parse_dataset,
    row_to_payload,
    validate_payload_sizes,
    TabularSource,
    DatasetError,
)


def test_csv_basic_and_quotes_newlines():
    csv_data = (
        'id,name,comment\n'
        '1,"Alpha UAV","System nominal"\n'
        '2,"Beta ""Bravo"" UAV","Waypoint 1,\nWaypoint 2"\n'
    )
    ds = parse_dataset(csv_data, fmt="csv")
    assert ds.format == "csv"
    assert ds.columns == ["id", "name", "comment"]
    assert len(ds.rows) == 2
    assert ds.rows[0]["name"] == "Alpha UAV"
    assert ds.rows[1]["name"] == 'Beta "Bravo" UAV'
    assert "Waypoint 1,\nWaypoint 2" in ds.rows[1]["comment"]


def test_csv_utf8_bom_stripped():
    csv_with_bom = '\ufefflat,lon,alt\n17.38,78.48,500\n'
    ds = parse_dataset(csv_with_bom)
    assert ds.format == "csv"
    assert ds.columns == ["lat", "lon", "alt"]
    assert len(ds.rows) == 1
    assert ds.rows[0]["lat"] == "17.38"


def test_csv_ragged_rows_short_and_long():
    # Short row padded with warning
    short_csv = "a,b,c\n1,2\n3,4,5\n"
    ds = parse_dataset(short_csv, fmt="csv")
    assert len(ds.rows) == 2
    assert ds.rows[0] == {"a": "1", "b": "2", "c": ""}
    assert len(ds.warnings) == 1
    assert "Row 2: padded 1 missing column" in ds.warnings[0]

    # Long row raises error with row number
    long_csv = "a,b\n1,2,3\n"
    with pytest.raises(DatasetError) as exc:
        parse_dataset(long_csv, fmt="csv")
    assert "Row 2" in str(exc.value)


def test_csv_duplicate_and_empty_headers():
    dup_csv = "id,name,id\n1,Alpha,2\n"
    with pytest.raises(DatasetError) as exc:
        parse_dataset(dup_csv, fmt="csv")
    assert "Duplicate column header 'id'" in str(exc.value)

    empty_hdr_csv = "id,,alt\n1,Alpha,500\n"
    with pytest.raises(DatasetError) as exc:
        parse_dataset(empty_hdr_csv, fmt="csv")
    assert "Header column 2 is empty" in str(exc.value)


def test_json_and_jsonl_parsing():
    json_data = '[{"id": 1, "active": true, "nested": {"x": 10}}, {"id": 2, "active": false}]'
    ds_json = parse_dataset(json_data)
    assert ds_json.format == "json"
    assert "id" in ds_json.columns and "active" in ds_json.columns and "nested" in ds_json.columns
    assert ds_json.rows[0]["active"] is True
    assert ds_json.rows[0]["nested"] == {"x": 10}

    jsonl_data = '{"lat": 12.3, "lon": 45.6}\n{"lat": 12.4, "lon": 45.7}\n'
    ds_jsonl = parse_dataset(jsonl_data)
    assert ds_jsonl.format == "jsonl"
    assert len(ds_jsonl.rows) == 2
    assert ds_jsonl.rows[1]["lat"] == 12.4


def test_column_selection_and_formula_injection_safety():
    # Formula injection strings stay inert plain strings
    formula_csv = 'sensor,val\n"=cmd|\' /C calc\'!A0",99\n'
    ds = parse_dataset(formula_csv, columns=["sensor"])
    assert ds.columns == ["sensor"]
    assert ds.rows[0]["sensor"] == "=cmd|' /C calc'!A0"

    # Unknown column raises error
    with pytest.raises(DatasetError) as exc:
        parse_dataset(formula_csv, columns=["nonexistent"])
    assert "Requested column 'nonexistent' not found" in str(exc.value)


def test_dataset_limits():
    # Max bytes limit
    with pytest.raises(DatasetError) as exc:
        parse_dataset("a,b\n1,2\n", max_bytes=5)
    assert "exceeds maximum limit" in str(exc.value)

    # Max rows limit
    with pytest.raises(DatasetError) as exc:
        parse_dataset("a\n1\n2\n3\n", max_rows=2)
    assert "Row count" in str(exc.value)

    # Payload size limit
    big_row = {"text": "X" * 1200}
    with pytest.raises(DatasetError) as exc:
        validate_payload_sizes([big_row], max_payload_bytes=1000)
    assert "Payload exceeds 1000 bytes limit" in str(exc.value)


def test_tabular_source_stream_payloads():
    rows = [{"id": 1}, {"id": 2}, {"id": 3}]
    source = TabularSource(rows, rate_pps=50, t0=1000.0)
    stream = list(source.stream_payloads())
    assert len(stream) == 3

    t0, p0, idx0 = stream[0]
    t1, p1, idx1 = stream[1]
    t2, p2, idx2 = stream[2]

    assert idx0 == 0 and idx1 == 1 and idx2 == 2
    assert t0 == 1000.0
    assert abs(t1 - 1000.02) < 1e-6
    assert abs(t2 - 1000.04) < 1e-6
    assert p0 == b'{"id":1}'
