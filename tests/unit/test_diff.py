"""Unit tests for content-based diff and label inference (simulation/manual/diff.py)."""

import pytest
from securelink.simulation.manual.diff import infer_labels


def test_diff_clean_baseline():
    parent = [
        {"eid": "1", "n": 1, "hex": "aabbcc11"},
        {"eid": "2", "n": 2, "hex": "aabbcc22"},
        {"eid": "3", "n": 3, "hex": "aabbcc33"},
    ]
    uploaded = [
        {"eid": "1", "n": 1, "hex": "aabbcc11"},
        {"eid": "2", "n": 2, "hex": "aabbcc22"},
        {"eid": "3", "n": 3, "hex": "aabbcc33"},
    ]
    labels, dropped = infer_labels(parent, uploaded)
    assert dropped == []
    assert labels == {"1": "AUTHENTIC", "2": "AUTHENTIC", "3": "AUTHENTIC"}


def test_diff_tampered_frame():
    parent = [
        {"eid": "1", "n": 1, "hex": "aabbcc11"},
        {"eid": "2", "n": 2, "hex": "aabbcc22"},
    ]
    # Frame 2 has modified hex
    uploaded = [
        {"eid": "1", "n": 1, "hex": "aabbcc11"},
        {"eid": "2", "n": 2, "hex": "aabbccff"},
    ]
    labels, dropped = infer_labels(parent, uploaded)
    assert dropped == []
    assert labels["1"] == "AUTHENTIC"
    assert labels["2"] == "TAMPERED"


def test_diff_replayed_frame_and_duplicates():
    parent = [
        {"eid": "1", "n": 1, "hex": "aabbcc11"},
        {"eid": "2", "n": 2, "hex": "aabbcc22"},
    ]
    # Frame 1 is duplicated / pasted at end
    uploaded = [
        {"eid": "1", "n": 1, "hex": "aabbcc11"},
        {"eid": "2", "n": 2, "hex": "aabbcc22"},
        {"eid": "rep_1", "n": 3, "hex": "aabbcc11"},
    ]
    labels, dropped = infer_labels(parent, uploaded)
    assert dropped == []
    assert labels["1"] == "AUTHENTIC"
    assert labels["2"] == "AUTHENTIC"
    assert labels["rep_1"] == "REPLAYED"


def test_diff_spoofed_frame():
    parent = [
        {"eid": "1", "n": 1, "hex": "aabbcc11"},
    ]
    # Brand new frame injected
    uploaded = [
        {"eid": "1", "n": 1, "hex": "aabbcc11"},
        {"eid": "spf_1", "n": 99, "hex": "deadbeef99"},
    ]
    labels, dropped = infer_labels(parent, uploaded)
    assert dropped == []
    assert labels["1"] == "AUTHENTIC"
    assert labels["spf_1"] == "SPOOFED"


def test_diff_dropped_frames():
    parent = [
        {"eid": "1", "n": 1, "hex": "aabbcc11"},
        {"eid": "2", "n": 2, "hex": "aabbcc22"},
        {"eid": "3", "n": 3, "hex": "aabbcc33"},
    ]
    # Line 2 deleted
    uploaded = [
        {"eid": "1", "n": 1, "hex": "aabbcc11"},
        {"eid": "3", "n": 3, "hex": "aabbcc33"},
    ]
    labels, dropped = infer_labels(parent, uploaded)
    assert dropped == [2]
    assert labels["1"] == "AUTHENTIC"
    assert labels["3"] == "AUTHENTIC"


def test_diff_malformed_line():
    parent = [{"eid": "1", "n": 1, "hex": "aabbcc11"}]
    uploaded = [{"eid": "1", "n": 1, "hex": "", "is_malformed": True}]
    labels, dropped = infer_labels(parent, uploaded)
    assert labels["1"] == "TAMPERED"
