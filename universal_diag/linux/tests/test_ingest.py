"""Ingest plumbing: JSON stream forms and timestamp parsing."""
import io
import json

import pytest

import unidiag_ml as ml


def test_read_json_stream_jsonl():
    stream = io.StringIO('{"a": 1}\n{"a": 2}\n')
    assert [o["a"] for o in ml.read_json_stream(stream)] == [1, 2]


def test_read_json_stream_concatenated_pretty():
    """jq default output: pretty-printed objects with no separators."""
    stream = io.StringIO('{\n  "a": 1\n}\n{\n  "a": 2\n}\n')
    assert [o["a"] for o in ml.read_json_stream(stream)] == [1, 2]


def test_parse_ts_utc_z():
    assert ml.parse_ts("1970-01-01T00:00:01.000Z") == 1.0


def test_parse_ts_offset():
    assert ml.parse_ts("1970-01-01T01:00:01.000+01:00") == 1.0


def test_parse_ts_naive_uses_local_time():
    """Syslog fallback emits no zone — must not crash, must be tz-aware."""
    assert isinstance(ml.parse_ts("2026-07-02T14:02:11.480"), float)


def test_ingest_assigns_same_fp_across_runs(ingest, db):
    from conftest import event
    ingest([event(1_700_000_000, message="connect to 10.0.0.5:5432 refused")])
    ingest([event(1_700_000_100, message="connect to 10.0.0.9:5432 refused")])
    fps = db.execute("SELECT DISTINCT fp FROM events").fetchall()
    assert len(fps) == 1


@pytest.mark.xfail(reason="ROADMAP A1: content-hash idempotent re-ingest not built yet")
def test_reingest_is_idempotent(ingest, db):
    from conftest import event
    events = [event(1_700_000_000, message="dup me")]
    ingest(events)
    ingest(events)
    assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
