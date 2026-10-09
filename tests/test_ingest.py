"""Tests for log validation and ingestion."""

import json

import pytest

import db
from ingest import ValidationError, ingest, parse_line

VALID = {
    "timestamp": "2026-10-05T09:00:00",
    "user": "mjames",
    "ip": "10.20.1.10",
    "action": "SELECT",
    "table": "departments",
    "rows": 3,
}


def line(**changes):
    """A valid log line with some fields changed (None removes the field)."""
    data = {**VALID, **changes}
    return json.dumps({k: v for k, v in data.items() if v is not None})


def test_valid_line_is_parsed():
    event = parse_line(line())
    assert event["username"] == "mjames"
    assert event["event_type"] == "SELECT"
    assert event["rows_affected"] == 3


@pytest.mark.parametrize("bad_line, reason", [
    ("this is not json", "not valid JSON"),
    ("[1, 2, 3]", "not a JSON object"),
    (line(user=None), "missing field 'user'"),
    (line(timestamp="yesterday"), "bad timestamp"),
    (line(ip="999.1.1.1"), "bad IP address"),
    (line(action="DROP"), "unknown action"),
    (line(action="UPDATE", table=None), "has no table"),
    (line(rows=-5), "bad row count"),
    (line(rows="lots"), "bad row count"),
])
def test_invalid_lines_are_rejected(bad_line, reason):
    with pytest.raises(ValidationError, match=reason):
        parse_line(bad_line)


def test_ingest_loads_every_valid_line(full_log):
    summary = ingest(full_log)
    assert summary["read"] == summary["inserted"]
    assert summary["rejected"] == 0


def test_ingest_twice_creates_no_duplicates(full_log):
    first = ingest(full_log)
    second = ingest(full_log)
    assert second["inserted"] == 0
    assert second["duplicates"] == first["inserted"]

    conn = db.get_connection()
    count = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    conn.close()
    assert count == first["inserted"]


def test_rejected_lines_are_logged_with_reason(temp_db):
    log = temp_db / "mixed.jsonl"
    log.write_text(line() + "\n" + line(ip="not-an-ip") + "\n")

    summary = ingest(log)

    assert summary["inserted"] == 1
    assert summary["rejected"] == 1
    rejected = (temp_db / "rejected.log").read_text()
    assert "bad IP address 'not-an-ip'" in rejected


def test_sql_injection_in_log_is_stored_as_plain_text(temp_db):
    """A malicious username must be saved as text, never run as SQL."""
    evil = "x'); DROP TABLE users; --"
    log = temp_db / "evil.jsonl"
    log.write_text(line(user=evil) + "\n")

    ingest(log)

    conn = db.get_connection()
    stored = conn.execute("SELECT username FROM audit_events").fetchone()[0]
    users_left = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    conn.close()
    assert stored == evil.lower()
    assert users_left == len(db.SEED_USERS)   # the users table survived
