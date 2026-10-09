"""Shared test setup.

Every test gets its own brand-new database in a temporary folder, so tests
never touch your real auditsentinel.db and can't affect each other.
"""

import json
import random
import sys
from pathlib import Path

import pytest

# Let tests import db, ingest, detect and app from the project folder
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import db  # noqa: E402
import generate_logs  # noqa: E402
import ingest  # noqa: E402


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """Point the project at a fresh, empty database for this one test."""
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(ingest, "REJECTED_LOG", tmp_path / "rejected.log")
    db.init_db()
    return tmp_path


def write_log(path, events):
    """Write a list of event dicts to a JSONL file and return its path."""
    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    return path


@pytest.fixture
def normal_log(temp_db):
    """A log containing only normal business activity, no attacks."""
    random.seed(42)
    return write_log(temp_db / "normal.jsonl", generate_logs.normal_activity())


@pytest.fixture
def full_log(temp_db):
    """The same log the project generates: normal activity plus five attacks."""
    random.seed(42)
    events = generate_logs.normal_activity() + generate_logs.attack_scenarios()
    events.sort(key=lambda e: e["timestamp"])
    return write_log(temp_db / "full.jsonl", events)
