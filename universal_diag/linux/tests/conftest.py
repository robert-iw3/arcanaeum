import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).parent
LINUX_DIR = TESTS_DIR.parent
FIXTURES = TESTS_DIR / "fixtures"

sys.path.insert(0, str(LINUX_DIR / "analysis"))

import unidiag_ml  # noqa: E402


@pytest.fixture
def db(tmp_path):
    conn = unidiag_ml.open_db(str(tmp_path / "test.db"))
    yield conn
    conn.close()


@pytest.fixture
def ingest(db, monkeypatch):
    """Ingest a list of event dicts through the real cmd_ingest path."""
    def _ingest(events):
        class Stdin:
            def read(self):
                return "\n".join(json.dumps(e) for e in events)
        monkeypatch.setattr(sys, "stdin", Stdin())
        unidiag_ml.cmd_ingest(db, None)
        return db
    return _ingest


def iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z")


def event(ts, severity="error", source="docker", origin="app", message="boom"):
    return {"ts": iso(ts), "severity": severity, "source": source,
            "origin": origin, "message": message}
