"""Historical frequency baselines and anomaly scoring."""
import math

import unidiag_ml as ml
from conftest import event


def test_anomaly_score_poisson_floor():
    # rare pattern (mean 0.05/h, std ~0): std floor prevents div-by-tiny
    z = ml.anomaly_score(30, 0.05, 0.01)
    assert 25 < z < 32


def test_anomaly_score_never_seen():
    assert ml.anomaly_score(5, 0.0, 0.0) == 5.0    # spread floor is 1.0


def test_anomaly_score_normal_rate_is_low():
    assert abs(ml.anomaly_score(2, 2.0, 0.5)) < 1


def test_baseline_counts_quiet_hours_as_zero(ingest, db):
    """A pattern firing once then silent for 99 hours must have mean ~0.01,
    not 1.0 — zeros are data."""
    t0 = 1_700_000_000
    events = [event(t0, message="rare glitch 1")]
    events += [event(t0 + 100 * 3600, message="rare glitch 2")]
    ingest(events)
    fp = db.execute("SELECT fp FROM events LIMIT 1").fetchone()[0]
    mean, std, span = ml.hourly_baseline(db, fp, before=t0 + 99 * 3600)
    assert span >= 98
    assert mean < 0.05


def test_compute_anomalies_ranks_burst_first(ingest, db):
    t0 = 1_700_000_000
    week = [event(t0 + h * 3600, origin="steady",
                  message=f"heartbeat {h} ok warn") for h in range(168)]
    burst = [event(t0 + 168 * 3600 + i, origin="bursty",
                   message="cache write failed") for i in range(50)]
    ingest(week + burst)
    results = ml.compute_anomalies(db, window=3600.0)
    top_z, top_fp = results[0][0], results[0][1]
    template = db.execute(
        "SELECT template FROM fingerprints WHERE fp=?", (top_fp,)).fetchone()[0]
    assert "cache write failed" in template
    assert top_z > 3
