"""End-to-end diagnosis: the OOM-cascade scenario is the core product claim —
the kernel kill must outrank the louder downstream storm."""
import unidiag_ml as ml
from conftest import event


def oom_cascade(t0):
    """7 days of noise, then: kernel OOM -> db crash -> downstream storm."""
    events = []
    for h in range(0, 168):
        events.append(event(t0 + h * 3600, severity="warn", source="journald",
                            origin="cron.service",
                            message=f"job {h} finished with warnings"))
    ti = t0 + 168 * 3600
    events.append(event(ti, severity="crit", source="kernel", origin="-",
                        message="Out of memory: Killed process 4231 (postgres) total-vm:8123456kB"))
    events.append(event(ti + 2, severity="crit", source="docker", origin="postgres",
                        message="FATAL: the database system is in recovery mode"))
    for i in range(30):
        events.append(event(ti + 3 + i * 0.4, severity="error", source="docker",
                            origin=("api", "worker", "webapp")[i % 3],
                            message=f"connect to 10.0.0.{2 + i % 8}:5432 refused"))
    return events


def test_oom_cascade_culprit_is_kernel_not_storm(ingest, db):
    ingest(oom_cascade(1_700_000_000))
    incidents = ml.analyze_incidents(db, window=3600.0)
    assert len(incidents) == 1
    culprit = incidents[0]["ranked"][0]
    assert culprit["origin"] == "-" or "Out of memory" in culprit["template"]
    assert "Out of memory" in culprit["template"]
    assert "first to fire" in culprit["reasons"]
    # the storm is present but demoted
    templates = [c["template"] for c in incidents[0]["ranked"]]
    assert any("refused" in t for t in templates[1:])


def test_storm_still_flagged_as_anomaly(ingest, db):
    """Anomaly detection and culprit ranking answer different questions:
    the storm IS the biggest anomaly, it is just not the culprit."""
    ingest(oom_cascade(1_700_000_000))
    top_fp = ml.compute_anomalies(db, window=3600.0)[0][1]
    template = db.execute(
        "SELECT template FROM fingerprints WHERE fp=?", (top_fp,)).fetchone()[0]
    assert "refused" in template


def test_single_pattern_bursts_are_not_incidents(ingest, db):
    t0 = 1_700_000_000
    ingest([event(t0 + i, message="same old error") for i in range(20)])
    assert ml.analyze_incidents(db, window=3600.0) == []
