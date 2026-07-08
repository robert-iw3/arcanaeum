"""Host profiling: role inference (bash plugin) and role priors (analysis).
The override env hooks make inference testable without a real web/db host.
"""
import json
import os
import subprocess

import unidiag_ml as ml
from conftest import LINUX_DIR, event

UNIDIAG = str(LINUX_DIR / "unidiag.sh")


def profile_json(ports="", comms=""):
    env = dict(os.environ,
               PROFILE_PORTS_OVERRIDE=ports or "none",
               PROFILE_COMMS_OVERRIDE=comms or "none")
    r = subprocess.run([UNIDIAG, "profile", "--json"], env=env,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


# ------------------------------------------------------------ role inference

def test_web_and_db_host_detected():
    p = profile_json(ports="80 443 5432", comms="nginx postgres sshd")
    assert p["roles"]["web"]["confidence"] == "high"       # process beats port
    assert p["roles"]["database"]["confidence"] == "high"
    assert p["hints"]["nginx"] == "web"
    assert p["hints"]["postgres"] == "database"


def test_port_only_evidence_is_medium_confidence():
    p = profile_json(ports="3306", comms="bash")
    assert p["roles"]["database"]["confidence"] == "medium"
    assert "port 3306" in p["roles"]["database"]["evidence"]


def test_unknown_host_falls_back_to_general():
    p = profile_json(ports="12345", comms="mystery-daemon")
    assert "general" in p["roles"]


def test_profile_json_is_valid_json_with_expected_shape():
    p = profile_json(ports="80", comms="nginx")
    assert set(p) == {"host", "roles", "hints"}
    for role, info in p["roles"].items():
        assert info["confidence"] in {"high", "medium", "low"}
        assert info["evidence"]


# ------------------------------------------------------- role priors (ML)

def test_origin_role_substring_match():
    hints = {"postgres": "database", "nginx": "web"}
    assert ml.origin_role("postgresql.service", hints) == "database"
    assert ml.origin_role("prod/nginx-7f9c4d", hints) == "web"
    assert ml.origin_role("cron.service", hints) is None


def test_role_prior_boosts_upstream_candidate(ingest, db):
    """Same incident, with and without a profile: the database candidate's
    score must rise by its role prior and carry the reason."""
    t0 = 1_700_000_000
    ingest([
        event(t0, origin="webapp", message="upstream timeout talking to backend"),
        event(t0 + 1, origin="postgres", message="too many connections limit reached"),
    ])
    plain = ml.analyze_incidents(db, window=3600.0)
    profiled = ml.analyze_incidents(db, window=3600.0,
                                    profile={"hints": {"postgres": "database"}})
    def cand(incidents, origin):
        return next(c for c in incidents[0]["ranked"] if c["origin"] == origin)
    boost = cand(profiled, "postgres")["score"] - cand(plain, "postgres")["score"]
    assert abs(boost - ml.ROLE_PRIOR["database"]) < 1e-9
    assert "role=database" in cand(profiled, "postgres")["reasons"]
    # the non-hinted candidate is untouched
    assert cand(profiled, "webapp")["score"] == cand(plain, "webapp")["score"]


def test_monitoring_role_gets_no_boost(ingest, db):
    t0 = 1_700_000_000
    ingest([
        event(t0, origin="prometheus", message="scrape target down"),
        event(t0 + 1, origin="api", message="request handler crashed hard"),
    ])
    plain = ml.analyze_incidents(db, window=3600.0)
    profiled = ml.analyze_incidents(db, window=3600.0,
                                    profile={"hints": {"prometheus": "monitoring"}})
    prom_plain = next(c for c in plain[0]["ranked"] if c["origin"] == "prometheus")
    prom_prof = next(c for c in profiled[0]["ranked"] if c["origin"] == "prometheus")
    assert prom_prof["score"] == prom_plain["score"]      # prior is 0.0
