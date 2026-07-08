"""Incident sessionization and lead-lag precedence."""
import unidiag_ml as ml


def ev(ts, fp, sev="error", src="docker", org="app"):
    return (ts, sev, src, org, fp)


def test_sessionize_splits_on_gap():
    events = [ev(0, "a"), ev(5, "a"), ev(100, "b"), ev(101, "b")]
    incidents = ml.sessionize(events)
    assert len(incidents) == 2
    assert [e[4] for e in incidents[0]] == ["a", "a"]


def test_sessionize_keeps_burst_together():
    events = [ev(i * 2.0, "x") for i in range(10)]
    assert len(ml.sessionize(events)) == 1


def test_precedence_root_leads_followers():
    incident = [ev(0, "root"), ev(2, "mid"), ev(4, "leaf1"), ev(5, "leaf2")]
    prec, first_seen = ml.precedence_scores(incident)
    assert prec["root"] == max(prec.values())
    assert prec["root"] == 3            # leads all three, led by none
    assert prec["leaf2"] < 0            # led by others, leads none
    assert min(first_seen, key=first_seen.get) == "root"


def test_precedence_respects_lead_lag_window():
    # 60s gap is beyond LEAD_LAG_MAX (15s): no causal edge, but the pair is
    # still one incident only if within INCIDENT_GAP — use 20s to stay inside
    incident = [ev(0, "a"), ev(20, "b")]
    prec, _ = ml.precedence_scores(incident)
    assert prec["a"] == 0 and prec["b"] == 0
