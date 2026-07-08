#!/usr/bin/env python3
"""
unidiag_ml — conceptual ML analysis layer for unidiag (Phase 1/2 prototype).

Consumes events from `unidiag.sh scan --json`, then:

  1. FINGERPRINT  Drain-lite template mining: mask variables (ips, uuids,
                  numbers, paths), cluster messages by token similarity so
                  "conn to 10.0.0.5 refused" == "conn to 10.0.0.9 refused".
  2. BASELINE     Historical frequency per fingerprint per hour bucket,
                  persisted in SQLite. This is the tool's memory.
  3. ANOMALY      Current rate vs. baseline as a z-score (with Poisson floor):
                  "4x/day historically, 400x this hour" -> huge z.
  4. CORRELATE    Gap-based sessionization clusters events into incidents;
                  within incidents, pairwise lead-lag counting learns which
                  patterns consistently PRECEDE which ("A fires 2s before B").
  5. DIAGNOSE     Rank culprit candidates per incident by: anomaly magnitude,
                  precedence centrality (how many patterns it leads), layer
                  prior (kernel > system > container > app), severity, and
                  onset (first in the burst). Print ranked diagnosis + why.

Deliberately stdlib-only so every concept is visible and portable — the same
algorithms port straight to Rust. Where production ML would slot in:
  - baselines: seasonal decomposition (statsmodels) instead of flat hourly mean
  - burst causality: Hawkes processes instead of lead-lag counts
  - culprit ranking: PageRank on the precedence graph (networkx/scipy)
  - template mining: drain3 instead of Drain-lite

Usage:
  unidiag.sh scan --since 1d --json | unidiag_ml.py ingest
  unidiag_ml.py anomalies [--window 3600]
  unidiag_ml.py diagnose  [--window 3600]
  unidiag_ml.py fingerprints
  unidiag_ml.py demo          # synthetic OOM-cascade end-to-end test
"""

import argparse
import hashlib
import json
import math
import os
import re
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timezone

DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "unidiag.db")

# --------------------------------------------------------------- fingerprints

MASKS = [
    (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "<uuid>"),
    (re.compile(r"(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?"), "<ip>"),
    (re.compile(r"0x[0-9a-fA-F]+"), "<hex>"),
    (re.compile(r"\b[0-9a-fA-F]{12,64}\b"), "<hash>"),
    (re.compile(r"(?<=[\s='\"(])/[\w@.\-/]{4,}"), "<path>"),
    (re.compile(r"\d+"), "<n>"),
]

SIMILARITY_THRESHOLD = 0.55   # Drain's default neighborhood


def mask(message: str) -> str:
    for pattern, token in MASKS:
        message = pattern.sub(token, message)
    return message


class TemplateMiner:
    """Drain-lite: bucket by (source, token count, first token), then merge a
    new message into the most similar existing template if token-position
    similarity clears the threshold; differing positions become <*>."""

    def __init__(self):
        self.buckets = defaultdict(list)   # key -> [template token lists]

    def fingerprint(self, source: str, message: str):
        tokens = mask(message).split()
        if not tokens:
            tokens = ["<empty>"]
        key = (source, len(tokens), tokens[0])
        best, best_sim = None, 0.0
        for template in self.buckets[key]:
            same = sum(1 for a, b in zip(template, tokens) if a == b or a == "<*>")
            sim = same / len(tokens)
            if sim > best_sim:
                best, best_sim = template, sim
        if best is not None and best_sim >= SIMILARITY_THRESHOLD:
            for i, (a, b) in enumerate(zip(best, tokens)):
                if a != b:
                    best[i] = "<*>"
            template = best
        else:
            template = list(tokens)
            self.buckets[key].append(template)
        text = " ".join(template)
        fp = hashlib.sha1(f"{source}|{text}".encode()).hexdigest()[:12]
        return fp, text


# -------------------------------------------------------------------- storage

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    ts        REAL NOT NULL,           -- unix epoch seconds
    severity  TEXT NOT NULL,
    source    TEXT NOT NULL,
    origin    TEXT NOT NULL,
    fp        TEXT NOT NULL,
    message   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_fp ON events(fp);
CREATE TABLE IF NOT EXISTS fingerprints (
    fp         TEXT PRIMARY KEY,
    template   TEXT NOT NULL,
    source     TEXT NOT NULL,
    first_seen REAL NOT NULL
);
"""


def open_db(path: str) -> sqlite3.Connection:
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    return db


def parse_ts(iso: str) -> float:
    iso = iso.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:                       # syslog fallback: local time
        dt = dt.astimezone()
    return dt.timestamp()


def read_json_stream(stream):
    """Accept both JSONL and jq-style concatenated pretty-printed objects."""
    decoder = json.JSONDecoder()
    buf = stream.read()
    idx, n = 0, len(buf)
    while idx < n:
        while idx < n and buf[idx] in " \t\r\n":
            idx += 1
        if idx >= n:
            break
        obj, end = decoder.raw_decode(buf, idx)
        idx = end
        yield obj


# --------------------------------------------------------------------- ingest

def cmd_ingest(db, args):
    miner = TemplateMiner()
    # replay existing templates so fingerprints stay stable across ingests
    for fp, template, source in db.execute("SELECT fp, template, source FROM fingerprints"):
        tokens = template.split()
        miner.buckets[(source, len(tokens), tokens[0])].append(tokens)
    count = 0
    for ev in read_json_stream(sys.stdin):
        ts = parse_ts(ev["ts"])
        fp, template = miner.fingerprint(ev["source"], ev["message"])
        db.execute("INSERT OR IGNORE INTO fingerprints VALUES (?,?,?,?)",
                   (fp, template, ev["source"], ts))
        db.execute("UPDATE fingerprints SET template=? WHERE fp=?", (template, fp))
        db.execute("INSERT INTO events VALUES (?,?,?,?,?,?)",
                   (ts, ev["severity"], ev["source"], ev["origin"], fp, ev["message"]))
        count += 1
    db.commit()
    total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    fps = db.execute("SELECT COUNT(*) FROM fingerprints").fetchone()[0]
    print(f"ingested {count} events ({total} total, {fps} distinct fingerprints)")


# ------------------------------------------------------------------- baseline

def hourly_baseline(db, fp: str, before: float):
    """Historical mean/std of events-per-hour for one fingerprint, computed
    over hour buckets strictly before the analysis window. Hours with zero
    events count as zeros across the fingerprint's observed lifespan."""
    rows = db.execute(
        "SELECT CAST(ts/3600 AS INT) h, COUNT(*) FROM events "
        "WHERE fp=? AND ts<? GROUP BY h", (fp, before)).fetchall()
    if not rows:
        return 0.0, 0.0, 0
    first_hour = min(h for h, _ in rows)
    span = max(int(before // 3600) - first_hour, 1)
    counts = [c for _, c in rows] + [0] * max(span - len(rows), 0)
    mean = sum(counts) / len(counts)
    var = sum((c - mean) ** 2 for c in counts) / len(counts)
    return mean, math.sqrt(var), span


def anomaly_score(current: int, mean: float, std: float) -> float:
    """z-score with a Poisson floor: for rare events std is tiny, so use
    sqrt(mean) as the minimum spread; +1 Laplace smoothing for never-seen."""
    spread = max(std, math.sqrt(max(mean, 0.0)), 1.0)
    return (current - mean) / spread


def window_counts(db, since: float):
    return dict(db.execute(
        "SELECT fp, COUNT(*) FROM events WHERE ts>=? GROUP BY fp", (since,)))


def compute_anomalies(db, window, now=None):
    """Rate anomalies for every fingerprint active in the window, sorted by
    z-score descending. Separated from printing so tests drive it directly."""
    now = latest_ts(db) if now is None else now
    since = now - window
    hours = window / 3600
    results = []
    for fp, current in window_counts(db, since).items():
        mean, std, span = hourly_baseline(db, fp, since)
        z = anomaly_score(current / hours, mean, std)
        results.append((z, fp, current, mean, span))
    results.sort(reverse=True)
    return results


def cmd_anomalies(db, args):
    results = compute_anomalies(db, args.window)
    if not results:
        print("no events in window")
        return
    print(f"rate anomalies, last {args.window/3600:g}h vs. history "
          f"(z >= 3 is anomalous):\n")
    for z, fp, current, mean, span in results[:15]:
        template, source = db.execute(
            "SELECT template, source FROM fingerprints WHERE fp=?", (fp,)).fetchone()
        flag = "!!" if z >= 3 else "  "
        print(f"{flag} z={z:6.1f}  {current:5d} now vs {mean:6.2f}/h "
              f"over {span}h  [{source}] {template[:90]}")


# ------------------------------------------------------------------ correlate

INCIDENT_GAP = 30.0     # seconds of silence that ends an incident
LEAD_LAG_MAX = 15.0     # max seconds for A to be considered "leading" B

LAYER_PRIOR = {"kernel": 3.0, "journald": 2.0, "syslog": 2.0,
               "docker": 1.5, "podman": 1.5, "k8s": 1.5}
SEVERITY_WEIGHT = {"crit": 2.0, "error": 1.5, "warn": 1.0}

# Causal role priors, fed by `unidiag.sh profile --json` hints. Upstream
# roles fail first and take dependents with them, so they deserve a higher
# culprit prior; a proxy or monitor mostly reports others' failures.
ROLE_PRIOR = {"database": 1.0, "dns": 1.0, "cache": 0.8, "queue": 0.8,
              "file-server": 0.8, "container-host": 0.5, "kubernetes-node": 0.5,
              "proxy": 0.2, "web": 0.3, "app-runtime": 0.3, "monitoring": 0.0}


def origin_role(origin: str, hints: dict):
    """Match an event origin against profile hints (substring match, so
    'postgres' tags both the unit postgresql.service and a postgres pod)."""
    for sub, role in hints.items():
        if sub in origin:
            return role
    return None


def load_events(db, since: float):
    return db.execute(
        "SELECT ts, severity, source, origin, fp FROM events "
        "WHERE ts>=? ORDER BY ts", (since,)).fetchall()


def sessionize(events):
    """Gap-based incident clustering: a silence > INCIDENT_GAP splits bursts."""
    incidents, current = [], []
    for ev in events:
        if current and ev[0] - current[-1][0] > INCIDENT_GAP:
            incidents.append(current)
            current = []
        current.append(ev)
    if current:
        incidents.append(current)
    return incidents


def precedence_scores(incident):
    """For each ordered fingerprint pair (A,B) with 0 < lag <= LEAD_LAG_MAX,
    count A->B. Centrality = (#patterns this one leads) - (#that lead it).
    A true root cause leads many and is led by few."""
    first_seen = {}
    for ts, _, _, _, fp in incident:
        first_seen.setdefault(fp, ts)
    leads = defaultdict(set)
    for a, ta in first_seen.items():
        for b, tb in first_seen.items():
            if a != b and 0 < tb - ta <= LEAD_LAG_MAX:
                leads[a].add(b)
    led_by = defaultdict(set)
    for a, targets in leads.items():
        for b in targets:
            led_by[b].add(a)
    return {fp: len(leads[fp]) - len(led_by[fp]) for fp in first_seen}, first_seen


# ------------------------------------------------------------------- diagnose

def analyze_incidents(db, window, now=None, profile=None):
    """Full diagnosis pipeline, returning structured incidents so tests (and
    future output formats) consume data, not stdout. Each incident dict:
    t0, t1, n_events, origins, and ranked candidates (best culprit first)
    with fp/template/origin/severity/score/z/reasons.
    profile: parsed `unidiag.sh profile --json` output; its hints add
    role-based causal priors to the ranking."""
    hints = (profile or {}).get("hints", {})
    now = latest_ts(db) if now is None else now
    since = now - window
    events = load_events(db, since)
    hours = window / 3600
    zcache = {}
    for fp, current in window_counts(db, since).items():
        mean, std, _ = hourly_baseline(db, fp, since)
        zcache[fp] = anomaly_score(current / hours, mean, std)

    results = []
    for inc in sessionize(events):
        if len({e[4] for e in inc}) < 2:        # single-pattern: nothing to correlate
            continue
        t0, t1 = inc[0][0], inc[-1][0]
        prec, first_seen = precedence_scores(inc)
        onset_fp = min(first_seen, key=first_seen.get)
        sev_by_fp, src_by_fp, org_by_fp = {}, {}, {}
        for _, sev, src, org, fp in inc:
            if SEVERITY_WEIGHT.get(sev, 1) >= SEVERITY_WEIGHT.get(sev_by_fp.get(fp, "warn"), 1):
                sev_by_fp[fp] = sev
            src_by_fp[fp], org_by_fp[fp] = src, org

        max_prec = max((abs(v) for v in prec.values()), default=1) or 1
        ranked = []
        for fp in first_seen:
            z = zcache.get(fp, 0.0)
            role = origin_role(org_by_fp[fp], hints)
            score = (2.0 * min(max(z, 0.0), 10.0) / 10.0        # anomaly, capped
                     + 1.5 * max(prec[fp], 0) / max_prec         # leads others
                     + LAYER_PRIOR.get(src_by_fp[fp], 1.0)       # host beats app
                     + SEVERITY_WEIGHT.get(sev_by_fp[fp], 1.0)
                     + (1.0 if fp == onset_fp else 0.0)          # first to fire
                     + (ROLE_PRIOR.get(role, 0.0) if role else 0.0))  # upstream role
            reasons = []
            if role:
                reasons.append(f"role={role}")
            if fp == onset_fp:
                reasons.append("first to fire")
            if prec[fp] > 0:
                reasons.append(f"precedes {prec[fp]} other pattern(s)")
            if z >= 3:
                reasons.append(f"rate anomaly z={z:.0f}")
            reasons.append(f"layer={src_by_fp[fp]}")
            reasons.append(f"sev={sev_by_fp[fp]}")
            template = db.execute(
                "SELECT template FROM fingerprints WHERE fp=?", (fp,)).fetchone()[0]
            ranked.append({"fp": fp, "template": template, "score": score,
                           "z": z, "origin": org_by_fp[fp],
                           "severity": sev_by_fp[fp], "reasons": reasons})
        ranked.sort(key=lambda c: c["score"], reverse=True)
        results.append({"t0": t0, "t1": t1, "n_events": len(inc),
                        "origins": sorted({org_by_fp[f] for f in first_seen}),
                        "ranked": ranked})
    return results


def cmd_diagnose(db, args):
    profile = None
    if getattr(args, "profile", None):
        with open(args.profile) as f:
            profile = json.load(f)
    incidents = analyze_incidents(db, args.window, profile=profile)
    if not incidents:
        print("no multi-pattern incidents in window (nothing to correlate)")
        return
    print(f"{len(incidents)} incident(s) in last {args.window/3600:g}h\n")
    for n, inc in enumerate(incidents, 1):
        span = inc["t1"] - inc["t0"]
        stamp = datetime.fromtimestamp(inc["t0"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        print(f"incident #{n}: {stamp}  ({span:.1f}s, {inc['n_events']} events, "
              f"{len(inc['ranked'])} patterns, origins: {', '.join(inc['origins'])})")
        for rank, cand in enumerate(inc["ranked"][:3], 1):
            marker = "CULPRIT" if rank == 1 else f"     #{rank}"
            print(f"  {marker}  [{cand['score']:4.1f}] [{cand['origin']}] {cand['template'][:80]}")
            print(f"           why: {', '.join(cand['reasons'])}")
        print()


def cmd_fingerprints(db, args):
    rows = db.execute(
        "SELECT f.fp, f.source, f.template, COUNT(e.fp) n FROM fingerprints f "
        "LEFT JOIN events e ON e.fp=f.fp GROUP BY f.fp ORDER BY n DESC LIMIT 20").fetchall()
    for fp, source, template, n in rows:
        print(f"{n:6d}x  {fp}  [{source}] {template[:90]}")


def latest_ts(db) -> float:
    row = db.execute("SELECT MAX(ts) FROM events").fetchone()
    return row[0] if row and row[0] else datetime.now(tz=timezone.utc).timestamp()


# ----------------------------------------------------------------------- demo

def cmd_demo(db, args):
    """Synthetic end-to-end test: 7 days of background noise, then an OOM
    cascade — kernel kill -> app crash -> downstream connection refusals.
    A correct diagnosis pins the kernel OOM as culprit, not the noisy apps."""
    import random
    random.seed(42)
    now = datetime.now(tz=timezone.utc).timestamp()
    t0 = now - 7 * 86400
    events = []

    def emit(ts, sev, src, org, msg):
        iso = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        events.append({"ts": iso, "severity": sev, "source": src,
                       "origin": org, "message": msg})

    # background noise: steady, boring, must NOT be blamed
    t = t0
    while t < now:
        emit(t, "warn", "journald", "cron.service",
             f"job {random.randint(100,999)} finished with warnings")
        t += 3600 + random.uniform(-300, 300)
    t = t0
    while t < now:
        emit(t, "error", "docker", "webapp",
             f"GET /health slow: {random.randint(200,900)}ms")
        t += 1800 + random.uniform(-200, 200)

    # occasional historical instances of the downstream error (low baseline)
    for _ in range(6):
        ts = random.uniform(t0, now - 7200)
        emit(ts, "error", "docker", "api",
             f"connect to 10.0.0.{random.randint(2,9)}:5432 refused")

    # THE INCIDENT, 20 minutes ago: OOM cascade
    ti = now - 1200
    emit(ti, "crit", "kernel", "-",
         "Out of memory: Killed process 4231 (postgres) total-vm:8123456kB")
    emit(ti + 2.0, "crit", "docker", "postgres",
         "FATAL: the database system is in recovery mode")
    for i in range(30):   # downstream storm across services
        ts = ti + 3 + i * 0.4
        svc = random.choice(["api", "worker", "webapp"])
        emit(ts, "error", "docker", svc,
             f"connect to 10.0.0.{random.randint(2,9)}:5432 refused")

    events.sort(key=lambda e: e["ts"])
    print(f"demo: ingesting {len(events)} synthetic events "
          f"(7d noise + OOM cascade 20min ago)\n")

    class FakeStdin:
        def read(self):
            return "\n".join(json.dumps(e) for e in events)
    real_stdin, sys.stdin = sys.stdin, FakeStdin()
    try:
        cmd_ingest(db, args)
    finally:
        sys.stdin = real_stdin

    print("\n--- anomalies ---")
    args.window = 3600.0
    cmd_anomalies(db, args)
    print("\n--- diagnose ---")
    cmd_diagnose(db, args)


# ------------------------------------------------------------------------ cli

def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("command",
                        choices=["ingest", "anomalies", "diagnose", "fingerprints", "demo"])
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite path")
    parser.add_argument("--window", type=float, default=3600.0,
                        help="analysis window in seconds (default 3600)")
    parser.add_argument("--profile", default=None,
                        help="path to `unidiag.sh profile --json` output; "
                             "adds role-based causal priors to diagnosis")
    args = parser.parse_args()
    if args.command == "demo" and os.path.exists(args.db) and args.db == DEFAULT_DB:
        args.db = args.db + ".demo"           # never mix demo data into real db
        if os.path.exists(args.db):
            os.remove(args.db)
    db = open_db(args.db)
    {"ingest": cmd_ingest, "anomalies": cmd_anomalies, "diagnose": cmd_diagnose,
     "fingerprints": cmd_fingerprints, "demo": cmd_demo}[args.command](db, args)


if __name__ == "__main__":
    main()
