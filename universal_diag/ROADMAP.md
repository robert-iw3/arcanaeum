# universal_diag — Planning Guide & Roadmap

> Living document. Check items off as they land; add decisions to the log at
> the bottom. Design brief (visual): https://claude.ai/code/artifact/672f314a-7507-45b7-ba55-cec8c4b0977b

## Intent

Every observability tool on the market stops at *showing* you the error. The
operator still does the last three steps by hand: correlating symptoms across
layers, identifying the actual culprit, and finding the fix. **unidiag exists
to automate those last three steps** — on any Linux host (bare metal, Docker/
podman, Kubernetes), on any distro (systemd or not, GNU or busybox), with no
SaaS dependency and no cluster to maintain.

The operating philosophy is baked into the tool:

1. **Host before apps** — an app error on a sick host is a symptom, not the
   disease. Triage the kernel, saturation, capacity, and platform first.
2. **Patterns, not lines** — reason over fingerprinted error templates, not
   raw log volume.
3. **Culprits, not anomalies** — the biggest spike is usually the victim.
   Onset order, precedence, and layer priors find the disease.
4. **Predict, don't just react** — trends (disk slope, fd creep, rate
   baselines) surface failures days before they fire.

## End state — what "done" looks like

A single static Rust binary, `unidiag`, that an admin drops onto any Linux
box and gets:

- `unidiag triage` — host health verdict in seconds, ordered by diagnostic
  value (kernel ring → saturation/PSI → capacity → platform).
- `unidiag scan` — unified warn+ timeline across journald/syslog/dmesg/
  containers/k8s, deduplicated into fingerprints.
- `unidiag daemon` — continuous ingest, frequency baselines, incident
  detection, and predictive alerts ("`/var` full in ~4 days", "fd count
  doubles every 6h in service X").
- `unidiag diagnose` — for any incident: ranked culprit with the *why*
  (onset, precedence, anomaly, layer), matched against resolution packs
  (community YAML: signature → diagnosis → fix steps), optional LLM fallback
  for unmatched incidents (clearly fenced, never in the remediation path).
- `unidiag fix` — guarded remediation: dry-run default, allowlisted,
  journaled, only for pack remediations marked safe.

**Success criteria:** a mid-incident admin gets from "something is wrong" to
"here is the culprit and the fix" in under a minute, offline, on a distro the
tool has never seen. Explicitly *not* a goal: long-term log storage — unidiag
reasons over a sliding window and defers archival to whatever exists.

## Where we are (2026-07-02)

- [x] **Phase 0 — bash PoC** (`linux/unidiag.sh`): `profile` / `triage` /
      `scan` / `collectors` commands; journald + syslog-file + dmesg +
      docker/podman + k8s collectors with per-distro fallbacks; unified TSV
      event schema; digest (fingerprint preview) and `--json` output.
- [x] **ML concept prototype** (`linux/analysis/unidiag_ml.py`, stdlib-only):
      Drain-lite template mining, SQLite frequency baselines, z-score rate
      anomalies with Poisson floor, gap sessionization into incidents,
      lead-lag precedence, weighted culprit ranking. Validated: synthetic OOM
      cascade pins the kernel kill (not the louder downstream storm); real
      host data collapses 58 events → 15 templates with sane grouping.
- [x] **Plugin architecture**: platform folder (`linux/`, `windows/` later);
      collect / triage / profile plugin kinds with TEMPLATE contracts;
      orchestrator only parses args, loads plugins, renders.
- [x] **Host profiling** (`profile` command): role inference from listening
      sockets + process names (web / database / cache / queue / dns /
      container-host / …) with confidence + evidence; `--json` hints feed
      the analysis layer as causal role priors (database upstream of web).
- [x] **Test harness**: pytest suite (42 tests) covering every ML pipeline
      stage, bash plugins via golden fixtures, CLI behavior, and role
      priors; the OOM-cascade product claim is itself a test. New behavior
      starts with a failing test (see the `xfail` marking A1 idempotency).
- [x] **Event schema spec** (`spec/event-schema.md`): versioned contract
      shared by bash, Python, and the future Rust port; fixtures double as
      the Rust parity suite.

The bash + Python pair is the **spec for the Rust port** — every algorithm
stays simple enough to read and re-implement (see the migration map in
README.md).

---

## Phase A (NEXT) — Data Collection & Preprocessing

**Goal:** a reliable, idempotent pipeline that extracts *historical* data
from the server and keeps collecting continuously, landing clean normalized
events in a durable store. Everything downstream (baselines, correlation,
prediction) is only as good as this foundation — garbage in, garbage
diagnosis.

### A0 — Profile-directed collection (started)

Know what the host *is* before deciding what to collect, so resources go to
relevant sources and origin tracing is faster.

- [x] role inference PoC: ports + process names → roles with evidence
- [x] role hints → causal priors in culprit ranking (`diagnose --profile`)
- [ ] deeper evidence: enabled systemd units, container image names,
      package-manager introspection (dpkg/rpm/apk), /etc fingerprints
- [ ] collection scoping: `scan --focus` uses the profile to prioritize/
      filter origins instead of only advising the human
- [ ] role-aware digest thresholds (workstation noise ≠ server noise)

### A1 — Historical backfill (one-time extraction per host)

- [ ] journald full history: iterate `journalctl --list-boots`, ingest all
      available boots, not just the current one
- [ ] rotated plain logs: `/var/log/*.log.N` and `.gz`/`.xz` (zcat/xzcat),
      oldest-first so fingerprint templates form in chronological order
- [ ] container history: docker/podman `logs` full depth per container,
      including exited containers (`ps -a`); k8s `--previous` container logs
- [ ] idempotent re-ingest: content-hash each event (ts+origin+message) and
      `INSERT OR IGNORE` so backfill can be re-run safely
- [ ] backfill report: coverage summary per source (time range, event count,
      gaps detected)

### A2 — Continuous collection (keep it flowing)

- [ ] cursor-based incremental ingest: `journalctl --after-cursor` persisted
      cursor; byte-offset tracking for plain files (detect truncation and
      rotation); `--since` watermark for container logs
- [ ] scheduler unit: systemd timer *and* plain cron fallback (any-distro
      rule) running `scan --json | ingest` every N minutes
- [ ] triage snapshots as time-series: store disk %, inode %, PSI, fd count,
      conntrack, load per run alongside events — this is the raw material
      for Phase D prediction
- [ ] ingest health self-check: alert when a collector goes silent (the
      collector failing is itself an incident)

### A3 — Preprocessing & normalization

- [ ] clock discipline: everything to UTC epoch at ingest; resolve the
      RFC3164 syslog year/timezone ambiguity (currently a known PoC gap);
      flag unsynced hosts (triage already detects this)
- [ ] per-source severity mapping table (journald priorities, container
      keyword classification, k8s event types) — one documented mapping
- [ ] masking rules v2: k8s pod hash suffixes (`web-7f9c4d-x2k1j` → `web`),
      container IDs, ports, emails, base64 blobs — fingerprints must be
      stable across pod restarts
- [ ] persist template-miner state so fingerprints stay stable across
      ingest runs (currently rebuilt from stored templates — formalize it)
- [ ] multiline collapse: stack traces / panics become one event, not 40

### A4 — Storage schema v1

- [ ] events table with content hash + host dimension (single host now,
      fleet-ready shape)
- [ ] hourly rollups: per-fingerprint counts materialized on ingest — raw
      events expire (default 14d), rollups are kept (they're tiny and are
      the baseline memory)
- [ ] metrics table for triage snapshots (same retention split)
- [ ] schema version + migration stub

**Phase gate:** after 7 days running unattended on one host — no gaps in
coverage, fingerprints stable across restarts, DB size bounded by retention,
and `diagnose` demonstrably sharper than day 1 because baselines matured.

---

## Later phases

### Phase B — Correlation hardening
Topology discovery (procfs, cgroups, container/k8s APIs) so correlation uses
*proximity in the system graph*, not just time; triage metrics join incidents
as first-class events (disk-full can be a culprit); cross-boot correlation.

### Phase C — Resolution packs
YAML signature format (fingerprint match → diagnosis → fix steps → safety
class); starter pack of ~50 common Linux/docker/k8s failures; pack loading,
matching, and a contribution format. Optional LLM fallback for unmatched
incidents — off by default, clearly labeled, never in the remediation path.

### Phase D — Prediction
Slope watchers over the A2 metrics time-series (disk/inode/fd/RSS → "full in
~N days"); per-fingerprint rate baselines with seasonality (hour-of-day,
day-of-week); expiry scans (certs, tokens); alerting (webhook/desktop).

### Phase E — Guarded remediation
Execute pack remediations marked safe: dry-run default, allowlist-gated,
every action journaled, reversible where possible.

### Phase F — Rust port
Single static binary (musl), collectors as traits, embedded SQLite; the bash
and Python prototypes retire to `poc/` as the reference spec. Port order:
schema → collectors → miner → correlator → CLI.

---

## Working agreements

- **Any distro**: no hard systemd/GNU assumptions; every collector has a
  fallback; POSIX flags; busybox-safe.
- **Prototype in bash/Python, target Rust**: keep prototype algorithms
  simple enough to read and re-implement; spec + golden fixtures are the
  parity contract.
- **Profile → triage → scan**: know the host, check the host, then read the
  app layer. Ordering is product, not preference.
- **TDD**: new behavior starts with a failing pytest test; `python3 -m
  pytest` from `universal_diag/` must stay green; upcoming work may be
  marked `xfail` as an executable TODO.
- **Plugins over monolith**: new sources/checks/profilers are NN-name.sh
  files implementing the TEMPLATE contract — never edits to the
  orchestrator.
- **Not a log store**: sliding window + rollups; archival is someone else's
  job.

## Decision log

| Date | Decision |
|------|----------|
| 2026-07-02 | Bash for PoC, Rust as eventual target |
| 2026-07-02 | Must run on any distro — journald→syslog→dmesg fallbacks, docker→podman |
| 2026-07-02 | Host triage runs before app-log analysis, ordering encoded in the tool |
| 2026-07-02 | Analysis layer prototyped in Python, stdlib-only, SQLite store |
| 2026-07-02 | Culprit ranking = onset + precedence + layer prior + severity + anomaly (anomaly alone blames victims) |
| 2026-07-02 | Next phase: Data Collection & Preprocessing (historical backfill + continuous ingest) |
| 2026-07-02 | Platform folders (linux/ now, windows/ later) + plugin architecture: collect / triage / profile kinds with TEMPLATE contracts |
| 2026-07-02 | Host profiling before collection: roles from ports+processes; hints feed causal role priors in ranking |
| 2026-07-02 | TDD with pytest across all components; golden fixtures + spec/event-schema.md double as the Rust parity suite |
