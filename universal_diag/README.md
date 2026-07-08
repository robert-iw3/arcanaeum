# universal_diag

Universal diagnostic tool: collect and correlate warn+ errors from anything
running on a host (bare metal, Docker/podman, Kubernetes), triage the host
before the apps, pinpoint culprits — not just anomalies — and eventually
predict failures before they fire. See [ROADMAP.md](ROADMAP.md) for intent,
end state, and phase tracking.

Current stage: **proof of concept** — bash collectors + Python analysis,
structured so the Rust port is a translation, not a redesign.

## Layout

```
universal_diag/
├── ROADMAP.md               planning guide: intent, end state, phases, decisions
├── spec/
│   └── event-schema.md      THE contract: event shape, severity mapping,
│                            masking tokens, fingerprint definition (v1)
├── linux/                   Linux implementation (windows/ comes later)
│   ├── unidiag.sh           orchestrator: args, plugin loader, rendering only
│   ├── lib/core.sh          shared helpers, portability shims, plugin loader
│   ├── plugins/
│   │   ├── collect/         one plugin per log source
│   │   │   ├── 10-journald.sh     systemd journal (incl. kernel ring)
│   │   │   ├── 20-syslog.sh       /var/log fallback for non-systemd hosts
│   │   │   ├── 30-container.sh    docker or podman
│   │   │   ├── 40-kubernetes.sh   cluster warning events
│   │   │   └── TEMPLATE.sh        contract + how to add a collector
│   │   ├── triage/          host health checks, run in diagnostic-value order
│   │   │   ├── 10-kernel.sh       ring buffer: OOM/MCE/IO/fs/thermal
│   │   │   ├── 20-saturation.sh   memory, swap, PSI, load
│   │   │   ├── 30-capacity.sh     disk, inodes, file descriptors
│   │   │   ├── 40-network.sh      link state, error rates, conntrack
│   │   │   ├── 50-platform.sh     failed units, zombies, clock sync
│   │   │   └── TEMPLATE.sh        contract + how to add a check
│   │   └── profile/         what IS this host? directs collection + priors
│   │       ├── 10-roles.sh        roles from listening ports + processes
│   │       └── TEMPLATE.sh        contract + how to add a profiler
│   ├── analysis/
│   │   ├── unidiag_ml.py    fingerprint → baseline → anomaly → correlate → diagnose
│   │   └── plugins/         analysis plugins (application-specific knowledge)
│   └── tests/               pytest suite + golden fixtures
└── windows/                 future platform port (Event Log/ETW collectors)
```

## Quickstart

Order encodes methodology: know the host → check the host → read the apps.

```sh
linux/unidiag.sh profile             # what is this host? roles + collection focus
linux/unidiag.sh triage              # host health before app logs — always
linux/unidiag.sh scan --since 2h     # unified warn+ timeline
linux/unidiag.sh scan --digest       # collapsed into distinct patterns
linux/unidiag.sh collectors          # what was detected on this host

# analysis layer (stdlib-only Python)
linux/unidiag.sh scan --since 1d --json | linux/analysis/unidiag_ml.py ingest
linux/unidiag.sh profile --json > profile.json
linux/analysis/unidiag_ml.py anomalies                    # rate spikes vs. history
linux/analysis/unidiag_ml.py diagnose --profile profile.json  # ranked culprits,
                                                          # role-aware priors
linux/analysis/unidiag_ml.py demo        # synthetic OOM-cascade walkthrough
```

## Development: TDD

Everything testable has a pytest test; new behavior starts with a failing
test (see the `xfail` in `test_ingest.py` marking the next Phase A
deliverable). Run from this directory:

```sh
python3 -m pytest
```

The suite covers the ML pipeline stage by stage (masking, template mining,
baselines, sessionization, precedence, end-to-end culprit ranking) and the
bash components via subprocess (plugin TSV contract against golden fixtures
in `linux/tests/fixtures/`, CLI behavior). The core product claim is itself
a test: `test_oom_cascade_culprit_is_kernel_not_storm`.

## Rust migration map

The PoC is shaped so the port is mechanical. Fixtures and the schema spec
carry over as-is; cargo tests must reproduce the golden TSV byte-for-byte.

| PoC artifact | Rust counterpart |
|---|---|
| `spec/event-schema.md` | `Event` struct + serde; the spec stays the source of truth |
| `lib/core.sh` plugin loader | `Collector` / `TriageCheck` traits + registry |
| `plugins/collect/*.sh` | one `impl Collector` per source (journald via libsystemd or journalctl exec) |
| `plugins/triage/*.sh` | one `impl TriageCheck` each; /proc + /sys reads become direct file reads |
| `unidiag_ml.py` TemplateMiner | `drain`-style miner module (same masks, threshold 0.55, same sha1 fp) |
| `unidiag_ml.py` baselines/anomaly | same math; SQLite via rusqlite, identical schema |
| `unidiag_ml.py` sessionize/precedence/ranking | same algorithms, same weights |
| `linux/tests/` + fixtures | cargo integration tests consuming the same `fixtures/` files |

Porting order (ROADMAP Phase F): schema → collectors → miner → correlator → CLI.

## Adding a plugin

Copy the `TEMPLATE.sh` in `plugins/collect/` or `plugins/triage/` to
`NN-<name>.sh` and implement the two functions documented there. The
numeric prefix is load/run order. Collection plugins emit schema-v1 TSV;
triage plugins print `verdict` lines. Nothing else to register.
