# unidiag event schema — v1

The one contract that makes "universal" real. Every collector emits this
shape; the analysis layer and resolution packs consume it; **the Rust port
must reproduce it byte-for-byte** (the pytest golden fixtures in
`linux/tests/fixtures/` are the parity test suite — reuse them in cargo
tests).

## Canonical event

| field    | type   | rules |
|----------|--------|-------|
| ts       | string | UTC ISO-8601 with milliseconds: `2026-07-02T14:02:11.480Z`. Lexicographic sort MUST equal time sort — this is how multi-source merge works without parsing. Syslog RFC3164 fallback may emit local time without `Z` (known v1 gap, ROADMAP A3). |
| severity | enum   | `crit` \| `error` \| `warn`. Nothing below warn enters the pipeline (filtered at the edge). |
| source   | string | collector/layer name: `journald`, `kernel`, `syslog`, `docker`, `podman`, `k8s`, … Drives the layer prior in culprit ranking. |
| origin   | string | producing unit: systemd unit, container name, `namespace/pod`, syslog tag. `-` when unknown. |
| message  | string | free text; tabs and newlines replaced with spaces. |

## Wire forms

**TSV** (collector output, one event per line — bash plugins emit this):

    ts<TAB>severity<TAB>source<TAB>origin<TAB>message

**JSON** (`scan --json`, analysis ingest; one object per event, stream may be
JSONL or concatenated pretty-printed objects):

    {"ts": "...", "severity": "...", "source": "...", "origin": "...", "message": "..."}

## Severity mapping (per source)

| source            | mapping |
|-------------------|---------|
| journald          | PRIORITY 0–2 → crit, 3 → error, 4 → warn (5+ filtered at query) |
| container/syslog  | keyword classification on lowercased message, first match wins: `fatal\|panic\|critical\|emerg` → crit; `error\|failed\|failure\|refused\|denied\|exception\|traceback` → error; `warn` → warn; no match → dropped |
| k8s events        | `type=Warning` → warn |

## Masking tokens (fingerprinting)

Applied in this order before template mining; these strings are reserved:

1. UUIDs → `<uuid>`
2. IPv4 (optionally `:port`) → `<ip>`
3. `0x…` hex literals → `<hex>`
4. bare hex strings 12–64 chars → `<hash>`
5. filesystem paths → `<path>` (analysis layer only in v1)
6. remaining digit runs → `<n>`
7. template-mining wildcard for diverging token positions → `<*>`

## Fingerprint

`fp = sha1(source + "|" + template)[:12]` where `template` is the masked,
Drain-clustered token sequence (similarity threshold 0.55, bucketed by
source + token count + first token). Fingerprints must be stable across
runs and across pod/container restarts — that is the whole point.

## Compatibility promise

- v1 fields are never renamed or reordered; new fields append (TSV) or add
  keys (JSON).
- Schema version bumps get a new file (`event-schema-v2.md`) and a migration
  note; collectors declare the version they emit.
