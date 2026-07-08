# universal_diag — Windows (planned)

Placeholder for the Windows implementation. Not started; Linux is the
proving ground (see [../ROADMAP.md](../ROADMAP.md)).

The plugin architecture mirrors `linux/`:

- collect plugins: Windows Event Log (System/Application/Security),
  ETW providers, container logs (Docker Desktop / containerd), IIS logs
- triage plugins: same diagnostic-value ordering — kernel/hardware (WHEA,
  disk, memory diagnostics) → saturation (memory/commit charge, CPU queue)
  → capacity (disk, handles) → network → platform (failed services, time
  sync)
- events normalize to the same schema: [../spec/event-schema.md](../spec/event-schema.md)
  — the analysis layer and the eventual Rust core are platform-agnostic by
  construction; only collectors and triage checks are per-platform.
