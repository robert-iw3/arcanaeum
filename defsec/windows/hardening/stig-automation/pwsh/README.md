# Windows STIG Automation (layered)

PowerShell automation for applying DISA STIG baselines to Windows hosts in **graduated layers**
instead of one monolithic blast. Each control is tagged with a **Section** (control type) and a
**Severity** (criticality), so you choose how much to apply.

## Layout

```
pwsh/
├─ Invoke-StigHardening.ps1            # orchestrator: discover host -> assess -> remediate -> reassess
├─ python_parser/                      # XCCDF -> PowerShell script generator
└─ tests/                              # Pester tests, one file per script
```

## Orchestrator (recommended entry point)

```powershell
# Safe dry run - discover host, back up, assess only, write reports/CSV. No changes.
.\Invoke-StigHardening.ps1

# Apply only High+Medium across the default sections, then reassess
.\Invoke-StigHardening.ps1 -Remediate -Severity High,Medium

# Apply just two layers
.\Invoke-StigHardening.ps1 -Remediate -Section AuditPolicy,UserRights
```

What it does, in order:

1. **Self-discovery** – hostname, FQDN, IPv4, make/model, serial, OS caption/version/build,
   architecture, product type, domain status. Picks the matching baseline (Win11 / 2022 / 2025).
2. **Backup** – `reg export` of HKLM\SOFTWARE, HKLM\SYSTEM, HKCU\Software; `secedit /export`
   of local security policy; `auditpol /backup`; plus `RECOVERY-README.txt`.
3. **Assess (dry run)** → `assessment-pre.csv`.
4. **Remediate** (only with `-Remediate`, after a confirmation unless `-Force`)
   → `remediation-applied.csv`.
5. **Re-assess** → `assessment-post.csv`.
6. **Report** – `STIG-Report.txt` (system-details header + before/after table),
   `system-details.csv` / `.json`.

Reports land in `.\StigReports\<HOSTNAME>-<timestamp>\`.

## Sections (control types) — Win11

| Section          | What it covers                                                        | Default |
|------------------|----------------------------------------------------------------------|:-------:|
| `AccountPolicy`  | Password/lockout policy, disable Guest                               | ✓ |
| `UserRights`     | User-rights assignments (secedit privileges)                         | ✓ |
| `AuditPolicy`    | Advanced audit policy subcategories (auditpol)                       | ✓ |
| `SecurityOptions`| LSA/NTLM/SMB/Netlogon/UAC security options (HKLM)                    | ✓ |
| `ComputerConfig` | Admin-template/registry hardening (HKLM)                             | ✓ |
| `System`         | Disable SMBv1 + PowerShell v2 features, Secondary Logon, remove Copilot | ✓ |
| `Domain`         | Domain-only controls (Hardened UNC paths, deny batch/service, etc.)  | opt-in |
| `DoD`            | DoD-specific (FIPS mode, logon legal banner)                         | opt-in |
| `Restrictive`    | Breaks common laptop use (deny webcam, disable Bluetooth, rename accts) | opt-in |

Use `-Section All` to include the opt-in layers.

## Severity (criticality)

`High`, `Medium`, `Low` — all on by default. Example: `-Severity High` applies only the
high-impact items.

## Per-script usage

Every script also runs standalone and supports `-Remediate`, `-Section`, `-Severity`,
`-ListRules`, and `-PassThru` (the orchestrator uses `-PassThru` to collect results):

```powershell
.\win11\Windows11-STIG-Computer-V2R7.ps1 -ListRules -Section AuditPolicy
.\win11\Windows11-STIG-Computer-V2R7.ps1 -Severity High -Remediate
```

## python_parser/ — drafting a new STIG script from a DISA XCCDF XML

Given an official DISA "Manual" XCCDF benchmark (the XML files in this directory's
root), `python_parser/runner.py` drafts a starting-point PowerShell script + `.ini`
RulesFile in the same shape as win11/server2022/server2025, instead of hand-transcribing
every control:

```powershell
python python_parser\runner.py -i U_MS_Windows_Server_DNS_STIG_V2R4_Manual-xccdf.xml -o dns\
```

Each control gets `VID`/`Title`/`Severity`/`Description` filled in from the XCCDF. Controls
that reduce to a single queryable value the engine already knows how to evaluate —
`Registry`, `UserRight`, or `AuditPolicy` (see `python_parser/classify.py`) — are fully
drafted and ready to run. Everything else (account policy, service/feature checks, zone
or role-level config, organizational/documented-procedure checks) is emitted as a
commented-out `# TODO [V-...]` block with the full check-content, for a human to classify
and finish. Search a generated script for `# TODO [V-` to find what's left.

`Registry` rules leave `Expected` as a TODO placeholder on purpose — free-text
`Value: 0x...(n)` parsing is failure-prone (ranges, SDDL strings, multi-value checks), and
a hardening tool shouldn't guess at the value a human must remediate to.

Run `python python_parser\generate_ps1_rules.py <xccdf.xml> <out.ps1.partial> [out.ini]`
directly if you just want the rules-array body without the full script shell, or
`python python_parser\xccdf_parser.py <xccdf.xml> <out.json>` to inspect the raw parsed
data.

## Not automated (manual / firmware)

TPM, UEFI/Secure Boot, BitLocker + PIN, AppLocker, DoD root certificates, NTFS/share/registry
ACLs, and IE removal are **not** set here — they require firmware, disk, or human action and
cannot be driven by registry/secedit/auditpol. Run elevated. Reboot after remediation.
