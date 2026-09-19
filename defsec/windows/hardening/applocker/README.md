# AppLocker baseline (Windows 11)

## Executive summary

This is a secure baseline for common, internet-facing Windows 11 endpoints (employee laptops,
shared workstations — any machine a normal, non-technical user logs into and browses the
internet, reads email, and runs everyday software on). It is designed to reduce the primary
attack vectors that target that population specifically:

- **ClickFix scams** — fake CAPTCHA/verification pages that talk a user into pasting and running
  an attacker command via Win+R or a terminal.
- **Phishing attachments** — malicious files delivered via email or web download, executed
  straight from where they land (Outlook's attachment cache, browser cache) before the user ever
  saves or inspects them.
- **Tech-support scams** — fake virus-alert popups and cold calls that talk a victim into
  installing a remote-access tool so a scammer can take over the machine.
- **Disguised executables** — the `invoice.pdf.exe` double-extension trick, relying on Windows
  hiding known file extensions by default.
- **Removable media drops** — "found a USB drive" AutoRun/AutoPlay abuse.

The mechanism is application allowlisting (AppLocker): instead of trying to detect malicious
software after the fact, the policy only allows execution from trusted, administrator-controlled
locations (Program Files, the Windows folder, signed publishers). Anything else — a download, an
attachment, a script pasted into a terminal — is blocked outright, regardless of whether it's
been seen by antivirus signatures before. This is layered with registry-level hardening (file
extension visibility, AutoRun, browser scam-popup blocking, Windows Script Host) for the handful
of attack surfaces AppLocker itself cannot reach (browser tabs, Explorer display settings).

The design is built around two repeatable mechanisms, both covered in full detail below:
**audit-before-enforce** (nothing is ever blocked without first being observed and tuned) and
**rollback** (every change made by this baseline, in whole or by individual module, can be
undone).

---

## Prerequisites

| Requirement | Detail |
|---|---|
| **OS edition** | Windows 11 Pro, Enterprise, or Education. AppLocker does not exist on Windows 11 Home — the cmdlets are absent and this script will not work. |
| **Elevation** | Every command that changes state (`-Remediate`, `-Enforce`, `-Rollback`) requires an **elevated (Run as Administrator) PowerShell session**. Assessment-only runs (no `-Remediate`) work unelevated. |
| **Pester (tests only)** | `Install-Module Pester -MinimumVersion 5.0` — only needed if you run `Invoke-Pester -Path .\test`. |

---

## Layout

| Path | What it is |
|---|---|
| `Invoke-AppLockerBaseline.ps1` | The single entry-point script. All operations go through this. |
| `Invoke-AppLockerBaseline.Functions.ps1` | Pure helper logic (module resolution, XML merging). Dot-sourced by the orchestrator; never call directly. |
| `nsa/` | Vendored NSA AppLocker-Guidance reference files (Windows 11 starter policy, event-log task). Do not hand-edit; re-pull from github.com/nsacyber/AppLocker-Guidance if updates are needed. |
| `modules/` | Pluggable rule and hardening additions. See `modules/README.md` for the full catalog. |
| `test/` | Pester 5 test suite (93 tests). No registry/AppLocker writes; requires an **elevated** session when Script enforcement is active (see Testing section). |
| `docs/` | Detailed reference documents. Start with `docs/dll-enforcement.md` for the Dll collection workflow. |
| `AppLockerReports/` | Created automatically on each `-Remediate` run. Contains backups and `MergedPolicy.xml`. |

---

## How AppLocker enforcement modes work

AppLocker has two modes per rule collection:

| Mode | What it does |
|---|---|
| **AuditOnly** | Logs what *would* be blocked to the AppLocker event logs. **Nothing is actually stopped.** The machine runs normally. |
| **Enabled** (Enforce) | Actually blocks execution of anything not on the allow list. Users see a block message when something is stopped. |

This script always deploys in **AuditOnly first** (with plain `-Remediate`). You then observe the audit log for a period of time to find any legitimate software that would be blocked, add allow rules for it, and only then flip to **Enabled** (with `-Remediate -Enforce`). Skipping the audit phase and going straight to enforce risks blocking software the machine legitimately needs.

---

## What the baseline includes

**NSA Windows 11 starter policy** (`nsa/AppLocker Starter Policy/Windows11_AppLocker Starter Policy.xml`) is the foundation. It already:

- Default-denies execution from anywhere outside Program Files, the Windows folder, and signed installer paths once a rule collection is `Enabled`.
- Explicitly denies execution from the user-writable Windows subfolders attackers use to bypass AppLocker (`%WINDIR%\Temp`, `%WINDIR%\Tasks`, `%SYSTEM32%\spool\drivers\color`, `%SYSTEM32%\Microsoft\Crypto\RSA\MachineKeys`, etc.) — including their NTFS alternate-data-stream (`:*`) variants.
- Denies known LOLBAS binaries and the Microsoft-recommended block list.

**Default modules** add on top of the base policy (all wired in by every `-Remediate` run unless you override `-Modules`):

| Module | What it does | Type |
|---|---|---|
| `ClickFix` | Denies `wscript.exe`, `cscript.exe`, `mshta.exe` (both System32 and SysWOW64). Disables Windows Script Host at the registry level as a backstop. | AppLocker + Registry |
| `PhishingAttachmentGuard` | Denies execution from Outlook's secure attachment cache and every major browser's cache directory (Edge, Chrome, Firefox, IE/legacy Edge). Does **not** block the Downloads folder — that is a legitimate location for intentional downloads. | AppLocker only |
| `RemovableMediaGuard` | Disables AutoRun/AutoPlay for all drive types. | Registry only |
| `ExplorerVisibilityHardening` | Forces Explorer to show known file extensions, defeating the `invoice.pdf.exe` double-extension trick. | Registry only |
| `BrowserScamGuard` | Blocks the browser notification-permission prompt used by fake-virus-alert scam popups. Raises Safe Browsing to Enhanced mode. Covers Edge, Chrome, and Firefox. | Registry/policy only |
| `DefenderCompatibility` | Allows execution from `%OSDRIVE%\ProgramData\Microsoft\Windows Defender\Platform\*` for Exe/Dll/Script. Without this, Defender's own platform binaries (MsMpEng.exe, MPOAV.DLL, etc.) fall outside the base policy's trusted locations and generate continuous audit noise or blocks. | AppLocker only |
| `WindowsAppRepository` | Dll collection only. Allows Microsoft-signed DLLs (O=MICROSOFT CORPORATION) via a **FilePublisherRule** (publisher-verified, not path-based — immune to DLL sideloading by design). Covers packaged app COM proxy DLLs like Windows Terminal's `OpenConsoleProxy.dll` that live under `%OSDRIVE%\ProgramData\Microsoft\Windows\AppRepository\Packages\*` — outside the base policy's Dll allow paths. | AppLocker only |

**Opt-in modules** (pass explicitly with `-Modules` or use `-Modules All`):

| Module | What it does | Why opt-in |
|---|---|---|
| `RunDialogLockdown` | Removes the Win+R Run dialog machine-wide | Affects admins too — real usability trade-off |
| `RemoteAccessToolGuard` | Denies AnyDesk, UltraViewer, TeamViewer QuickSupport, ConnectWise ScreenConnect, Atera, Splashtop, NetSupport Manager by filename | Many orgs use these as their sanctioned RMM tool |
| `OfficeMacroGuard` | Enables Defender ASR rules blocking Office macros from spawning processes or calling Win32 APIs | Requires Defender as active AV; can break legitimate macro automation |

---

## Step-by-step implementation

All commands must be run from an **elevated PowerShell session** for any step that applies changes.

### Step 1 — Assess current state (safe, no changes)

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-AppLockerBaseline.ps1
```

This is a pure read operation. It reports:
- Application Identity service (AppIDSvc) status and startup type — must be running for enforcement to work
- Current local AppLocker policy (rule counts and enforcement mode per collection)
- AppLocker event log sizes
- Whether the popup-alert task is registered
- Status from each wired-in module (WSH state, AutoRun state, etc.)

No system state is changed.

---

### Step 2 — Deploy in Audit mode (REQUIRED before enforcing)

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-AppLockerBaseline.ps1 -Remediate
```

What this does:
1. Starts the Application Identity service (AppIDSvc) if stopped; sets it to Automatic start.
2. Loads the NSA Windows 11 starter policy XML.
3. Merges in rule additions from all default modules (ClickFix deny rules, Defender allow rules, etc.).
4. Writes the merged policy to `AppLockerReports\<HOSTNAME>-<timestamp>\MergedPolicy.xml`.
5. Backs up whatever local AppLocker policy existed beforehand to `PreChange-LocalPolicy.xml` in the same folder.
6. Applies the merged policy via `Set-AppLockerPolicy`. **All five rule collections (Dll, Exe, Msi, Script, Appx) remain in AuditOnly mode** — nothing is blocked.
7. Increases all four AppLocker event log channels to 64 MB.
8. Runs each default module's complementary hardening (disables WSH, sets AutoRun policy, sets Explorer HideFileExt=0, sets browser policies).
9. **Does NOT register the popup-alert task** — that only happens at Step 4 (Enforce), because every audit hit during tuning would otherwise pop up a message box.

After this step: the machine behaves normally. Everything that was running before still runs. The audit logs are now recording what would be blocked once enforcement is on.

---

### Step 3 — Review audit hits and tune

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-AppLockerBaseline.ps1 -ShowAuditHits
```

This reads the AppLocker event logs and shows the top 25 files that would have been blocked, grouped by path and sorted by frequency. A CSV is also written to `AppLockerReports\<HOSTNAME>-<timestamp>\AppLockerAuditHits.csv`.

**Run the machine normally for several days first** before reviewing — the audit log needs real usage to surface legitimate software that would be blocked (line-of-business tools, admin utilities, scripts run by your IT process, etc.).

For anything legitimate that appears in the audit hits:
- Add a publisher-based Allow rule (preferred over path rules — publisher rules survive binary updates and can't be spoofed by renaming a file). Use `Get-AppLockerFileInformation -Path <file>` to find the publisher details.
- Re-run Step 2 with `-Merge` if you want to keep existing custom rules alongside the re-deployed baseline.

**The `DefenderCompatibility` module covers Defender's own files, so you should not see `%OSDRIVE%\ProgramData\Microsoft\Windows Defender\*` in the audit hits after Step 2.**

Repeat Step 2 and Step 3 until the audit log is clean.

---

### Step 4 — Turn on enforcement

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-AppLockerBaseline.ps1 -Remediate -Enforce
```

**You must pass both `-Remediate` AND `-Enforce` together.** `-Enforce` alone does nothing — the script will error and tell you. This is intentional: enforcement is a state change that requires re-importing the policy, and `-Remediate` is what triggers the policy import.

What `-Remediate -Enforce` does differently from plain `-Remediate`:
- Sets the Exe, Msi, Script, and Appx rule collections to `Enabled`. Execution from anything not on the allow list is now **actually blocked**.
- **The Dll rule collection remains in AuditOnly.** DLL allowlisting has a significantly higher risk of breaking legitimate software. Enable it only after the rest of the policy has been running stably in enforce mode for weeks, by adding `-EnableDllRules`:

  ```powershell
  powershell.exe -ExecutionPolicy Bypass -File .\Invoke-AppLockerBaseline.ps1 -Remediate -Enforce -EnableDllRules
  ```

- **Registers the NSA popup-alert scheduled task.** Once enforcement is on, blocks should be rare and actionable — the popup tells the user which file was blocked and gives an Event Record ID for the admin to look up.

---

### Dll enforcement — hold back, observe, then enable

The Dll rule collection is deliberately left in `AuditOnly` even after `-Enforce`. Enabling it outright would risk breaking legitimate applications whose DLL dependencies aren't yet covered by allow rules. The correct workflow is: observe Dll audit hits for weeks, write publisher rules for any gaps, then enable. See **[docs/dll-enforcement.md](docs/dll-enforcement.md)** for the full process including the `Get-AppLockerDllPublisherInfo` helper that generates ready-to-paste FilePublisherRule XML.

To review Dll audit hits:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-AppLockerBaseline.ps1 -ShowAuditHits
```

Once the Dll audit log is clean (weeks, not days):
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-AppLockerBaseline.ps1 -Remediate -Enforce -EnableDllRules
```

### What `-Enforce` does to non-elevated PowerShell

Non-elevated sessions enter **Constrained Language Mode** (ClickFix protection working as intended — paste-and-run payloads lose access to `Add-Type`, COM, and arbitrary .NET). Elevated sessions are unaffected. Run all admin/dev/test PowerShell work from an elevated session. See [docs/dll-enforcement.md](docs/dll-enforcement.md) for detail.

---

### Step 5 — (Optional) Add opt-in modules

The default set already wires in ClickFix, PhishingAttachmentGuard, RemovableMediaGuard, ExplorerVisibilityHardening, BrowserScamGuard, DefenderCompatibility, and WindowsAppRepository. To add opt-in modules:

```powershell
# Add Win+R lockdown on top of the defaults
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-AppLockerBaseline.ps1 -Remediate -Modules ClickFix,PhishingAttachmentGuard,RemovableMediaGuard,ExplorerVisibilityHardening,BrowserScamGuard,DefenderCompatibility,WindowsAppRepository,RunDialogLockdown

# Every available module
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-AppLockerBaseline.ps1 -Remediate -Modules All
```

When passing multiple module names via `powershell.exe -File`, comma-separated values with no spaces work: `-Modules Foo,Bar,Baz`. Spaces are not required.

---

## Rollback

### Full rollback — remove everything

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-AppLockerBaseline.ps1 -Rollback
```

With no `-Modules` specified, this:
1. Clears the local AppLocker policy entirely (sets it to an empty policy — no rules).
2. Disables the popup-alert task.
3. Calls `Invoke-<Name>Rollback -Remediate` on every default module, undoing all registry/OS changes.

### Targeted rollback — undo a single module only

```powershell
# Undo only RunDialogLockdown (restores Win+R)
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-AppLockerBaseline.ps1 -Rollback -Modules RunDialogLockdown
```

When `-Modules` is specified, **only that module's registry/OS changes are undone**. The AppLocker policy is left intact.

### Per-module rollback reference

| Module | What `Invoke-<Name>Rollback -Remediate` undoes |
|---|---|
| `ClickFix` | Removes the WSH `Enabled=0` registry value (re-enables Windows Script Host) |
| `RunDialogLockdown` | Removes `NoRun` policy value; restarts Explorer automatically |
| `RemovableMediaGuard` | Removes `NoDriveTypeAutoRun` policy value |
| `ExplorerVisibilityHardening` | Removes `HideFileExt=0` override from HKCU and Default profile; restarts Explorer automatically |
| `BrowserScamGuard` | Removes Edge/Chrome browser policy values; removes Firefox `policies.json` |
| `OfficeMacroGuard` | Calls `Remove-MpPreference` for both ASR rule GUIDs |
| `RemoteAccessToolGuard` | Removes the `RemoteSupport` local account |
| `PhishingAttachmentGuard` | Policy-only — covered by full rollback (policy clear) |
| `DefenderCompatibility` | Policy-only — covered by full rollback (policy clear) |

### Manual single-module rollback

```powershell
# Example: undo ClickFix only, without touching AppLocker policy or other modules
Import-Module .\modules\ClickFix.psm1
Invoke-ClickFixRollback -Remediate
```

All rollback functions support a **dry run** (omit `-Remediate`) that shows exactly what they would do without changing anything:

```powershell
Invoke-RunDialogLockdownRollback    # shows current NoRun value and what would be removed
```

---

## Re-running and idempotency

Every step is safe to re-run. Re-running `-Remediate` re-imports the (possibly updated) policy, reapplies all module hardening, and creates a new timestamped backup folder. Re-running `-Remediate -Enforce` re-enforces. Re-running `-Rollback` re-clears.

Each `-Remediate` run backs up the prior local policy to `AppLockerReports\<HOSTNAME>-<timestamp>\PreChange-LocalPolicy.xml` before overwriting it.

---

## Testing changes

```powershell
Invoke-Pester -Path .\test
```

The suite (83 tests) covers:
- Unit tests for the pure module-resolution and policy-XML-merge logic (no elevation needed)
- Per-module contract tests: every module imports cleanly, fragments are valid AppLockerPolicy XML, hardening/rollback dry-runs don't throw
- Per-module mocked remediation/rollback tests: registry and cmdlet calls are verified without touching real state
- NSA reference data regression tests: guards against the file-content corruption that hit this repo once (filenames swapped onto wrong content)
- Guarded real E2E orchestrator tests: dry-run and mocked `-Remediate` paths run against the real orchestrator binary

Nothing in the suite writes to the registry or AppLocker. **Elevation is required to run the suite
when the Script collection is Enforced** — Pester itself uses `Add-Type` internally and will fail
to load in a non-elevated session because that session will be in Constrained Language Mode (see
"What to expect after `-Enforce`" above). Run `Invoke-Pester -Path .\test` from an elevated
PowerShell session. Alternatively, roll back to AuditOnly (`-Remediate` without `-Enforce`) to
run the suite unelevated for development purposes, then re-enforce afterward.

---

## Out of scope

The following are separate OS-hardening concerns and belong in their own modules/folders elsewhere in this repo, not here:

- Kiosk mode / Assigned Access (single-app lockdown)
- Unified Write Filter (UWF — session wiping on reboot)
- Browser GPO lockdown beyond what BrowserScamGuard covers (extension blocklists, InPrivate enforcement, file:// URL blocking)
- BIOS/UEFI password and Secure Boot configuration
