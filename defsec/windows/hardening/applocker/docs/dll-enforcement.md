# Dll rule collection: why it's held back and how to safely enable it

## Why `-Enforce` doesn't enable Dll

AppLocker has five independent rule collections: **Dll, Exe, Msi, Script, Appx.** `-Remediate -Enforce` sets Exe, Msi, Script, and Appx to `Enabled`. **Dll is deliberately left in `AuditOnly`** for two reasons:

1. **Blast radius.** Once the Dll collection is Enabled, AppLocker checks every DLL loaded by every process — not just the EXE that started, but every plugin, every .NET assembly, every COM component it pulls in afterward. One missing allow rule for a dependency DLL of an otherwise-allowed application is enough to make that application fail silently or with a confusing error that doesn't obviously point back to AppLocker.

2. **Performance.** DLL loads happen orders of magnitude more often than process starts. Checking every one against the policy adds measurable per-load latency across the whole system.

Dll: AuditOnly means nothing is blocked at the DLL level. Every DLL load is logged (Event ID 8002 = "was allowed to run") but never denied. The Dll rules in the policy are still important even in AuditOnly — they define correct intent and are ready the moment Dll enforcement is turned on.

---

## Step 1: Find the gaps with -ShowAuditHits

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-AppLockerBaseline.ps1 -ShowAuditHits
```

`-ShowAuditHits` now includes a "Dll collection audit hits" section that queries Event ID 8003 ("was allowed to run but would have been prevented from running if the AppLocker policy were enforced") and groups results by parent directory. A CSV is saved to `AppLockerReports\<HOSTNAME>-<timestamp>\AppLockerDllAuditHits.csv`.

To query Dll hits directly at any time:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -eq 8003 } |
    Group-Object { ($_.Message -split ' was allowed')[0] } |
    Sort-Object Count -Descending |
    Select-Object -First 25 Count, Name
```

---

## Step 2: Write publisher rules for each gap

**Publisher rules (FilePublisherRule) are mandatory for the Dll collection wherever possible.** A publisher rule verifies the DLL's digital signature at load time — a malicious DLL placed in an allowed path still fails rule evaluation unless it carries a valid code-signing certificate from the same publisher. Path-based Dll rules are only acceptable when the path is demonstrably non-writable by standard users.

Use `Get-AppLockerDllPublisherInfo` (from `Invoke-AppLockerBaseline.Functions.ps1`) to get the publisher info and a ready-to-paste FilePublisherRule XML fragment for any DLL from the audit hits:

```powershell
# From an elevated PowerShell session
. .\Invoke-AppLockerBaseline.Functions.ps1

# Single file
Get-AppLockerDllPublisherInfo -Path 'C:\Program Files\App\example.dll'

# Multiple files
'C:\Path\A.dll','C:\Path\B.dll' | Get-AppLockerDllPublisherInfo
```

Output fields:
- `SuggestedXml` — ready-to-paste `<FilePublisherRule>` XML, scoped to the exact `BinaryName` (narrow). Widen `BinaryName="*"` to cover all DLLs from that publisher/product.
- `IsSideloadingRisk` — always `$false` for valid-signature DLLs (publisher rules can't be sideloaded). `$true` for unsigned DLLs — only add a path rule if you've confirmed `icacls <path>` shows the directory is not writable by standard users.
- `Note` — recommendation on whether to widen or keep exact.
- `PublisherName` — O=..., L=..., S=..., C=... fields in the AppLocker-expected uppercase format.

Add the resulting rule XML as a `Get-<Name>PolicyFragment` function in a new module under `modules/` (see `modules/README.md` for the contract), add it to your `-Modules` list, and re-run `-Remediate -Enforce`.

### Known gaps already covered by default modules

| Module | What it adds to the Dll collection |
|---|---|
| `DefenderCompatibility` | Path rule for `%OSDRIVE%\ProgramData\Microsoft\Windows Defender\Platform\*` (Exe/Dll/Script) — path-safe because the directory is OS-managed and not user-writable |
| `WindowsAppRepository` | Publisher rule for O=MICROSOFT CORPORATION — covers packaged app COM proxy DLLs (e.g. Windows Terminal's `OpenConsoleProxy.dll`) loaded from the AppRepository path |

---

## Step 3: Enable Dll enforcement only after the audit log is clean

Weeks, not days — Dll activity volume is much higher than EXE activity.

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-AppLockerBaseline.ps1 -Remediate -Enforce -EnableDllRules
```

`-EnableDllRules` has no effect without `-Enforce`, and `-Enforce` has no effect without `-Remediate`. The script validates this and errors immediately with a clear message if you pass them incorrectly.

---

## Constrained Language Mode after Script enforcement

Once the Script rule collection is `Enabled`, every **non-elevated** PowerShell session automatically runs in **Constrained Language Mode** (no `Add-Type`, no arbitrary .NET method calls, no COM object creation). This is the intended protective effect — it removes most of what a ClickFix paste-and-run one-liner needs.

The mechanism: PowerShell writes a disposable self-test script to `%TEMP%\__PSScriptPolicyTest_*.ps1` on startup to determine which language mode to use. `%TEMP%` is explicitly denied by this baseline (standard-user bypass folder), so the probe is blocked and PowerShell falls back to Constrained Language Mode. You will see Event ID 8007 events for these files in the `Microsoft-Windows-AppLocker/MSI and Script` log — this is expected and means the baseline is working.

**Elevated sessions are unaffected** — the base policy's "Allow administrators to run all scripts" rule covers the elevated (admin) token.

**Impact:** Any non-elevated PowerShell workflow — including running this repo's own Pester test suite — will fail or behave unexpectedly. Always run dev/admin/test work from an elevated session when Script enforcement is active. To run tests without enforcement: roll back to `-Remediate` only (AuditOnly) for the session, run tests, then re-enforce afterward.
