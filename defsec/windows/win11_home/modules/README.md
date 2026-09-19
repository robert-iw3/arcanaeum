# Home baseline modules

Each module is a single PowerShell script module (`.psm1`) dropped in this folder.
`Invoke-HomeBaseline.ps1` discovers them automatically and wires them into the run via
`-Modules` (default: the curated set - see `$DefaultModules` in the orchestrator).

Modules let the baseline grow (new LOTL techniques, new bloat, org-specific containment)
without editing the orchestrator itself.

## Contract

A module name is its file's base name, e.g. `ScriptHostGuard.psm1` -> module name
`ScriptHostGuard`. It may export any of the following functions - all optional, all called by
convention name:

| Function                  | Phase      | Called                | Returns |
|---------------------------|------------|-----------------------|---------|
| `Get-<Name>Status`        | assessment | every run             | zero or more strings to print under the module's status section |
| `Invoke-<Name>Hardening`  | hardening  | `-Remediate` only     | accepts `-Remediate` switch; zero or more strings describing what it did (or would do, on a dry run) |
| `Invoke-<Name>Rollback`   | rollback   | `-Rollback` only      | accepts `-Remediate` switch; zero or more strings describing what it undid |

Unlike the applocker baseline there is **no PolicyFragment phase** - there is no central policy
document here. Every module owns its changes end to end, which also means every module with a
Hardening function MUST ship a matching Rollback function (status-only modules like
`SmartAppControlAudit` are exempt).

### Guidelines

- **Dry run is the default.** `Invoke-<Name>Hardening` and `Invoke-<Name>Rollback` must change
  nothing unless `-Remediate` is passed, and the dry-run output must say exactly what would
  happen (prefix with `(dry run)`).
- **Don't harden anything without a specific, named threat.** Every control should map to a
  documented post-exploitation technique, named in the module's comment-based help - not
  "seems risky."
- **Respect the balance.** If a control can break printing, external storage, NAS access,
  gaming, or casting for a normal household, it is opt-in (like `NtlmEgressGuard`) or a
  parameter on a direct module call (like `-IncludeCurl`/`-IncludeXbox`) - never default-on.
  Document the trade-off in the module help.
- **Both engines.** Code must run on Windows PowerShell 5.1 and PowerShell 7+ (no ternary/`??`,
  no 3-argument `Join-Path`; Appx/Dism need the `-UseWindowsPowerShell` fallback on 7 - see
  `Import-DebloatCompatModule` for the pattern).
- **Prefer mechanisms user-mode tampering can't reach** (firewall/WFP, PPL, disabled engines)
  over detection-dependent ones where a choice exists.

## Modules in this folder

### Default-on (wired into every `-Remediate` run unless overridden)

- **ScriptHostGuard.psm1** - disables Windows Script Host engine-wide and points the
  double-click association for every WSH script type (and `.hta`) at Notepad. The Home-edition
  substitute for the applocker baseline's Script-collection and mshta/wscript/cscript denies.

- **LolbinEgressGuard.psm1** - outbound-block firewall rules for the signed inbox binaries
  used as download cradles and C2 callbacks (mshta, wscript, cscript, certutil, certreq,
  bitsadmin, regsvr32). Kernel-level WFP enforcement, so it keeps working when Defender is
  evaded or user-mode ETW/AMSI is patched. `-IncludeCurl` extends it to curl.exe.

- **CredentialTheftGuard.psm1** - LSA Protection (`RunAsPPL=1`): LSASS becomes a Protected
  Process Light and user-mode credential dumping (the step before every lateral move) fails,
  even from an elevated process.

- **NameResolutionGuard.psm1** - disables LLMNR, NetBIOS broadcast resolution (P-node), and
  WPAD auto-discovery: the three protocols Responder-class tools poison to harvest NTLM
  credentials from a compromised network. Leaves mDNS alone (printers/casting).

- **RemoteServiceGuard.psm1** - stops and disables WinRM and Remote Registry, the built-in
  remote-management channels lateral movement rides in on. Leaves Print Spooler, file sharing,
  and Quick Assist alone.

- **ExplorerVisibilityHardening.psm1** - forces Explorer to show known file extensions,
  defeating the `invoice.pdf.exe` double-extension disguise. Same control as the applocker
  module of the same name, carried here because Home can't run that orchestrator.

- **PhishingAttachmentGuard.psm1** - the registry replacement for the applocker module's
  "deny execution from Outlook/browser cache" path rules. Forces the Attachment Manager to
  preserve the Mark-of-the-Web on downloads/attachments (`SaveZoneInformation=2`), always
  AV-scan them, and treat unknown file types as high-risk - so a payload can't shed its
  untrusted marking to slip past SmartScreen/Defender. Blocks nothing outright (no legitimate-
  file collateral).

- **BrowserScamGuard.psm1** - ported from the applocker baseline (policy/registry-only there).
  Blocks the browser notification-permission prompt behind most "your PC has a virus" scam
  popups and raises Safe Browsing to Enhanced across Edge, Chrome, and Firefox.

- **RemovableMediaGuard.psm1** - ported. Disables the AutoRun/AutoPlay *prompt* for all drive
  types (the "found a USB - run setup.exe?" vector) while leaving storage fully usable - the
  balanced version of "USB hardening". Matches STIG WN11-CC-000190.

- **Debloat.psm1** - removes retired/promotional preinstalled apps (all reinstallable from the
  Store), disables silent promoted-app installs and Start suggestions, the advertising ID, and
  the Widgets feed, and removes the deprecated WMIC capability (a LOTL execution primitive).
  Keeps Store, Phone Link, media apps, Weather, Quick Assist, and Xbox (`-IncludeXbox` to
  remove Xbox too).

- **SmartAppControlAudit.psm1** - status-only. Reports whether Smart App Control (the built-in
  WDAC allowlisting layer, Windows' own AppLocker substitute for Home) is On / Evaluation /
  permanently Off, and what your options are in each state. No Hardening function on purpose:
  SAC cannot be enabled by script once off - only a reset re-arms it.

### Opt-in (pass explicitly via `-Modules`, `-Modules All`, or enable in `config.ini`)

- **RunDialogLockdown.psm1** - ported. Removes the Win+R Run dialog (a common ClickFix delivery
  path) machine-wide. Opt-in: also removes Run for admins/power users.

- **OfficeMacroGuard.psm1** - ported. Enables the two Defender ASR rules that stop an Office
  macro from spawning a process or calling Win32 APIs. Opt-in: needs Defender as active AV and
  can break legitimate macro automation. (The Defender STIG already sets these on Home if you
  run the `stig\` layer.)

- **RemoteAccessToolGuard.psm1** - the registry replacement for the applocker module's
  `*\<tool>.exe` denies. Blocks known remote-access/RMM tools by filename using an Image File
  Execution Options "Debugger" redirect (launching the tool runs a no-op instead), matching
  AppLocker's leaf-filename semantics. Also exports the confined non-admin
  `Enable/Disable-RemoteAccessToolGuardSupportSession` fallback for genuine support. Opt-in:
  several listed tools are the sanctioned RMM for many IT departments - edit
  `$KnownRemoteAccessTools` before enabling.

- **NtlmEgressGuard.psm1** - denies all outgoing NTLM authentication
  (`RestrictSendingNTLMTraffic=2`), killing challenge-response capture and relay outright.
  Opt-in because NTLM-only NAS boxes, older printers/scanners, and some VPNs break; the module
  help documents the audit-first workflow (value 1 + the NTLM operational event log).

## Writing a new module

1. Create `modules/<Name>.psm1` with comment-based help naming the attack technique it cuts off.
2. Export whichever of `Get-<Name>Status`, `Invoke-<Name>Hardening`, `Invoke-<Name>Rollback`
   apply, via `Export-ModuleMember -Function ...`.
3. `test/Modules.Tests.ps1` picks it up automatically (it iterates every `.psm1` here) for the
   contract checks; add a dedicated `Describe` block asserting the exact registry/firewall/
   service calls with mocks.
4. Decide whether it belongs in the orchestrator's `$DefaultModules` (no collateral for a
   normal household) or stays opt-in (real usability trade-off, like `NtlmEgressGuard`).
