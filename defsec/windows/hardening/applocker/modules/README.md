# AppLocker baseline modules

Each module is a single PowerShell script module (`.psm1`) dropped in this folder.
`Invoke-AppLockerBaseline.ps1` discovers them automatically and wires them into the run via
`-Modules` (default: a curated set - see `$DefaultModules` in the orchestrator).

Modules let the baseline grow (new scam patterns, new LOLBAS abuse, org-specific rules) without
editing the orchestrator itself.

## Contract

A module name is its file's base name, e.g. `ClickFix.psm1` -> module name `ClickFix`. It may
export any of the following functions - all optional, all called by convention name:

| Function                        | Phase            | Called                          | Returns |
|----------------------------------|------------------|---------------------------------|---------|
| `Get-<Name>Status`               | assessment       | every run                       | zero or more strings/objects to print under the module's status section |
| `Get-<Name>PolicyFragment`       | policy build     | `-Remediate` only, before import | zero or more objects: `@{ CollectionType; Name; Xml }` |
| `Invoke-<Name>Hardening`         | hardening        | `-Remediate` only, after import | accepts `-Remediate` switch; zero or more strings describing what it did |
| `Invoke-<Name>Rollback`          | rollback         | `-Rollback` only                | accepts `-Remediate` switch; zero or more strings describing what it undid |

Policy-only modules (`PhishingAttachmentGuard`, `DefenderCompatibility`) do not need a Rollback
function - their contribution is AppLocker rules that are removed by the orchestrator's
`-Rollback` path (which clears the whole local policy). Only modules with registry/OS-level side
effects need a Rollback function.

### `Get-<Name>PolicyFragment` return shape

Each item must be a hashtable/object with:

- `CollectionType` - one of `Dll`, `Exe`, `Msi`, `Script`, `Appx` (which AppLocker rule
  collection to merge the rule into).
- `Name` - short human-readable label, used only for the "merging rule '...'" log line.
- `Xml` - a single well-formed `<FilePathRule>` or `<FilePublisherRule>` (with its
  `<Conditions>`) as a string, exactly as it would appear inside a `<RuleCollection>` in an
  AppLockerPolicy XML document. Give it a real GUID `Id` and a `Description` explaining *why*
  the rule exists (what attack/scam it addresses), since that description is what an admin
  reviewing Local Security Policy will actually see.

### Guidelines

- **Modules must be additive and independently skippable.** `-Modules @()` (wire in nothing)
  must still leave a working, importable baseline policy.
- **Don't deny anything without a specific, named threat.** Every deny rule should map to a
  documented attack technique (cite it in the rule's `Description`), not "seems risky."
- Prefer `Action="Deny"` over trying to be clever with allow-list precision; AppLocker is
  default-deny per collection once a collection is `Enabled`, so most modules only need to add
  *extra* denies for things the base allow rules (Program Files / Windows / signed publishers)
  would otherwise let through.
- `Invoke-<Name>Hardening` changes should be reversible and scoped to the module's stated threat
  (e.g. a registry value, not a sweeping policy). Document the trade-off in the module's
  comment-based help if the control affects usability (see `RunDialogLockdown.psm1`).

## Modules in this folder

### Default-on (wired into every `-Remediate` run unless overridden)

- **ClickFix.psm1** - targets the "paste this into Run / a terminal to fix the problem"
  social-engineering pattern (fake CAPTCHA/verification pages, fake error dialogs, fake
  driver/update fixes) that overwhelmingly catches ordinary, non-technical users rather than
  attackers targeting admins directly. Adds explicit AppLocker denies for the Windows Script Host
  engines (`wscript.exe`, `cscript.exe`) and `mshta.exe` that these lures typically chain into,
  and disables the Windows Script Host engine at the registry level as defense-in-depth (it still
  stops a `.vbs`/`.js` payload even if AppLocker is ever misconfigured or bypassed).

- **PhishingAttachmentGuard.psm1** - denies execution from Outlook's secure attachment temp
  folder and the on-disk cache for Internet Explorer/legacy Edge, Edge (Chromium), Chrome, and
  Firefox - locations nobody ever deliberately saves to or runs from, so the deny has no
  legitimate-use collateral. Deliberately does **not** cover the Downloads folder: that's where
  every browser and webmail provider saves a deliberate, legitimate download, and a blanket deny
  there would block normal installer use far more often than it would catch an attack. Policy-only,
  no registry changes.

- **RemovableMediaGuard.psm1** - disables AutoRun/AutoPlay for all drive types, closing the
  "found a USB drive" prompt-to-run vector. Registry-only, no AppLocker rules.

- **ExplorerVisibilityHardening.psm1** - forces Explorer to show known file extensions, defeating
  the `invoice.pdf.exe` double-extension disguise. Registry-only, no AppLocker rules.

- **BrowserScamGuard.psm1** - blocks the browser notification-permission prompt that's the actual
  delivery mechanism behind most "your PC has a virus, call this number" popups (once granted, a
  malicious site can push OS-style alerts indefinitely, even after the tab is closed), and raises
  Safe Browsing / phishing-protection to its strict setting. Covers Edge, Chrome, and Firefox via
  their respective enterprise policy mechanisms. Registry/policy-file only, no AppLocker rules.

- **DefenderCompatibility.psm1** - not a threat-targeted module like the others; it's a
  correctness fix for the base policy's blind spot. Microsoft Defender's own platform binaries
  (MsMpEng.exe, MPOAV.DLL, etc.) install under `%OSDRIVE%\ProgramData\Microsoft\Windows
  Defender\Platform\<version>\`, outside the locations the base policy trusts, so without this
  AppLocker audits/blocks Defender's own components continuously - including popping up the
  block-notification message for every scan/signature update once `-Enforce` is on. Allow-lists
  exactly that Platform subfolder (not all of ProgramData) for Exe/Dll/Script. Policy-only, no
  registry changes.

- **WindowsAppRepository.psm1** - Dll collection only. Allows Microsoft-signed DLLs
  (O=MICROSOFT CORPORATION) via a FilePublisherRule. Closes the gap for packaged app component
  DLLs (Windows Terminal's `OpenConsoleProxy.dll`, etc.) loaded from
  `%OSDRIVE%\ProgramData\Microsoft\Windows\AppRepository\Packages\*` — outside the base Dll
  collection's path-based allow rules. Uses a publisher rule, not a path rule, so it cannot be
  exploited for DLL sideloading: the binary must carry a valid Microsoft code-signing certificate,
  not just exist at a matching path. The NSA base policy's specific Deny rules for vulnerable
  Microsoft DLLs (System.Management.Automation.dll etc.) still take precedence since Deny always
  beats Allow in AppLocker. Policy-only, no registry changes.

### Opt-in (pass explicitly via `-Modules`, or `-Modules All` for everything)

- **RunDialogLockdown.psm1** - removes the Win+R "Run" dialog, the single most common delivery
  mechanism for ClickFix-style scams. Opt-in because it also removes a dialog legitimate
  admins/power users rely on.

- **RemoteAccessToolGuard.psm1** - denies remote-access/RMM tools by filename anywhere on disk,
  covering two related patterns: consumer tech-support scams (AnyDesk, UltraViewer, TeamViewer
  QuickSupport - "let us connect to fix your computer") and the CISA-documented pattern of
  legitimate RMM software (ScreenConnect, Atera, Splashtop, NetSupport Manager) abused by
  ransomware actors as an initial-access/persistence tool. Opt-in - and check carefully before
  enabling, since several of the RMM entries are the actual sanctioned tool for many MSPs/IT
  departments; remove the specific entry that conflicts rather than skipping the whole module.
  AppLocker can only gate whether a binary runs, not
  whether a running remote-access session is "view only" - that's a feature the tool itself would
  need to offer. For genuine support, prefer Microsoft Quick Assist (already allowed, and its
  control actions still go through normal Windows UAC consent). If a vendor mandates a denied
  tool anyway, the module also exports `Enable-RemoteAccessToolGuardSupportSession` /
  `Disable-RemoteAccessToolGuardSupportSession`, which stand up a disposable, non-administrator
  local account so the session is confined to what that limited account can reach, regardless of
  the tool's own control mode - see the module's `.NOTES` for the full workflow.

- **OfficeMacroGuard.psm1** - enables the two Microsoft Defender ASR rules that stop an Office
  macro from spawning a process or calling Win32 APIs directly (the "enable macros to view this
  document" phishing chain - a gap AppLocker itself can't see into, since the Office app doing the
  spawning is already fully trusted). Opt-in because it requires Defender to be the active AV.

## Writing a new module

1. Create `modules/<Name>.psm1`.
2. Export whichever of `Get-<Name>Status`, `Get-<Name>PolicyFragment`, `Invoke-<Name>Hardening`
   apply, via `Export-ModuleMember -Function ...`.
3. Add it to `test/Modules.Tests.ps1` coverage runs automatically (it iterates every `.psm1` in
   this folder) - no test changes needed unless the module needs its own dedicated assertions.
4. Decide whether it belongs in the orchestrator's `$DefaultModules` (safe to apply unprompted)
   or stays opt-in (meaningful usability trade-off, like `RunDialogLockdown`).
