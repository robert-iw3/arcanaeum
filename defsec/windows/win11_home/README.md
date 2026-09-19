# Windows 11 Home hardening baseline — for users who click first and think later

## Executive summary

This is a security baseline for the person most malware is actually written for: a **non-technical
Windows 11 Home user** who opens the email attachment, pastes the "run this to fix your PC"
command, clicks *Allow* on the popup, and installs what a website told them to — without pausing
to evaluate any of it. You can't reliably train that instinct away, so this baseline is built on a
blunt assumption instead:

> **Assume the click happens. Assume a payload lands. Make it not matter** — stop the attacker
> from doing the *next* thing (fetching the real malware, stealing credentials, moving to other
> devices, encrypting the family photos).

That "next thing" is the **pivot**, and it's where an attacker turns one careless click into a
real compromise. Everything here is chosen to break the pivot using mechanisms that keep working
even when Defender doesn't flag anything — while being carefully **balanced so a normal household
computer still works**: the printer prints, the external drive mounts, the NAS is reachable, games
run, banking sites load, and video calls connect.

It works on **every Windows 11 edition, including Home**, where AppLocker isn't available.

**What it stops the attacker from doing after the click:**

- **Fetch the next stage / call home.** Living-off-the-land download cradles (`mshta https://...`,
  `certutil -urlcache`, `bitsadmin /transfer`, `regsvr32 /i:https://...`, WSH downloaders) are
  signed Microsoft binaries doing "legitimate" things — Defender routinely doesn't surface them.
  This baseline blocks their **network egress at the kernel** and disables the script engines, so
  the cradle can't reach its payload or C2.
- **Run the payload at all.** Script-host lures, disk-image (`.iso`/`.vhd`) smuggling that bypasses
  Mark-of-the-Web, double-extension disguises, bad-reputation installers, and Office/macro chains
  are shut at the point of execution.
- **Steal credentials to move laterally.** LSASS runs as a Protected Process Light, so even a
  full-admin attacker can't dump it from user mode.
- **Abuse the admin account.** UAC is turned up to prompt on the secure desktop with Admin Approval
  Mode, so the silent auto-elevation malware relies on stops working.
- **Poison the network / pivot to other devices.** LLMNR/NetBIOS/WPAD poisoning is cut off, and the
  remote-management channels (WinRM, Remote Registry) nothing at home uses are disabled.
- **Reach a malicious destination.** An optional filtering resolver makes phishing/malware/C2
  domains fail before the browser or a cradle ever connects.
- **Encrypt the personal files.** Optional ransomware containment plus a recovery path.

It also **shrinks the attack surface up front** — removing out-of-box bloat (retired apps, ad-driven
content channels, silent promoted-app installs, Widgets, the advertising ID, the WMIC LOLBin) so
there's less for an adversary to hide in.

Everything is Windows PowerShell 5.1 **and** PowerShell 7+ native, registry/firewall/service/Appx
based (no third-party tools), driven from a documented `config.ini`, fully rollback-able per module,
dry-run by default, and it writes a Markdown report of everything it covered after each run.

---

## How this layers with the rest of the repo

| Layer | Directory | Editions | What it contributes |
|---|---|---|---|
| 1 | `stig\` | all (registry/secedit/auditpol work on Home) | DISA STIG: account/audit policy, Defender AV + **ASR rules**, PowerShell script-block logging + transcription, SMB signing, NTLMv2-only, WDigest off, SmartScreen, WinRM auth hardening, SMBv1/PSv2 removal |
| 2 | **`home\` (this)** | **all, incl. Home** | Post-compromise containment + debloat: everything STIG/AppLocker don't reach (see module table) |
| 3 | `applocker\` | Pro/Enterprise/Education only | Real application allowlisting (NSA starter policy + modules) |

This baseline deliberately does **not** duplicate STIG controls. Notably, the Defender STIG
already enables the ASR rule set (Office child-process blocks, LSASS-access block, PSExec/WMI
process blocks, USB-untrusted-executable block), PUA protection, MAPS, and cloud protection —
all registry policies that apply on Home. Run `stig\` first.

On Home, also check **Smart App Control** status (reported by this baseline's
`SmartAppControlAudit` module): it is the built-in WDAC-based allowlisting layer and the true
AppLocker substitute — but it can only be enabled on a fresh install/reset, so it's a decision
point, not something a script can turn on.

---

## Prerequisites

| Requirement | Detail |
|---|---|
| **OS** | Windows 11, any edition (Home/Pro/Enterprise/Education). |
| **PowerShell** | Windows PowerShell 5.1 or PowerShell 7+. On 7, the Appx/Dism cmdlets used by `Debloat` are proxied through the built-in 5.1 compatibility session automatically. |
| **Elevation** | `-Remediate` and `-Rollback` require an elevated session. Assessment (no switches) runs unelevated. |
| **Pester (tests only)** | `Install-Module Pester -MinimumVersion 5.0` — only for `Invoke-Pester -Path .\test`. |

---

## Layout

| Path | What it is |
|---|---|
| `Invoke-HomeBaseline.ps1` | The single entry-point script. All operations go through this. |
| `Invoke-HomeBaseline.Functions.ps1` | Pure helper logic (module resolution/dispatch, PS 5.1/7 compat shim). Dot-sourced by the orchestrator; unit-testable without elevation. |
| `modules/` | Pluggable hardening modules. See `modules/README.md` for the contract and full catalog. |
| `test/` | Pester 5 test suite. No registry/firewall/service writes — dry runs and mocks only. |
| `HomeReports/` | Created on each `-Remediate` run: `.reg` exports of every touched hive, a firewall policy export, and the pre-change provisioned-Appx list. |

---

## Modules

### Default-on

| Module | Cuts off | Mechanism |
|---|---|---|
| `ScriptHostGuard` | WSH payload execution (`.vbs/.js/.jse/.wsf`), double-click script/HTA execution | WSH `Enabled=0`; shell default verb → Edit (Notepad) for all WSH types and `.hta` |
| `LolbinEgressGuard` | LOTL download cradles reaching the internet: `mshta`, `wscript`, `cscript`, `certutil`, `certreq`, `bitsadmin`, `regsvr32` | Outbound-block Windows Firewall rules (kernel WFP — unaffected by user-mode ETW/AMSI tampering) |
| `CredentialTheftGuard` | LSASS credential dumping → lateral movement | `RunAsPPL=1` (LSA Protection) |
| `NameResolutionGuard` | Responder-style LLMNR/NetBIOS/WPAD poisoning | `EnableMulticast=0`, NetBT `NodeType=2` (P-node), `WpadOverride=1` |
| `RemoteServiceGuard` | Inbound WinRM / Remote Registry pivoting | Services stopped + disabled |
| `ExplorerVisibilityHardening` | `invoice.pdf.exe` double-extension disguise | `HideFileExt=0` (current user + Default profile) |
| `PhishingAttachmentGuard` | Downloaded/emailed payloads shedding their untrusted marking to slip past SmartScreen/Defender | Attachment Manager: force Mark-of-the-Web preservation (`SaveZoneInformation=2`), always AV-scan, high default file-type risk. *(Registry replacement for AppLocker's "deny execution from browser/Outlook cache".)* |
| `BrowserScamGuard` | Browser notification-permission scam popups ("your PC has a virus, call…") | Blocks the notification prompt + raises Safe Browsing to Enhanced, Edge/Chrome/Firefox *(ported)* |
| `BrowserHardening` | The browser as the #1 initial-access surface | Balanced max-security policy across Edge/Chrome/Firefox: block dangerous downloads, disable the remote-debug port infostealers use, block silent extension installs & LAN probing, TLS 1.2 floor, DoH, Edge Enhanced Security Mode. `Strict` option adds 3rd-party-cookie + download-prompt. Keeps password manager/DevTools/http pages working. |
| `RemovableMediaGuard` | "Found a USB — run setup.exe?" AutoRun/AutoPlay prompt | `NoDriveTypeAutoRun=255`. **Does not block storage** — drives still mount and files are accessible *(ported)* |
| `UacHardening` | The admin account — the biggest weakness on Home — and silent auto-elevation | UAC consent on the secure desktop (`ConsentPromptBehaviorAdmin=2`, `PromptOnSecureDesktop=1`) + Admin Approval Mode (`FilterAdministratorToken=1`). Flags a lone-admin machine. Doesn't auto-demote (see below). |
| `DiskImageMountGuard` | `.iso`/`.img`/`.vhd(x)` payload smuggling (files inside a mounted image bypass Mark-of-the-Web) | Marks the double-click *mount* verb `ProgrammaticAccessOnly` — `Mount-DiskImage` still works |
| `SmartScreenOsGuard` | Click-through of bad-reputation apps/files | OS SmartScreen `ShellSmartScreenLevel=Block` (no override) + Defender PUA blocking |
| `UpdateAssurance` | Exploitation of unpatched Windows/Office (needs no click) | Pins automatic updates on, clears deferrals, un-disables the Update service |
| `Debloat` | Retired/promo apps, silent app installs, Widgets feed, advertising ID, WMIC | Appx removal (installed + provisioned), ContentDeliveryManager, `Dsh` policy, `AdvertisingInfo`, `Remove-WindowsCapability` |
| `SmartAppControlAudit` | (status-only) reports Smart App Control state and what your options are | Reads `VerifiedAndReputablePolicyState` |

### Opt-in (pass via `-Modules`, `-Modules All`, or enable in `config.ini`)

| Module | What it does | Why opt-in |
|---|---|---|
| `RunDialogLockdown` | Removes the Win+R Run dialog (a ClickFix delivery path) *(ported)* | Also removes Run for admins/power users on the machine |
| `OfficeMacroGuard` | Enables the Defender ASR rules blocking Office macros from spawning processes / calling Win32 APIs *(ported)* | Requires Defender as active AV; can break legitimate macro automation |
| `RemoteAccessToolGuard` | Blocks known RAT/RMM tools by filename via **Image File Execution Options** *(registry replacement for AppLocker's `*\AnyDesk.exe` denies)*. Includes a confined non-admin support-account fallback. | Several listed tools (ScreenConnect, Atera, Splashtop) are the sanctioned tool for many IT departments — edit the list first |
| `NtlmEgressGuard` | Denies **all outgoing NTLM** (`RestrictSendingNTLMTraffic=2`) — no more capturable/relayable challenge-responses | NTLM-only NAS boxes, older printers/scanners, and some VPNs stop authenticating. Audit first (see the module's help). |
| `DnsFilterGuard` | Blocks phishing/malware/C2 **domains at the network layer** — DNS points at a filtering resolver (`Provider` = Quad9/Cloudflare) + encrypted DNS | Captive-portal Wi-Fi and some ISP/enterprise networks misbehave with a pinned resolver |
| `RansomwareResilience` | Defender **Controlled Folder Access** (`Mode` = Enabled/Audit) blocks unknown processes encrypting your files, + System Restore recovery path | CFA has a false-positive tail; use Audit first, then allow-list legit apps |
| `OfficeHardening` | Blocks **macros-from-internet + DDE**, pins Protected View on; **auto-skips if desktop Office isn't installed** | Pointless without Office; can inconvenience a trusted downloaded-macro workflow |

Every module ships a matching **rollback** (`Invoke-<Name>Rollback`); a per-module test enforces
that any module with a Hardening function also exports a Rollback function.

> **The one thing this baseline can't do for you: the account model.** `UacHardening` makes the
> admin token far harder to abuse, but the single biggest win is to run day-to-day as a **Standard
> user**. It's not automated because demoting the account you're logged into — without a second
> admin present — can lock a non-technical user out of their own PC. Safe manual path: create a
> second admin account, sign in and confirm it works, then set the everyday account to **Standard**
> in *Settings → Accounts → Other users*. Most commodity malware that assumes admin rights simply
> fails against a standard user.

---

## Step-by-step

```powershell
# 1. Assess - safe on any edition, unelevated, changes nothing
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-HomeBaseline.ps1

# 2. Apply the default baseline (elevated)
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-HomeBaseline.ps1 -Remediate

# 3. Reboot (RunAsPPL and the NetBIOS node type apply at boot), then re-assess
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-HomeBaseline.ps1
```

## Configuration (`config.ini`)

Instead of remembering module names on the command line, drive the whole run from `config.ini`
— one `[Section]` per module, each with a plain-language explanation, an `Enabled` toggle, and
any per-module options:

```powershell
# Edit config.ini to taste, then:
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-HomeBaseline.ps1 -Remediate -ConfigPath .\config.ini
```

```ini
[LolbinEgressGuard]
; Kernel-level firewall egress blocks for LOTL download cradles...
Enabled = true
IncludeCurl = false     ; also block curl.exe (off — real dev/support tool)

[RemoteAccessToolGuard]
; Blocks AnyDesk/TeamViewer QS/ScreenConnect/... by filename (IFEO)...
Enabled = false         ; opt-in — several are sanctioned IT tools
```

Rules:
- An `Enabled` of `false`/`no`/`off`/`0` skips the module; anything else (or a missing `Enabled`)
  includes it.
- Enabled sections become the module set **unless** you also pass `-Modules` (which wins); the
  per-module **options** apply either way.
- Options are only passed to a module that actually declares that parameter, so a stray key
  never breaks a run.

The shipped `config.ini` documents every module (default-on and opt-in) in place — it doubles as
the reference for what each control does and its trade-off.

Both PowerShell engines work identically:

```powershell
pwsh.exe -ExecutionPolicy Bypass -File .\Invoke-HomeBaseline.ps1 -Remediate
```

Per-module knobs are available by importing a module directly:

```powershell
# Also block curl.exe egress (developers: read LolbinEgressGuard help first)
Import-Module .\modules\LolbinEgressGuard.psm1
Invoke-LolbinEgressGuardHardening -Remediate -IncludeCurl

# Also remove the Xbox apps on a machine that never games
Import-Module .\modules\Debloat.psm1
Invoke-DebloatHardening -Remediate -IncludeXbox
```

---

## Rollback

```powershell
# Full rollback of the default set
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-HomeBaseline.ps1 -Rollback

# Undo a single module only
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-HomeBaseline.ps1 -Rollback -Modules NameResolutionGuard
```

| Module | What rollback restores |
|---|---|
| `ScriptHostGuard` | Removes the WSH disable and every file-association override (execution behavior returns to Windows defaults) |
| `LolbinEgressGuard` | Deletes the whole firewall rule group |
| `CredentialTheftGuard` | Removes `RunAsPPL` (reboot to apply) |
| `NameResolutionGuard` | Removes the LLMNR policy, NetBIOS node type (reboot), and WPAD override |
| `RemoteServiceGuard` | Restores Windows 11 default startup types (WinRM=Manual, RemoteRegistry=Disabled) |
| `ExplorerVisibilityHardening` | Removes the `HideFileExt` overrides |
| `PhishingAttachmentGuard` | Removes the Attachment Manager / file-type-risk overrides |
| `BrowserScamGuard` | Removes the Edge/Chrome policy values and the Firefox `policies.json` |
| `RemovableMediaGuard` | Removes `NoDriveTypeAutoRun` |
| `Debloat` | Restores all registry defaults; removed apps reinstall from the Microsoft Store (pre-change provisioned list saved under `HomeReports\`); WMIC via `Add-WindowsCapability` |
| `RunDialogLockdown` | Removes `NoRun`; restarts Explorer |
| `OfficeMacroGuard` | Removes both ASR rule GUIDs |
| `RemoteAccessToolGuard` | Removes every IFEO block and the temporary support account |
| `NtlmEgressGuard` | Removes the outgoing-NTLM restriction |

Every module also supports a dry-run rollback preview: `Invoke-<Name>Rollback` without
`-Remediate` shows exactly what would be undone.

---

## The balance: what this baseline deliberately does NOT do

Hardening that breaks the household gets turned off within a week — and then nothing is
protected. Every control here was filtered against "does a normal user with a printer, an
external drive, a NAS, and a game library still have a working computer?"

| Not done | Why |
|---|---|
| Disable USB mass storage / removable drives | External drives, camera cards, and flash drives are daily-use. AutoRun/AutoPlay abuse is already covered by STIG (`NoDriveTypeAutoRun=255`) and the Defender ASR USB rule — the storage itself stays. |
| Disable Print Spooler | Printing is not negotiable on a home machine. (On a machine that provably never prints, disabling it is a fine manual extra.) |
| Disable mDNS | It's how network printers, casting, and smart-home discovery work. LLMNR + NetBIOS broadcasts are the poisoning surface that matters and they're already off. |
| Disable LanmanServer / file sharing | Sharing a folder or printer to the household is legitimate. STIG already forces SMB signing and kills SMBv1/anonymous access. |
| Block `powershell.exe`/`pwsh.exe` egress | Breaks winget/module updates and Windows' own remediation scripts. Compensated by STIG script-block logging + transcription and the CLM note below. |
| Block `curl.exe` egress by default | Real tool for developers and support flows. Opt-in via `-IncludeCurl`. |
| Remove Xbox apps, Phone Link, media apps, Store, Quick Assist | First-class home use cases. Xbox removal is opt-in (`-IncludeXbox`); Quick Assist is the sanctioned remote-help path (and its control actions still pass UAC). |
| Force PowerShell Constrained Language Mode (`__PSLockdownPolicy`) | Microsoft explicitly documents it as not a security boundary; it breaks legitimate scripts/tests system-wide while an admin-level attacker removes it in one line. On Pro+, the applocker baseline's Script enforcement provides CLM properly. |
| Block the Downloads folder or file associations for documents | Deliberate downloads are the point of a browser. |

## Honest limits: ETW/EDR tampering

Registry hardening cannot stop a kernel-level attacker, and user-mode ETW/AMSI patching is a
script-kiddie-accessible technique. What this baseline does about it:

- **Prefers controls that don't depend on telemetry**: firewall egress rules are enforced in
  the kernel by WFP; RunAsPPL is enforced by the kernel; a disabled WSH engine has no
  hook to patch. Blinding ETW doesn't re-open any of these.
- **Defender Tamper Protection** (blocks the `Set-MpPreference`/registry route to disabling
  AV) must be verified by hand in Windows Security — it is not scriptable *by design*, and
  that's the correct trade. The status output reminds you.
- What it **cannot** do: stop BYOVD kernel exploitation, protect a machine whose owner runs
  as admin and approves every UAC prompt, or substitute for a real EDR. On Pro/Enterprise,
  layer `applocker\`; on any edition, a clean install with Smart App Control latched On is
  worth more than any post-hoc script.

---

## Testing

```powershell
Invoke-Pester -Path .\test
```

The suite covers the pure helper functions (module resolution, comma-splitting, phase
dispatch), a per-module contract (imports cleanly, Status/dry-runs never throw, dry runs never
write), and mocked remediation/rollback paths asserting the exact registry values, firewall
rules, and service calls each module makes. Nothing in the suite changes machine state; it
runs unelevated on both PowerShell 5.1 and 7+.
