<#
.SYNOPSIS
    Pure/testable helper functions for Invoke-HomeBaseline.ps1 - module discovery and dispatch,
    plus the Windows PowerShell 5.1 / PowerShell 7+ compatibility shim for Appx/Dism cmdlets.
    No registry/service/firewall calls live here; those stay in the orchestrator and modules so
    this file can be dot-sourced and unit tested without Administrator rights.
#>

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-HomeAvailableModule {
    <#
    .SYNOPSIS
        Lists the module base names (without .psm1) available under a modules/ folder.
    #>
    param(
        [Parameter(Mandatory)] [string]$ModulesRoot
    )
    if (-not (Test-Path -LiteralPath $ModulesRoot)) { return @() }
    @(Get-ChildItem -LiteralPath $ModulesRoot -Filter '*.psm1' -File | ForEach-Object { $_.BaseName })
}

function Resolve-HomeModule {
    <#
    .SYNOPSIS
        Resolves which modules should be wired into a run.

    .DESCRIPTION
        - Not requested at all (BoundModules = $false) -> the default set.
        - Requested as @('All') -> every module found under ModulesRoot.
        - Requested as @() (explicitly empty) -> no modules.
        - Requested as a specific list -> that list, filtered to what actually exists
          (with a warning emitted via $WarningOut for anything not found).

        Each requested entry is also split on commas before resolution. This matters because
        `powershell.exe -File script.ps1 -Modules Foo,Bar` passes "Foo,Bar" as a single raw
        argument (no PowerShell-side array splitting happens across a -File boundary), so without
        this the whole comma-joined string is looked up as one (nonexistent) module name.
    #>
    param(
        [string[]]$RequestedModules,
        [bool]$BoundModules,
        [string[]]$DefaultModules,
        [Parameter(Mandatory)] [string]$ModulesRoot,
        [scriptblock]$WarningOut = { param($msg) Write-Warning $msg }
    )
    $available = Get-HomeAvailableModule -ModulesRoot $ModulesRoot

    if (-not $BoundModules) {
        return @($DefaultModules | Where-Object { $_ -in $available })
    }

    $RequestedModules = @($RequestedModules | ForEach-Object { $_ -split ',' } | Where-Object { $_ })

    if ($RequestedModules.Count -eq 1 -and $RequestedModules[0] -eq 'All') {
        return @($available)
    }
    if ($RequestedModules.Count -eq 0) {
        return @()
    }

    $resolved = @()
    foreach ($name in $RequestedModules) {
        if ($name -in $available) {
            $resolved += $name
        } else {
            & $WarningOut "Module '$name' not found under $ModulesRoot - skipping."
        }
    }
    return @($resolved)
}

function Invoke-HomeModulePhase {
    <#
    .SYNOPSIS
        Calls a module's convention-named function for a given phase, if it exports one.

    .DESCRIPTION
        Module contract (see modules\README.md):
            Get-<Name>Status         - phase 'Status'
            Invoke-<Name>Hardening   - phase 'Hardening'  (receives -Remediate)
            Invoke-<Name>Rollback    - phase 'Rollback'   (receives -Remediate)
        There is no PolicyFragment phase here - unlike the applocker baseline, this baseline has
        no central policy document to merge into; every module owns its registry/firewall/appx
        changes end to end. Returns $null if the module doesn't export a function for the
        requested phase.

        -Options carries per-module switches/values from config.ini (e.g. IncludeCurl,
        IncludeXbox). Only keys that the target function actually declares as parameters are
        splatted in; unknown keys are ignored, so one module's options never break another.
    #>
    param(
        [Parameter(Mandatory)] [string]$ModuleName,
        [Parameter(Mandatory)] [ValidateSet('Status', 'Hardening', 'Rollback')] [string]$Phase,
        [switch]$Remediate,
        [hashtable]$Options
    )
    $functionName = switch ($Phase) {
        'Status'    { "Get-${ModuleName}Status" }
        'Hardening' { "Invoke-${ModuleName}Hardening" }
        'Rollback'  { "Invoke-${ModuleName}Rollback" }
    }
    $cmd = Get-Command -Name $functionName -ErrorAction SilentlyContinue
    if (-not $cmd) { return $null }

    $splat = @{}
    if ($Options) {
        foreach ($key in $Options.Keys) {
            if ($cmd.Parameters.ContainsKey($key)) { $splat[$key] = $Options[$key] }
        }
    }

    if ($Phase -in 'Hardening', 'Rollback') {
        return & $cmd -Remediate:$Remediate @splat
    }
    return & $cmd @splat
}

function Invoke-HomeModulePhaseSafe {
    <#
    .SYNOPSIS
        Runs Invoke-HomeModulePhase but never throws: if the module errors (e.g. a write to an
        ACL-protected policy key, a service that refuses to stop, a Defender cmdlet failing) the
        failure is captured and returned so the orchestrator can report it and keep going,
        instead of one module aborting the whole run under ErrorActionPreference='Stop'.

    .OUTPUTS
        [pscustomobject] with:
            Lines - the phase's output strings, or $null
            Error - the exception message if the module threw, otherwise $null
    #>
    param(
        [Parameter(Mandatory)] [string]$ModuleName,
        [Parameter(Mandatory)] [ValidateSet('Status', 'Hardening', 'Rollback')] [string]$Phase,
        [switch]$Remediate,
        [hashtable]$Options
    )
    try {
        $lines = Invoke-HomeModulePhase -ModuleName $ModuleName -Phase $Phase -Remediate:$Remediate -Options $Options
        [pscustomobject]@{ Lines = $lines; Error = $null }
    } catch {
        [pscustomobject]@{ Lines = $null; Error = $_.Exception.Message }
    }
}

function ConvertTo-HomeConfigValue {
    <#
    .SYNOPSIS
        Types a raw INI string value: true/false -> [bool], integer text -> [int], else the
        trimmed string. Inline comments (' ;' / ' #') are stripped first.
    #>
    param([string]$Raw)
    if ($null -eq $Raw) { return $null }
    $v = ($Raw -replace '\s+[;#].*$', '').Trim()
    switch -Regex ($v) {
        '^(?i:true|yes|on|1)$'  { return $true }
        '^(?i:false|no|off|0)$' {
            # Bare 0/1 are ambiguous (could be an int option). Treat literal true/false/yes/no/
            # on/off as bool; treat 0/1 as bool ONLY here because every option in this baseline
            # that uses 0/1 is a toggle. Numeric-valued options use values >1.
            return $false
        }
        '^-?\d+$' { return [int]$v }
        default   { return $v }
    }
}

function ConvertFrom-HomeIni {
    <#
    .SYNOPSIS
        Minimal INI parser: returns an ordered hashtable of section-name -> (ordered hashtable of
        key -> raw string value). Blank lines and ';'/'#' comment lines are ignored. Keys before
        any [section] header are dropped (this baseline requires every key under a module section).
    #>
    param([Parameter(Mandatory)] [AllowEmptyString()] [string[]]$Lines)
    $sections = [ordered]@{}
    $current = $null
    foreach ($line in $Lines) {
        $t = $line.Trim()
        if ($t -eq '' -or $t.StartsWith(';') -or $t.StartsWith('#')) { continue }
        if ($t -match '^\[(.+)\]$') {
            $current = $Matches[1].Trim()
            if (-not $sections.Contains($current)) { $sections[$current] = [ordered]@{} }
            continue
        }
        if ($null -eq $current) { continue }
        $idx = $t.IndexOf('=')
        if ($idx -lt 1) { continue }
        $key = $t.Substring(0, $idx).Trim()
        $val = $t.Substring($idx + 1).Trim()
        $sections[$current][$key] = $val
    }
    $sections
}

function Get-HomeModuleCoverage {
    <#
    .SYNOPSIS
        One-line "threat addressed - mechanism" description per module, used in the run report so
        it documents what each control covers. Kept here as the single source of truth; a test
        asserts every module file has an entry so this can't silently go stale.
    #>
    [ordered]@{
        ScriptHostGuard             = 'ClickFix "paste-and-run" lures & emailed script droppers - disables Windows Script Host and routes .vbs/.js/.jse/.wsf/.hta double-click to Notepad.'
        LolbinEgressGuard           = 'Living-off-the-land download cradles / C2 callbacks - kernel-level (WFP) firewall egress block on mshta/wscript/cscript/certutil/certreq/bitsadmin/regsvr32.'
        CredentialTheftGuard        = 'LSASS credential dumping (Mimikatz/comsvcs) that precedes lateral movement - LSA Protection (RunAsPPL=1).'
        NameResolutionGuard         = 'LLMNR/NetBIOS/WPAD poisoning (Responder) that harvests NTLM creds on a LAN - disables broadcast name resolution and WPAD auto-discovery.'
        RemoteServiceGuard          = 'WinRM & Remote Registry inbound pivot channels - stopped and disabled.'
        ExplorerVisibilityHardening = 'invoice.pdf.exe double-extension disguise - shows file extensions (current user + seeded into the Default profile).'
        PhishingAttachmentGuard     = 'Downloaded/emailed payloads shedding their Mark-of-the-Web to evade SmartScreen/Defender - Attachment Manager forces MOTW retention + AV scan.'
        BrowserScamGuard            = 'Fake-virus / tech-support notification scam popups - blocks the notification-permission prompt and raises Safe Browsing (Edge/Chrome/Firefox).'
        BrowserHardening            = 'Browser as the #1 initial-access surface - balanced max-security policy across Edge/Chrome/Firefox (block dangerous downloads, disable remote-debug cookie theft, block silent extensions & LAN probing, TLS 1.2 floor, DoH, Edge Enhanced Security Mode).'
        RemovableMediaGuard         = '"Found a USB - run setup.exe?" AutoRun/AutoPlay prompt - disabled for all drive types (storage itself stays fully usable).'
        Debloat                     = 'Out-of-box attack surface / bloat - removes retired & promo apps, silent app installs, the Widgets feed, the advertising ID, and the deprecated WMIC LOLBin.'
        SmartAppControlAudit        = 'Reports Smart App Control (Windows'' built-in allowlisting, the AppLocker substitute on Home) state - status only, makes no changes.'
        RunDialogLockdown           = 'Win+R Run dialog as a ClickFix delivery path - removes it machine-wide (opt-in).'
        OfficeMacroGuard            = 'Office macro spawning processes / calling Win32 APIs - Defender ASR rules (opt-in).'
        RemoteAccessToolGuard       = 'Tech-support-scam & abused-RMM remote-access tools - Image File Execution Options block-by-filename + confined support account (opt-in).'
        NtlmEgressGuard             = 'Outgoing NTLM capture/relay from a lured/coerced auth - denies all outbound NTLM (opt-in).'
        UacHardening                = 'Admin account is the biggest weakness on Home - UAC to always-prompt on the secure desktop + Admin Approval Mode, so silent script-driven elevation on the initial vector dies.'
        DiskImageMountGuard         = 'ISO/IMG/VHD payload smuggling (files inside a mounted image bypass Mark-of-the-Web) - disables double-click auto-mount (Mount-DiskImage still works).'
        SmartScreenOsGuard          = 'Click-through of bad-reputation apps/files - OS SmartScreen set to Block (no override) + Defender PUA blocking.'
        UpdateAssurance             = 'Exploitation of unpatched Windows/Office with no user click - pins automatic updates on and clears deferrals.'
        DnsFilterGuard              = 'Phishing/malware/C2 domains - points system DNS at a malware-filtering resolver (Quad9/Cloudflare) with encrypted DNS (opt-in).'
        RansomwareResilience        = 'Ransomware encrypting personal files after detonation - Defender Controlled Folder Access + System Restore (opt-in).'
        OfficeHardening             = 'Document-borne attacks beyond macros - blocks macros from the internet, kills DDE, pins Protected View (opt-in, auto-skips if no Office).'
    }
}

function New-HomeBaselineReport {
    <#
    .SYNOPSIS
        Builds a Markdown run report (returned as a string) documenting everything the baseline
        covered on this run: context, per-module coverage/status/actions/errors, and the modules
        that were not run. Pure - takes data in, returns text; the orchestrator writes it to disk.

    .PARAMETER Mode
        Assess | Remediate | Rollback - controls the wording and which action label is used.

    .PARAMETER Context
        Hashtable: Computer, OS, Build, PSVersion, Elevated, ConfigPath, BackupPath, Timestamp.

    .PARAMETER RunLog
        Ordered dictionary keyed by module name; each value a hashtable with Status ([string[]]),
        Action ([string[]]), and Error ([string]).

    .PARAMETER AllModules
        The full module catalog, so the report can list what was available but not run.
    #>
    param(
        [Parameter(Mandatory)] [ValidateSet('Assess', 'Remediate', 'Rollback')] [string]$Mode,
        [Parameter(Mandatory)] [hashtable]$Context,
        [Parameter(Mandatory)] $RunLog,
        [string[]]$AllModules = @()
    )
    $cov = Get-HomeModuleCoverage
    $actionLabel = switch ($Mode) { 'Remediate' { 'Applied' } 'Rollback' { 'Rolled back' } default { 'Actions' } }
    $ran = @($RunLog.Keys)
    $failed = @($ran | Where-Object { $RunLog[$_].Error })

    $L = New-Object System.Collections.Generic.List[string]
    $L.Add("# Windows 11 Home Baseline - Run Report")
    $L.Add("")
    $L.Add("| Field | Value |")
    $L.Add("|---|---|")
    $L.Add("| Generated | $($Context.Timestamp) |")
    $L.Add("| Mode | $Mode |")
    $L.Add("| Computer | $($Context.Computer) |")
    $L.Add("| OS | $($Context.OS) (build $($Context.Build)) |")
    $L.Add("| PowerShell | $($Context.PSVersion) |")
    $L.Add("| Elevated | $($Context.Elevated) |")
    if ($Context.ConfigPath) { $L.Add("| Config | $($Context.ConfigPath) |") }
    if ($Context.BackupPath) { $L.Add("| Pre-change backups | $($Context.BackupPath) |") }
    $L.Add("| Modules run | $($ran.Count) |")
    $L.Add("| Modules with errors | $($failed.Count) |")
    $L.Add("")

    if ($failed.Count -gt 0) {
        $L.Add("> **Warning:** these modules reported errors and may be only partially applied: **$($failed -join ', ')**. See their sections below.")
        $L.Add("")
    }

    $L.Add("## Coverage - what ran")
    $L.Add("")
    foreach ($name in $ran) {
        $entry = $RunLog[$name]
        $L.Add("### $name")
        if ($cov.Contains($name)) { $L.Add("_$($cov[$name])_") }
        $L.Add("")
        if ($entry.Status) {
            $L.Add("**State:**")
            foreach ($s in $entry.Status) { $L.Add("- $s") }
            $L.Add("")
        }
        if ($entry.Action) {
            $L.Add("**${actionLabel}:**")
            foreach ($a in $entry.Action) { $L.Add("- $a") }
            $L.Add("")
        }
        if ($entry.Error) {
            $L.Add("**Error (skipped, run continued):** $($entry.Error)")
            $L.Add("")
        }
    }

    $notRun = @($AllModules | Where-Object { $_ -notin $ran })
    if ($notRun.Count -gt 0) {
        $L.Add("## Available but not run")
        $L.Add("")
        foreach ($name in $notRun) {
            $desc = if ($cov.Contains($name)) { $cov[$name] } else { '(no description)' }
            $L.Add("- **$name** - $desc")
        }
        $L.Add("")
    }

    $L.Add("---")
    $L.Add("_Layered baseline: run ``stig\`` for DISA STIG controls (works on Home too) and, on Pro/Enterprise/Education, ``applocker\`` for application allowlisting. Reboot after remediation to apply RunAsPPL and the NetBIOS node type._")
    ($L -join [Environment]::NewLine)
}

function Get-HomeConfig {
    <#
    .SYNOPSIS
        Reads a baseline config.ini and returns which modules are enabled plus each module's
        options.

    .DESCRIPTION
        Each [SectionName] is a module name, EXCEPT the reserved [Baseline] section, which holds
        global run settings (Remediate, Rollback, SkipBackup, NoReport, Force, ReportPath,
        OutputPath) so the whole run can be driven from the config file, not just module
        selection.

        For module sections: an 'Enabled' key of false/no/off/0 excludes the module; any other
        value (or a missing Enabled key) includes it. Every other key becomes an entry in that
        module's Options hashtable, typed by ConvertTo-HomeConfigValue.

        Returns [pscustomobject] with:
            Modules  - [string[]] of enabled module names, in file order
            Options  - [hashtable] moduleName -> [hashtable] of typed option key/value pairs
                       (excluding 'Enabled')
            Settings - [hashtable] of typed global settings from the [Baseline] section (empty
                       if absent)
    #>
    param(
        [Parameter(Mandatory)] [string]$Path,
        [string]$SettingsSection = 'Baseline'
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Config file not found: $Path"
    }
    $sections = ConvertFrom-HomeIni -Lines (Get-Content -LiteralPath $Path)
    $enabled = @()
    $options = @{}
    $settings = @{}
    foreach ($name in $sections.Keys) {
        $keys = $sections[$name]

        if ($name -eq $SettingsSection) {
            foreach ($k in $keys.Keys) { $settings[$k] = ConvertTo-HomeConfigValue -Raw $keys[$k] }
            continue
        }

        $isEnabled = $true
        if ($keys.Contains('Enabled')) {
            $isEnabled = [bool](ConvertTo-HomeConfigValue -Raw $keys['Enabled'])
        }
        $opt = @{}
        foreach ($k in $keys.Keys) {
            if ($k -eq 'Enabled') { continue }
            $opt[$k] = ConvertTo-HomeConfigValue -Raw $keys[$k]
        }
        $options[$name] = $opt
        if ($isEnabled) { $enabled += $name }
    }
    [pscustomobject]@{
        Modules  = @($enabled)
        Options  = $options
        Settings = $settings
    }
}

function Import-HomeCompatModule {
    <#
    .SYNOPSIS
        Imports a Windows-inbox module (Appx, Dism) so its cmdlets work on both Windows
        PowerShell 5.1 and PowerShell 7+.

    .DESCRIPTION
        On 5.1 a plain Import-Module works. On PowerShell 7 the Appx module (and on some builds
        Dism) refuses to load natively and tells you to use -UseWindowsPowerShell, which proxies
        the cmdlets through a background 5.1 session. Try native first, fall back to the
        compatibility session. Returns $true when the module's cmdlets are usable.
    #>
    param(
        [Parameter(Mandatory)] [string]$Name
    )
    if (Get-Module -Name $Name) { return $true }
    try {
        Import-Module -Name $Name -ErrorAction Stop -WarningAction SilentlyContinue
        return $true
    } catch {
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            try {
                Import-Module -Name $Name -UseWindowsPowerShell -ErrorAction Stop -WarningAction SilentlyContinue
                return $true
            } catch {
                return $false
            }
        }
        return $false
    }
}
