<#
.SYNOPSIS
    Applies a post-compromise-containment and debloat baseline to Windows 11 - the layer that
    works on every edition including Home, where AppLocker does not exist. Registry, firewall,
    service, and Appx hardening aimed at the attacks Defender does not surface: living-off-the-
    land download cradles, credential dumping, and name-resolution poisoning.

.DESCRIPTION
    Threat model: assume an initial payload lands anyway (phishing attachment, ClickFix paste,
    malicious download). This baseline is about what happens NEXT. Each wired-in module cuts a
    specific post-exploitation dependency:

        ScriptHostGuard             - WSH/HTA script engines can't run or double-click-execute
        LolbinEgressGuard           - LOTL download cradles (mshta/certutil/bitsadmin/regsvr32/
                                      wscript/cscript/certreq) get kernel-level firewall egress
                                      denies - immune to user-mode ETW/AMSI patching
        CredentialTheftGuard        - LSASS runs as PPL; no user-mode credential dumping
        NameResolutionGuard         - LLMNR/NetBIOS-broadcast/WPAD poisoning (Responder) cut off
        RemoteServiceGuard          - WinRM + Remote Registry pivot channels disabled
        ExplorerVisibilityHardening - double-extension disguises visible
        Debloat                     - retired/promo apps, silent app installs, Widgets feed,
                                      advertising ID, deprecated WMIC removed
        SmartAppControlAudit        - reports the state of Windows' built-in allowlisting
                                      (the Home-edition AppLocker substitute; status-only)

    Layering: this directory covers what stig\ and applocker\ do not. Run stig\ first (its
    registry/audit controls - Defender ASR rules, PowerShell logging, SMB signing, WDigest -
    work on Home too). On Pro/Enterprise/Education, add applocker\ for real allowlisting; this
    baseline detects those editions and reminds you.

    Flow, mirroring the assess/remediate pattern used elsewhere in this repo:
        1. ASSESS (default, no changes): each module reports its current state.
        2. REMEDIATE (-Remediate): backs up affected registry hives, the firewall policy, and
           the provisioned-Appx list to HomeReports\<host>-<timestamp>\, then runs every
           wired-in module's hardening.
        3. ROLLBACK (-Rollback): undoes every module's changes (or a single module's with
           -Modules <Name>). Removed Appx packages reinstall via the Microsoft Store.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+ (Appx/Dism cmdlets are proxied
    through the 5.1 compatibility session on 7 where needed).

.PARAMETER Remediate
    Apply changes. Without it, the script only assesses and reports current state - a safe dry
    run showing exactly what each module would do.

.PARAMETER Rollback
    Undo module changes. With no -Modules, every default module is rolled back; with -Modules,
    only the named modules are.

.PARAMETER Modules
    Names of modules\*.psm1 (without extension) to wire into this run. Defaults to the curated
    set above. Pass 'All' for every module (including the opt-in NtlmEgressGuard - read its
    help first: NTLM-only NAS/printer shares will break), or @() for none. Comma-joined values
    (-Modules Foo,Bar) are accepted even via `powershell.exe -File`. An explicit -Modules
    overrides the module selection in -ConfigPath.

.PARAMETER ConfigPath
    Path to a config.ini (see the bundled config.ini) whose [Section] per module carries an
    Enabled flag plus per-module options (IncludeCurl, IncludeXbox, ...). Enabled sections
    become the module set unless -Modules is also given; the per-module options apply either
    way. A relative path resolves against the script directory.

.PARAMETER OutputPath
    Folder for pre-change backups. Default: .\HomeReports\<HOSTNAME>-<timestamp>\

.PARAMETER SkipBackup
    Skip the registry/firewall/Appx backups before remediation.

.PARAMETER Force
    Bypass the Windows 11 pre-flight check and the elevation requirement.

.EXAMPLE
    # Safe dry run - report current state, no changes
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-HomeBaseline.ps1

.EXAMPLE
    # Apply the default baseline
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-HomeBaseline.ps1 -Remediate

.EXAMPLE
    # Apply everything including the opt-in outgoing-NTLM deny
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-HomeBaseline.ps1 -Remediate -Modules All

.EXAMPLE
    # Drive module selection and per-module options from config.ini
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-HomeBaseline.ps1 -Remediate -ConfigPath .\config.ini

.EXAMPLE
    # Undo a single module (restore WinRM/RemoteRegistry defaults) without touching the rest
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-HomeBaseline.ps1 -Rollback -Modules RemoteServiceGuard

.EXAMPLE
    # Full rollback of the default set
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-HomeBaseline.ps1 -Rollback

.NOTES
    Author: Robert Weber
    Run from an elevated PowerShell session for -Remediate / -Rollback. Reboot afterwards -
    RunAsPPL and the NetBIOS node type only take effect at boot.
#>

[CmdletBinding()]
param(
    [switch]$Remediate,
    [switch]$Rollback,
    [string[]]$Modules,
    [string]$ConfigPath,
    [string]$OutputPath,
    [string]$ReportPath,
    [switch]$NoReport,
    [switch]$SkipBackup,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $root 'Invoke-HomeBaseline.Functions.ps1')

$ModulesRoot = Join-Path $root 'modules'
$DefaultModules = @('ScriptHostGuard', 'LolbinEgressGuard', 'CredentialTheftGuard', 'NameResolutionGuard', 'RemoteServiceGuard', 'ExplorerVisibilityHardening', 'PhishingAttachmentGuard', 'BrowserScamGuard', 'BrowserHardening', 'RemovableMediaGuard', 'UacHardening', 'DiskImageMountGuard', 'SmartScreenOsGuard', 'UpdateAssurance', 'Debloat', 'SmartAppControlAudit')

# =============================================================================
# CONFIG - load first so config.ini can drive the entire run, not just module selection.
# The reserved [Baseline] section carries global run settings (Remediate, Rollback, SkipBackup,
# NoReport, Force, ReportPath, OutputPath). Anything explicitly passed on the command line still
# wins over the config; the config fills in the rest.
# =============================================================================
$config = $null
if ($PSBoundParameters.ContainsKey('ConfigPath')) {
    if (-not [System.IO.Path]::IsPathRooted($ConfigPath)) { $ConfigPath = Join-Path $root $ConfigPath }
    $config = Get-HomeConfig -Path $ConfigPath
    Write-Host "Loaded config: $ConfigPath ($($config.Modules.Count) module(s) enabled)." -ForegroundColor DarkCyan

    $s = $config.Settings
    if ($s) {
        if (-not $PSBoundParameters.ContainsKey('Remediate')  -and $s.Contains('Remediate'))  { $Remediate  = [bool]$s['Remediate'] }
        if (-not $PSBoundParameters.ContainsKey('Rollback')   -and $s.Contains('Rollback'))   { $Rollback   = [bool]$s['Rollback'] }
        if (-not $PSBoundParameters.ContainsKey('SkipBackup') -and $s.Contains('SkipBackup')) { $SkipBackup = [bool]$s['SkipBackup'] }
        if (-not $PSBoundParameters.ContainsKey('NoReport')   -and $s.Contains('NoReport'))   { $NoReport   = [bool]$s['NoReport'] }
        if (-not $PSBoundParameters.ContainsKey('Force')      -and $s.Contains('Force'))      { $Force      = [bool]$s['Force'] }
        if (-not $PSBoundParameters.ContainsKey('ReportPath') -and $s.Contains('ReportPath')) { $ReportPath = [string]$s['ReportPath'] }
        if (-not $PSBoundParameters.ContainsKey('OutputPath') -and $s.Contains('OutputPath')) { $OutputPath = [string]$s['OutputPath'] }
    }
}

# =============================================================================
# 0. PRE-FLIGHT
# =============================================================================
if (-not (Test-Admin)) {
    Write-Warning "Not running elevated. Assessment works; -Remediate/-Rollback require Administrator."
    if (($Remediate -or $Rollback) -and -not $Force) {
        throw "Re-run from an elevated PowerShell session (or pass -Force to override)."
    }
}

$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($os -and $os.Caption -notmatch 'Windows 11') {
    Write-Warning "This baseline targets Windows 11; detected: $($os.Caption)."
    if ($Remediate -and -not $Force) { throw "Re-run with -Force to apply anyway." }
}
if ($os -and $os.Caption -notmatch 'Home') {
    Write-Host "Detected a non-Home edition. This baseline still applies, but AppLocker is available here - layer the applocker\ baseline on top for real application allowlisting." -ForegroundColor DarkCyan
}

if ($Remediate -and $Rollback) {
    throw "-Remediate and -Rollback are mutually exclusive."
}

if (-not $OutputPath) {
    $OutputPath = Join-Path $root "HomeReports\$($env:COMPUTERNAME)-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
}

# Module selection precedence:
#   1. -Modules on the command line always wins (explicit intent).
#   2. else -ConfigPath's enabled sections (config.ini).
#   3. else the built-in default set.
# Per-module options (IncludeCurl, IncludeXbox, ...) always come from config.ini when present,
# regardless of how selection was decided, so you can tune a module without also having to
# re-list every module on the command line.
$ModuleOptions = @{}
$modulesRequested = $Modules
$modulesBound = $PSBoundParameters.ContainsKey('Modules')

if ($config) {
    $ModuleOptions = $config.Options
    if (-not $modulesBound) {
        $modulesRequested = $config.Modules
        $modulesBound = $true
    }
}

$ResolvedModules = Resolve-HomeModule -RequestedModules $modulesRequested -BoundModules $modulesBound `
    -DefaultModules $DefaultModules -ModulesRoot $ModulesRoot
foreach ($name in $ResolvedModules) {
    Import-Module (Join-Path $ModulesRoot "$name.psm1") -Force
}

# --- Run report scaffolding: accumulate what each module reported/did, write a Markdown report
#     of everything covered to the working directory at the end of every run mode. ---
$RunTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
if (-not $ReportPath) {
    $ReportPath = Join-Path (Get-Location).Path "HomeBaseline-Report-$($env:COMPUTERNAME)-$(Get-Date -Format 'yyyyMMdd-HHmmss').md"
}
$runLog = [ordered]@{}
function Add-RunLog {
    param([string]$Name, [string[]]$Status, [string[]]$Action, [string]$ErrorMsg)
    if (-not $runLog.Contains($Name)) { $runLog[$Name] = @{ Status = @(); Action = @(); Error = $null } }
    if ($Status)   { $runLog[$Name].Status = $Status }
    if ($Action)   { $runLog[$Name].Action = $Action }
    if ($ErrorMsg) { $runLog[$Name].Error  = $ErrorMsg }
}
function Write-HomeReport {
    param([Parameter(Mandatory)][ValidateSet('Assess', 'Remediate', 'Rollback')][string]$Mode, [string]$BackupPath)
    if ($NoReport) { return }
    $ctx = @{
        Timestamp  = $RunTimestamp
        Computer   = $env:COMPUTERNAME
        OS         = if ($os) { $os.Caption } else { 'Unknown' }
        Build      = if ($os) { $os.BuildNumber } else { '' }
        PSVersion  = $PSVersionTable.PSVersion.ToString()
        Elevated   = (Test-Admin)
        ConfigPath = $ConfigPath
        BackupPath = $BackupPath
    }
    try {
        $report = New-HomeBaselineReport -Mode $Mode -Context $ctx -RunLog $runLog `
            -AllModules (Get-HomeAvailableModule -ModulesRoot $ModulesRoot)
        Set-Content -Path $ReportPath -Value $report -Encoding UTF8
        Write-Host "`nReport written: $ReportPath" -ForegroundColor Green
    } catch {
        Write-Warning "Could not write run report to '$ReportPath': $($_.Exception.Message)"
    }
}

# =============================================================================
# 1. STATUS / ASSESSMENT
# =============================================================================
Write-Host "`n== Host ==" -ForegroundColor Cyan
if ($os) {
    Write-Host "  $($os.Caption) (build $($os.BuildNumber)), PowerShell $($PSVersionTable.PSVersion)"
}

foreach ($name in $ResolvedModules) {
    Write-Host "`n== Module: $name ==" -ForegroundColor Cyan
    $r = Invoke-HomeModulePhaseSafe -ModuleName $name -Phase Status -Options $ModuleOptions[$name]
    if ($r.Error) {
        Write-Warning "  status check failed: $($r.Error)"
        Add-RunLog -Name $name -ErrorMsg $r.Error
    } elseif ($null -eq $r.Lines) {
        Write-Host "  (no status reported)"
        Add-RunLog -Name $name
    } else {
        $r.Lines | ForEach-Object { Write-Host "  $_" }
        Add-RunLog -Name $name -Status $r.Lines
    }
}

# =============================================================================
# 2. ROLLBACK
# =============================================================================
if ($Rollback) {
    Write-Host "`n== ROLLBACK: undoing module hardening ==" -ForegroundColor Yellow
    foreach ($name in $ResolvedModules) {
        $r = Invoke-HomeModulePhaseSafe -ModuleName $name -Phase Rollback -Remediate -Options $ModuleOptions[$name]
        if ($r.Error) {
            Write-Host "  ${name}:" -ForegroundColor Yellow
            Write-Warning "    rollback failed (continuing): $($r.Error)"
            Add-RunLog -Name $name -ErrorMsg $r.Error
        } elseif ($null -ne $r.Lines) {
            Write-Host "  ${name}:" -ForegroundColor Yellow
            $r.Lines | ForEach-Object { Write-Host "    $_" }
            Add-RunLog -Name $name -Action $r.Lines
        }
    }
    Write-HomeReport -Mode 'Rollback'
    Write-Host "`nRollback complete. Reboot to fully apply LSA/NetBIOS reversions." -ForegroundColor Green
    return
}

if (-not $Remediate) {
    Write-HomeReport -Mode 'Assess'
    Write-Host "`nDry run only. Re-run with -Remediate to apply the baseline." -ForegroundColor Green
    return
}

# =============================================================================
# 3. REMEDIATE: BACKUP
# =============================================================================
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

if (-not $SkipBackup) {
    Write-Host "`n== Backing up pre-change state to $OutputPath ==" -ForegroundColor Cyan

    $regBackups = @(
        @{ Hive = 'HKLM\SOFTWARE\Policies';                                File = 'HKLM-Software-Policies.reg' },
        @{ Hive = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa';             File = 'HKLM-Lsa.reg' },
        @{ Hive = 'HKLM\SYSTEM\CurrentControlSet\Services\NetBT';          File = 'HKLM-NetBT.reg' },
        @{ Hive = 'HKLM\SOFTWARE\Microsoft\Windows Script Host';           File = 'HKLM-WSH.reg' },
        @{ Hive = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; File = 'HKCU-ContentDeliveryManager.reg' }
    )
    foreach ($b in $regBackups) {
        & reg.exe export $b.Hive (Join-Path $OutputPath $b.File) /y 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  Exported $($b.Hive)"
        } else {
            Write-Warning "Could not export $($b.Hive) (key may not exist yet)."
        }
    }

    & netsh.exe advfirewall export (Join-Path $OutputPath 'firewall-policy.wfw') 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Host "  Exported firewall policy" }

    if (Import-HomeCompatModule -Name 'Dism') {
        try {
            Get-AppxProvisionedPackage -Online -ErrorAction Stop |
                Select-Object DisplayName, PackageName |
                Export-Csv -Path (Join-Path $OutputPath 'provisioned-appx-pre-change.csv') -NoTypeInformation
            Write-Host "  Exported provisioned-Appx package list"
        } catch {
            Write-Warning "Could not snapshot provisioned Appx packages: $($_.Exception.Message)"
        }
    }
}

# =============================================================================
# 4. REMEDIATE: MODULE HARDENING
# =============================================================================
$hardeningFailures = @()
foreach ($name in $ResolvedModules) {
    Write-Host "`nRunning '$name' module hardening..." -ForegroundColor Cyan
    $r = Invoke-HomeModulePhaseSafe -ModuleName $name -Phase Hardening -Remediate -Options $ModuleOptions[$name]
    if ($r.Error) {
        # One module failing (e.g. a protected policy key, a stuck service) must not abort the
        # rest of the baseline. Report it and move on; the pre-change backup is already written.
        Write-Warning "  '$name' hardening did not fully complete and was skipped: $($r.Error)"
        Add-RunLog -Name $name -ErrorMsg $r.Error
        $hardeningFailures += $name
    } elseif ($null -ne $r.Lines) {
        $r.Lines | ForEach-Object { Write-Host "  $_" }
        Add-RunLog -Name $name -Action $r.Lines
    }
}

Write-Host "`nDone. Pre-change backups: $OutputPath" -ForegroundColor Green
if ($hardeningFailures.Count -gt 0) {
    Write-Warning "These modules reported errors and may be only partially applied: $($hardeningFailures -join ', '). Re-run elevated and review the messages above; each module is independently re-runnable and rollback-able."
}
Write-HomeReport -Mode 'Remediate' -BackupPath $OutputPath
Write-Host "Reboot to apply LSA Protection (RunAsPPL) and the NetBIOS node type." -ForegroundColor Green
