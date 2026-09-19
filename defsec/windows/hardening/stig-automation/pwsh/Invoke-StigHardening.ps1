<#
.SYNOPSIS
    Host-aware STIG hardening orchestrator for Windows 11 / Server 2022 / Server 2025.

.DESCRIPTION
    One entry point that decides WHICH STIG applies to THIS box (self-discovery), then drives
    the per-OS rule scripts in this repo so security is applied in graduated layers instead of
    one monolithic blast. Flow:

        1. Discover the host (hostname, IP, make/model, OS, domain) and pick the applicable STIG.
        2. Back up the registry + local security policy + audit policy (for recovery).
        3. ASSESS (dry run, no changes) and write a pre-remediation report + CSV.
        4. REMEDIATE the in-scope rules (only with -Remediate).
        5. RE-ASSESS and write a post-remediation report + CSV.
        6. Emit a combined summary + system-details header.

    The "different levels of security" come from -Section (control type) and -Severity
    (criticality), which are forwarded to whichever child scripts understand them. Children that
    don't (the current Server scripts) are run whole and simply tagged as a single section.

.PARAMETER Remediate
    Apply fixes. Without it the orchestrator only assesses (steps 1-3) - a safe dry run.

.PARAMETER Section
    Control types to apply (forwarded to children that support it). Default: the laptop/workstation
    set. Use 'All' for everything including Domain/DoD/Restrictive extras.

.PARAMETER Severity
    Criticality levels to apply. Default: High, Medium, Low.

.PARAMETER StigId
    Target one or more specific STIG IDs (e.g. WN11-SO-000195, V-254238). Forwarded only to
    child scripts that declare a -StigId parameter (all of them, as of this writing); overrides
    their Section/Severity/RulesFile scoping for this run.

.PARAMETER RulesFile
    Path to a child script's INI include/exclude file (see the .ini next to each rule script).
    Forwarded only to children that declare a -RulesFile parameter. Ignored by a child if its
    own -StigId is also in effect.

.PARAMETER IgnoreRulesFile
    Forwarded to every child that declares -IgnoreRulesFile, so the whole run ignores each
    script's INI include/exclude file and evaluates every rule.

.PARAMETER Scope
    Computer, User, or Both (default). Selects machine-level and/or per-user rule scripts.

.PARAMETER OutputPath
    Folder for reports/CSV/backups. Default: .\StigReports\<HOSTNAME>-<timestamp>\

.PARAMETER SkipBackup
    Skip the registry / policy backup step (not recommended).

.PARAMETER Force
    Bypass the "is this OS supported / are you sure" confirmation before remediating.

.EXAMPLE
    # Safe dry run - assess only, full report, no changes
    .\Invoke-StigHardening.ps1

.EXAMPLE
    # Apply only High + Medium across the default sections, then reassess
    .\Invoke-StigHardening.ps1 -Remediate -Severity High,Medium

.EXAMPLE
    # Apply just the audit + user-rights layers (Win11)
    .\Invoke-StigHardening.ps1 -Remediate -Section AuditPolicy,UserRights

.EXAMPLE
    # Apply one specific control on a Win11 box
    .\Invoke-StigHardening.ps1 -Remediate -StigId WN11-SO-000195

.NOTES
    Author: Robert Weber
    Run from an elevated PowerShell session.
#>

[CmdletBinding()]
param(
    [switch]$Remediate,
    [string[]]$Section   = @('AccountPolicy','UserRights','AuditPolicy','SecurityOptions','ComputerConfig','System'),
    [ValidateSet('High','Medium','Low')]
    [string[]]$Severity  = @('High','Medium','Low'),
    [string[]]$StigId,
    [string]$RulesFile,
    [switch]$IgnoreRulesFile,
    [ValidateSet('Computer','User','Both')]
    [string]$Scope       = 'Both',
    [string]$OutputPath,
    [switch]$SkipBackup,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $root 'Invoke-StigHardening.Functions.ps1')

# =============================================================================
# 0. PRE-FLIGHT
# =============================================================================
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-Admin)) {
    Write-Warning "Not running elevated. Remediation and policy/registry backup require Administrator."
    if ($Remediate -and -not $Force) { throw "Re-run from an elevated PowerShell session (or pass -Force to override)." }
}

# =============================================================================
# 1. HOST DISCOVERY  +  STIG APPLICABILITY
# =============================================================================
function Get-SystemDetails {
    $cs  = Get-CimInstance Win32_ComputerSystem      -ErrorAction SilentlyContinue
    $os  = Get-CimInstance Win32_OperatingSystem     -ErrorAction SilentlyContinue
    $bios= Get-CimInstance Win32_BIOS                -ErrorAction SilentlyContinue
    $ips = @()
    try {
        $ips = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' }).IPAddress
    } catch {
        $ips = (Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue |
                Where-Object { $_.IPEnabled }).IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }
    }
    $ptype = switch ($os.ProductType) { 1 {'Workstation'} 2 {'Domain Controller'} 3 {'Server'} default {'Unknown'} }

    [pscustomobject]@{
        Hostname      = $env:COMPUTERNAME
        FQDN          = "$($env:COMPUTERNAME).$($cs.Domain)"
        IPv4          = ($ips -join ', ')
        Manufacturer  = $cs.Manufacturer
        Model         = $cs.Model
        SerialNumber  = $bios.SerialNumber
        Domain        = $cs.Domain
        DomainJoined  = [bool]$cs.PartOfDomain
        OSCaption     = $os.Caption
        OSVersion     = $os.Version
        OSBuild       = $os.BuildNumber
        OSArchitecture= $os.OSArchitecture
        ProductType   = $ptype
        LastBootTime  = $os.LastBootUpTime
        InstallDate   = $os.InstallDate
        ScannedBy     = "$env:USERDOMAIN\$env:USERNAME"
        ScanTime      = (Get-Date)
    }
}

$sys     = Get-SystemDetails
$stigSet = Resolve-StigSet -Sys $sys -RootPath $root

Write-Host "================ HOST DISCOVERY ================" -ForegroundColor Cyan
$sys | Format-List | Out-String | Write-Host
if (-not $stigSet) {
    throw "No STIG baseline in this repo matches '$($sys.OSCaption)'. Supported: Windows 11, Server 2022, Server 2025."
}
Write-Host "Applicable baseline : $($stigSet.Name)" -ForegroundColor Green
Write-Host "Scope               : $Scope" -ForegroundColor Green
Write-Host "Sections requested  : $($Section -join ', ')" -ForegroundColor Green
Write-Host "Severity requested  : $($Severity -join ', ')" -ForegroundColor Green
if ($StigId) { Write-Host "StigId requested    : $($StigId -join ', ')" -ForegroundColor Green }
Write-Host "Mode                : $(if($Remediate){'ASSESS -> REMEDIATE -> RE-ASSESS'}else{'ASSESS ONLY (dry run)'})`n" -ForegroundColor Green

# Output folder
if (-not $OutputPath) {
    $stamp      = Get-Date -Format 'yyyyMMdd-HHmmss'
    $OutputPath = Join-Path $root ("StigReports\{0}-{1}" -f $sys.Hostname, $stamp)
}
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
Write-Host "Output folder       : $OutputPath`n" -ForegroundColor DarkGray

# =============================================================================
# 2. BACKUP (registry + local security policy + audit policy)
# =============================================================================
function Invoke-Backup {
    param([string]$Dir)
    $bk = Join-Path $Dir 'backup'
    New-Item -ItemType Directory -Path $bk -Force | Out-Null
    Write-Host "[Backup] Exporting registry hives + policy state for recovery..." -ForegroundColor Yellow

    $hives = @(
        @{ N='HKLM-SOFTWARE'; K='HKLM\SOFTWARE' },
        @{ N='HKLM-SYSTEM';   K='HKLM\SYSTEM'   },
        @{ N='HKCU-Software'; K='HKCU\Software' }
    )
    foreach ($h in $hives) {
        $out = Join-Path $bk "$($h.N).reg"
        try   { & reg.exe export $h.K $out /y *> $null; Write-Host "  saved $($h.N).reg" -ForegroundColor DarkGray }
        catch { Write-Warning "  could not export $($h.K): $($_.Exception.Message)" }
    }

    # Local security policy (account policy, user rights, security options)
    try {
        & secedit.exe /export /cfg (Join-Path $bk 'secpol-backup.inf') /quiet
        Write-Host "  saved secpol-backup.inf" -ForegroundColor DarkGray
    } catch { Write-Warning "  secedit backup failed: $($_.Exception.Message)" }

    # Advanced audit policy
    try {
        & auditpol.exe /backup /file:(Join-Path $bk 'auditpol-backup.csv') *> $null
        Write-Host "  saved auditpol-backup.csv" -ForegroundColor DarkGray
    } catch { Write-Warning "  auditpol backup failed: $($_.Exception.Message)" }

    # Recovery instructions
    @"
RECOVERY INSTRUCTIONS  ($(Get-Date))
=====================================
Registry:        reg import HKLM-SOFTWARE.reg   (repeat per .reg file)
Security policy:  secedit /configure /db secedit.sdb /cfg secpol-backup.inf
Audit policy:     auditpol /restore /file:auditpol-backup.csv

Restore from an elevated prompt in this folder. Reboot afterward.
NOTE: .reg import re-adds exported keys/values; it does not delete keys that were created
after the export. For a created-key rollback, delete the specific key, then re-import.
"@ | Set-Content -Path (Join-Path $bk 'RECOVERY-README.txt') -Encoding UTF8

    Write-Host "[Backup] Complete -> $bk`n" -ForegroundColor Yellow
}
if (-not $SkipBackup) { Invoke-Backup -Dir $OutputPath }
else { Write-Host "[Backup] SKIPPED (-SkipBackup).`n" -ForegroundColor Yellow }

# =============================================================================
# CHILD-SCRIPT DRIVER  (forwards only supported params; normalizes the report)
# Get-ChildScriptParams / ConvertTo-NormalizedReportRow / Resolve-StigSet live in
# Invoke-StigHardening.Functions.ps1 so Pester can exercise them directly.
# =============================================================================
function Invoke-StigScript {
    param([string]$ScriptPath, [string]$Layer, [switch]$DoRemediate)

    if (-not (Test-Path $ScriptPath)) { return @() }
    $cmd    = Get-Command -Name $ScriptPath
    $params = Get-ChildScriptParams -Cmd $cmd -Section $Section -Severity $Severity -StigId $StigId `
                -RulesFile $RulesFile -IgnoreRulesFile:$IgnoreRulesFile -DoRemediate:$DoRemediate

    $raw = & $ScriptPath @params
    $raw | ConvertTo-NormalizedReportRow -Layer $Layer
}

function Invoke-Phase {
    param([switch]$DoRemediate)
    $results = @()
    if ($Scope -in @('Computer','Both') -and $stigSet.Computer) {
        $results += Invoke-StigScript -ScriptPath $stigSet.Computer -Layer 'Computer' -DoRemediate:$DoRemediate
    }
    if ($Scope -in @('User','Both') -and $stigSet.User) {
        $results += Invoke-StigScript -ScriptPath $stigSet.User -Layer 'User' -DoRemediate:$DoRemediate
    }
    $results
}

function Write-PhaseSummary {
    param($Results, [string]$Label)
    $total = $Results.Count
    $comp  = ($Results | Where-Object Status -eq 'Compliant').Count
    $non   = $total - $comp
    Write-Host ("{0}: {1}/{2} compliant, {3} non-compliant" -f $Label, $comp, $total, $non) -ForegroundColor White
    $Results | Where-Object Status -ne 'Compliant' |
        Group-Object Severity | Sort-Object Name |
        ForEach-Object { Write-Host ("    {0,-7} non-compliant: {1}" -f ($_.Name -as [string]), $_.Count) -ForegroundColor DarkGray }
}

# =============================================================================
# 3. ASSESS (dry run)
# =============================================================================
Write-Host "================ PHASE 1: ASSESS (dry run) ================" -ForegroundColor Cyan
$pre = Invoke-Phase
Write-PhaseSummary -Results $pre -Label 'Pre-remediation'
$pre | Sort-Object Layer, Section, Severity, Id |
    Export-Csv -Path (Join-Path $OutputPath 'assessment-pre.csv') -NoTypeInformation
Write-Host "  -> assessment-pre.csv`n" -ForegroundColor DarkGray

$post = $null
if ($Remediate) {
    if (-not $Force) {
        $ans = Read-Host "Proceed to REMEDIATE $(($pre | Where-Object Status -ne 'Compliant').Count) non-compliant item(s)? [y/N]"
        if ($ans -notmatch '^[Yy]') { Write-Host "Aborted before remediation. Assessment + backup were saved." -ForegroundColor Yellow; $Remediate = $false }
    }
}

# =============================================================================
# 4 & 5. REMEDIATE + RE-ASSESS
# =============================================================================
if ($Remediate) {
    Write-Host "`n================ PHASE 2: REMEDIATE ================" -ForegroundColor Cyan
    $applied = Invoke-Phase -DoRemediate
    ($applied | Where-Object Remediated -eq 'Yes') |
        Export-Csv -Path (Join-Path $OutputPath 'remediation-applied.csv') -NoTypeInformation
    Write-Host ("Applied fixes to {0} item(s) -> remediation-applied.csv" -f (($applied | Where-Object Remediated -eq 'Yes').Count)) -ForegroundColor Green

    Write-Host "`n================ PHASE 3: RE-ASSESS ================" -ForegroundColor Cyan
    $post = Invoke-Phase
    Write-PhaseSummary -Results $post -Label 'Post-remediation'
    $post | Sort-Object Layer, Section, Severity, Id |
        Export-Csv -Path (Join-Path $OutputPath 'assessment-post.csv') -NoTypeInformation
    Write-Host "  -> assessment-post.csv`n" -ForegroundColor DarkGray
}

# =============================================================================
# 6. COMBINED REPORT (system details header + before/after)
# =============================================================================
$final     = if ($post) { $post } else { $pre }
$preComp   = ($pre  | Where-Object Status -eq 'Compliant').Count
$postComp  = if ($post) { ($post | Where-Object Status -eq 'Compliant').Count } else { $null }

$reportTxt = Join-Path $OutputPath 'STIG-Report.txt'
$lines = @()
$lines += "=========================================================="
$lines += " STIG HARDENING REPORT"
$lines += "=========================================================="
$lines += " Baseline       : $($stigSet.Name)"
$lines += " Hostname       : $($sys.Hostname)   ($($sys.FQDN))"
$lines += " IPv4           : $($sys.IPv4)"
$lines += " Make / Model   : $($sys.Manufacturer) / $($sys.Model)"
$lines += " Serial         : $($sys.SerialNumber)"
$lines += " OS             : $($sys.OSCaption) ($($sys.OSArchitecture))"
$lines += " Version / Build: $($sys.OSVersion) / $($sys.OSBuild)"
$lines += " Product Type   : $($sys.ProductType)"
$lines += " Domain         : $($sys.Domain)  (Joined: $($sys.DomainJoined))"
$lines += " Last Boot      : $($sys.LastBootTime)"
$lines += " Scanned By     : $($sys.ScannedBy)"
$lines += " Scan Time      : $($sys.ScanTime)"
$lines += "----------------------------------------------------------"
$lines += " Scope          : $Scope"
$lines += " Sections       : $($Section -join ', ')"
$lines += " Severity       : $($Severity -join ', ')"
$lines += " Mode           : $(if($Remediate){'Remediated'}else{'Assessment only (dry run)'})"
$lines += "----------------------------------------------------------"
$lines += " Pre  compliant : $preComp / $($pre.Count)"
if ($null -ne $postComp) { $lines += " Post compliant : $postComp / $($post.Count)" }
$lines += "=========================================================="
$lines += ""
$lines += ($final | Sort-Object Layer, Section, Severity, Id |
           Format-Table Layer, Id, Section, Severity, Status, Remediated, Title -AutoSize | Out-String)
$lines | Set-Content -Path $reportTxt -Encoding UTF8

# System details as standalone CSV/JSON too
$sys | Export-Csv -Path (Join-Path $OutputPath 'system-details.csv') -NoTypeInformation
$sys | ConvertTo-Json -Depth 3 | Set-Content -Path (Join-Path $OutputPath 'system-details.json') -Encoding UTF8

Write-Host "================ DONE ================" -ForegroundColor Cyan
Write-Host "Report folder : $OutputPath" -ForegroundColor Green
Get-ChildItem $OutputPath -Recurse -File | ForEach-Object {
    Write-Host ("  {0}" -f $_.FullName.Substring($OutputPath.Length+1)) -ForegroundColor DarkGray
}
if ($Remediate -and ($post | Where-Object Status -ne 'Compliant')) {
    Write-Host "`nSome items remain non-compliant (often firmware/manual: TPM, Secure Boot, BitLocker, certs)." -ForegroundColor Yellow
    Write-Host "A reboot may also be required for account/audit/feature changes to fully apply." -ForegroundColor Yellow
}
