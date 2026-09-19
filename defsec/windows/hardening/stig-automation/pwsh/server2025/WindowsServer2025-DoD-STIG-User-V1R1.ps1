<#
.SYNOPSIS
    DoD WinSvr 2025 MS STIG User v1r1

.DESCRIPTION
    This script checks and optionally remediates user-level settings for the DoD Windows Server
    2025 MS STIG User v1r1. It evaluates compliance based on registry values and provides a report.

.PARAMETER StigId
    Target one or more specific VIDs (e.g. V-278240) instead of the whole baseline. When
    supplied, Severity and the RulesFile are ignored - only the listed ID(s) are
    evaluated/remediated. Unknown IDs are reported with a warning and otherwise skipped.

.PARAMETER Severity
    Which CRITICALITY levels to evaluate. Default: High, Medium, Low.

.PARAMETER RulesFile
    Path to an INI file listing one VID per line that toggles which rules are in scope -
    comment out a line (prefix with ; or #) to exclude that control. Defaults to
    "WindowsServer2025-DoD-STIG-User-V1R1.ini" next to this script, if present. Ignored when
    -StigId is supplied.

.PARAMETER IgnoreRulesFile
    Skip the INI include/exclude file even if it exists, and evaluate every rule.

.PARAMETER ListRules
    Print the in-scope rules (after Severity/StigId/RulesFile filtering) and exit. No changes made.

.EXAMPLE
    # Check compliance only
    .\WindowsServer2025-DoD-STIG-User-V1R1.ps1

    # Check and remediate non-compliant settings
    .\WindowsServer2025-DoD-STIG-User-V1R1.ps1 -Remediate

.NOTES
    Author: Robert Weber
#>

[CmdletBinding()]
param(
    [switch]$Remediate,

    [ValidateSet('High','Medium','Low')]
    [string[]]$Severity = @('High','Medium','Low'),

    # One or more specific VIDs. Overrides Severity/RulesFile scoping when supplied.
    [string[]]$StigId,

    # INI include/exclude list. Defaults to <ScriptName>.ini next to this script when present.
    [string]$RulesFile,
    [switch]$IgnoreRulesFile,

    [switch]$ListRules,
    [switch]$PassThru
)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { $null }
}

function Set-RegValue {
    param([string]$Path, [string]$Name, [object]$Value, [string]$Type = "DWord")
    if (!(Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}

# Reads an INI rules file (see WindowsServer2025-DoD-STIG-User-V1R1.ini) and returns the
# VIDs that are still active, i.e. NOT commented out with a leading ';' or '#'.
function Get-EnabledStigIdsFromIni {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    $enabled = [System.Collections.Generic.List[string]]::new()
    foreach ($line in Get-Content -Path $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith(';') -or $trimmed.StartsWith('#') -or $trimmed.StartsWith('[')) { continue }
        if ($trimmed -match '^([^=]+?)\s*=') { $enabled.Add($matches[1].Trim()) }
    }
    $enabled
}

# =============================================================================
# STIG RULES ARRAY
# =============================================================================
$rules = @(
    [pscustomobject]@{VID="V-278240"; Title="Do not preserve zone information in file attachments"; Severity="Medium"; Description="Windows Server 2025 must preserve zone information when saving attachments."; CheckType="Registry"; Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"; Name="SaveZoneInformation"; Expected=2},
    [pscustomobject]@{VID="V-278121"; Title="Always install with elevated privileges"; Severity="High"; Description="Windows Server 2025 must disable the Windows Installer Always install with elevated privileges option."; CheckType="Registry"; Path="HKCU:\Software\Policies\Microsoft\Windows\Installer"; Name="AlwaysInstallElevated"; Expected=0}
)

# =============================================================================
# SCOPE FILTER (by StigId, else Severity / RulesFile)
# =============================================================================
if ($StigId) {
    $scoped  = $rules | Where-Object { $_.VID -in $StigId }
    $missing = $StigId | Where-Object { $_ -notin $rules.VID }
    if ($missing) {
        Write-Warning "No rule found for STIG ID(s): $($missing -join ', ')"
    }
} else {
    $scoped = $rules | Where-Object { $_.Severity -in $Severity }
    if (-not $IgnoreRulesFile) {
        $iniPath = if ($RulesFile) { $RulesFile } else { Join-Path $PSScriptRoot 'WindowsServer2025-DoD-STIG-User-V1R1.ini' }
        $enabled = Get-EnabledStigIdsFromIni -Path $iniPath
        if ($null -ne $enabled) {
            $scoped = $scoped | Where-Object { $_.VID -in $enabled }
            if (-not $PassThru) { Write-Host "Rules file   : $iniPath" -ForegroundColor DarkGray }
        } elseif ($RulesFile -and -not $PassThru) {
            Write-Warning "RulesFile '$RulesFile' not found - ignoring."
        }
    }
}

if (-not $scoped) {
    if (-not $PassThru) { Write-Host "No rules match the selected -Severity / -StigId / RulesFile. Nothing to do." -ForegroundColor Yellow }
    return
}

if ($ListRules) {
    if ($PassThru) { return $scoped }
    $scoped | Sort-Object Severity, VID | Format-Table VID, Severity, Title, Description -AutoSize -Wrap
    Write-Host "`n$($scoped.Count) rule(s) in scope." -ForegroundColor Cyan
    return
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================
$report = @()

foreach ($rule in $scoped) {
    $status = "Non-Compliant"
    $remediated = $false
    $current = Get-RegValue -Path $rule.Path -Name $rule.Name

    if ($current -eq $rule.Expected) {
        $status = "Compliant"
    }
    elseif ($Remediate) {
        Set-RegValue -Path $rule.Path -Name $rule.Name -Value $rule.Expected
        $remediated = $true
    }

    $report += [pscustomobject]@{
        VID         = $rule.VID
        Sev         = $rule.Severity
        Title       = $rule.Title
        Description = $rule.Description
        Status      = $status
        Remediated  = if ($Remediate -and $remediated) { "Yes" } else { "No" }
        Current     = if ($null -eq $current) { "Not Set" } else { $current }
    }
}

# =============================================================================
# OUTPUT
# =============================================================================
if ($PassThru) { return $report }

$report | Sort-Object Sev, VID | Format-Table VID, Sev, Title, Status, Remediated, Current -AutoSize

if ($Remediate) {
    Write-Host "`nRemediation complete for all DoD WinSvr 2025 MS STIG User v1r1 rules!" -ForegroundColor Green
} else {
    Write-Host "`nRun with -Remediate to fix Non-Compliant items." -ForegroundColor Cyan
}
Write-Host "DoD WinSvr 2025 MS STIG User v1r1 is finished." -ForegroundColor White
