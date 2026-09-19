<#
.SYNOPSIS
    PowerShell automation for the Microsoft Windows 11 STIG V2R7 - User (HKCU) settings.

.DESCRIPTION
    Per-user STIG controls (current user's HKCU hive). Same Section/Severity model as the
    Computer script so an orchestrator can apply a consistent slice of the baseline.
    Run as the target user (these live under HKEY_CURRENT_USER).

.PARAMETER Remediate   Apply expected values for Non-Compliant rules.
.PARAMETER Section     Control types to evaluate. Default: UserConfig.
.PARAMETER Severity    Criticality levels. Default: High, Medium, Low.
.PARAMETER StigId      Target one or more specific STIG IDs instead of a Section/Severity
                        slice. Overrides Section/Severity (and the RulesFile) when supplied.
.PARAMETER RulesFile   INI include/exclude list (comment out a STIGID line to skip it).
                        Defaults to "Windows11-STIG-User-V2R7.ini" next to this script.
.PARAMETER IgnoreRulesFile  Skip the INI file even if present.
.PARAMETER ListRules   Print in-scope rules and exit.
.PARAMETER PassThru    Return report objects (quiet) for an orchestrator.

.EXAMPLE
    .\Windows11-STIG-User-V2R7.ps1 -Remediate

.EXAMPLE
    # Apply just one specific control
    .\Windows11-STIG-User-V2R7.ps1 -StigId WN11-UC-000020 -Remediate

.NOTES
    Author: Robert Weber
#>

[CmdletBinding()]
param(
    [switch]$Remediate,
    [ValidateSet('All','UserConfig')]
    [string[]]$Section = @('UserConfig'),
    [ValidateSet('High','Medium','Low')]
    [string[]]$Severity = @('High','Medium','Low'),

    # One or more specific STIG IDs. Overrides Section/Severity/RulesFile scoping when supplied.
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

# Reads an INI rules file (see Windows11-STIG-User-V2R7.ini) and returns the STIGIDs that
# are still active, i.e. NOT commented out with a leading ';' or '#'.
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
# STIG RULES ARRAY (HKCU)
# =============================================================================
$rules = @(
    [pscustomobject]@{STIGID="WN11-UC-000015"; Title="No toast notifications on lock screen";      Section="UserConfig"; Severity="Low";    CheckType="Registry"; Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"; Name="NoToastApplicationNotificationOnLockScreen"; Expected=1},
    [pscustomobject]@{STIGID="WN11-UC-000020"; Title="Preserve zone info on file attachments";     Section="UserConfig"; Severity="Medium"; CheckType="Registry"; Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"; Name="SaveZoneInformation"; Expected=2},
    [pscustomobject]@{STIGID="WN11-CC-000390"; Title="No third-party suggestions in spotlight";    Section="UserConfig"; Severity="Low";    CheckType="Registry"; Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name="DisableThirdPartySuggestions"; Expected=1}
)

# =============================================================================
# SCOPE FILTER (by StigId, else Section / Severity / RulesFile)
# =============================================================================
if ($StigId) {
    $scoped  = $rules | Where-Object { $_.STIGID -in $StigId }
    $missing = $StigId | Where-Object { $_ -notin $rules.STIGID }
    if ($missing) {
        Write-Warning "No rule found for STIG ID(s): $($missing -join ', ')"
    }
} else {
    if ($Section -contains 'All') { $scoped = $rules } else { $scoped = $rules | Where-Object { $_.Section -in $Section } }
    $scoped = $scoped | Where-Object { $_.Severity -in $Severity }

    if (-not $IgnoreRulesFile) {
        $iniPath = if ($RulesFile) { $RulesFile } else { Join-Path $PSScriptRoot 'Windows11-STIG-User-V2R7.ini' }
        $enabled = Get-EnabledStigIdsFromIni -Path $iniPath
        if ($null -ne $enabled) {
            $scoped = $scoped | Where-Object { $_.STIGID -in $enabled }
            if (-not $PassThru) { Write-Host "Rules file   : $iniPath" -ForegroundColor DarkGray }
        } elseif ($RulesFile -and -not $PassThru) {
            Write-Warning "RulesFile '$RulesFile' not found - ignoring."
        }
    }
}

if (-not $scoped) {
    if (-not $PassThru) { Write-Host "No rules match the selected -Section / -Severity / -StigId / RulesFile." -ForegroundColor Yellow }
    return
}
if ($ListRules) {
    if ($PassThru) { return $scoped }
    $scoped | Sort-Object Section, Severity, STIGID | Format-Table STIGID, Section, Severity, Title -AutoSize
    return
}
if (-not $PassThru) {
    Write-Host "Windows 11 STIG V2R7 (User) - $($scoped.Count) rule(s) in scope.  Mode: $(if($Remediate){'REMEDIATE'}else{'CHECK ONLY'})`n" -ForegroundColor White
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================
$report = @()
foreach ($rule in $scoped) {
    $status = "Non-Compliant"; $remediated = $false
    $type   = if ($rule.PSObject.Properties.Name -contains 'Type') { $rule.Type } else { 'DWord' }
    $current = Get-RegValue -Path $rule.Path -Name $rule.Name

    if ("$current" -eq "$($rule.Expected)") { $status = "Compliant" }
    elseif ($Remediate) { Set-RegValue -Path $rule.Path -Name $rule.Name -Value $rule.Expected -Type $type; $remediated = $true }

    $report += [pscustomobject]@{
        STIGID     = $rule.STIGID
        Section    = $rule.Section
        Sev        = $rule.Severity
        Title      = $rule.Title
        Status     = $status
        Remediated = if ($Remediate -and $remediated) { "Yes" } else { "No" }
        Current    = if ($null -eq $current -or "$current" -eq "") { "Not Set" } else { "$current" }
    }
}

# =============================================================================
# OUTPUT
# =============================================================================
if ($PassThru) { return $report }

$report | Sort-Object Section, Sev, STIGID | Format-Table STIGID, Section, Sev, Status, Remediated, Title -AutoSize
$compliant = ($report | Where-Object Status -eq 'Compliant').Count
Write-Host ("`nSummary: {0}/{1} compliant" -f $compliant, $report.Count) -ForegroundColor White
if (-not $Remediate) { Write-Host "Run with -Remediate to fix the Non-Compliant items above." -ForegroundColor Cyan }
