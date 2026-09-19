<#
.SYNOPSIS
    Pure dispatch/helper functions for Invoke-StigHardening.ps1, split out so Pester can
    exercise them without running the full backup/assess/remediate pipeline.

.DESCRIPTION
    Dot-sourced by Invoke-StigHardening.ps1. Everything here is side-effect free (no registry,
    secedit, auditpol, or filesystem writes) so tests can call it directly.
#>

# Maps a discovered host (OSCaption) to the matching per-OS rule scripts in this repo.
function Resolve-StigSet {
    param(
        [Parameter(Mandatory)] $Sys,
        [Parameter(Mandatory)] [string]$RootPath
    )
    $cap = "$($Sys.OSCaption)"
    if     ($cap -match 'Windows 11')   { $key = 'win11' }
    elseif ($cap -match 'Server 2025')  { $key = 'server2025' }
    elseif ($cap -match 'Server 2022')  { $key = 'server2022' }
    else                                { $key = $null }

    switch ($key) {
        'win11' {
            [pscustomobject]@{
                Name     = 'Windows 11 STIG V2R7'
                Computer = Join-Path $RootPath 'win11\Windows11-STIG-Computer-V2R7.ps1'
                User     = Join-Path $RootPath 'win11\Windows11-STIG-User-V2R7.ps1'
            }
        }
        'server2025' {
            [pscustomobject]@{
                Name     = 'Windows Server 2025 DoD STIG V1R1'
                Computer = Join-Path $RootPath 'server2025\WindowsServer2025-DoD-STIG-Computer-V1R1.ps1'
                User     = Join-Path $RootPath 'server2025\WindowsServer2025-DoD-STIG-User-V1R1.ps1'
            }
        }
        'server2022' {
            [pscustomobject]@{
                Name     = 'Windows Server 2022 STIG V2R7'
                Computer = Join-Path $RootPath 'server2022\WindowsServer2022-STIG-V2R7.ps1'
                User     = $null
            }
        }
        default { $null }
    }
}

# Returns the ValidateSet values declared on a command's parameter, or $null if the param
# doesn't exist / has no ValidateSet.
function Get-ValidSetValues {
    param($Cmd, [string]$ParamName)
    if (-not $Cmd.Parameters.ContainsKey($ParamName)) { return $null }
    $vs = $Cmd.Parameters[$ParamName].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
    if ($vs) { $vs.ValidValues } else { @() }
}

# Builds the splat hashtable for a child rule script, forwarding only the parameters that
# script actually declares (so older/simpler children just run with their own defaults).
function Get-ChildScriptParams {
    param(
        [Parameter(Mandatory)] $Cmd,
        [string[]]$Section,
        [string[]]$Severity,
        [string[]]$StigId,
        [string]$RulesFile,
        [switch]$IgnoreRulesFile,
        [switch]$DoRemediate
    )
    $params = @{ PassThru = $true }
    if ($DoRemediate) { $params.Remediate = $true }

    if ($Cmd.Parameters.ContainsKey('Section')) {
        $valid = Get-ValidSetValues -Cmd $Cmd -ParamName 'Section'
        $pass  = if ($Section -contains 'All') { @('All') }
                 elseif ($valid) { @($Section | Where-Object { $_ -in $valid }) }
                 else { $Section }
        if ($pass) { $params.Section = $pass }
    }
    if ($Cmd.Parameters.ContainsKey('Severity')) { $params.Severity = $Severity }
    if ($StigId -and $Cmd.Parameters.ContainsKey('StigId')) { $params.StigId = $StigId }
    if ($RulesFile -and $Cmd.Parameters.ContainsKey('RulesFile')) { $params.RulesFile = $RulesFile }
    if ($IgnoreRulesFile -and $Cmd.Parameters.ContainsKey('IgnoreRulesFile')) { $params.IgnoreRulesFile = $true }

    $params
}

# Normalizes the differing report schemas (win11's STIGID/Section/Sev vs the server
# scripts' bare VID) into one common shape for the combined report/CSV.
function ConvertTo-NormalizedReportRow {
    param([Parameter(Mandatory, ValueFromPipeline)] $Row, [string]$Layer)
    process {
        $id = if ($Row.PSObject.Properties.Name -contains 'STIGID') { $Row.STIGID } else { $Row.VID }
        [pscustomobject]@{
            Layer      = $Layer
            Id         = $id
            Section    = if ($Row.PSObject.Properties.Name -contains 'Section') { $Row.Section } else { '(monolithic)' }
            Severity   = if ($Row.PSObject.Properties.Name -contains 'Sev')     { $Row.Sev }     else { '' }
            Title      = $Row.Title
            Status     = $Row.Status
            Remediated = if ($Row.PSObject.Properties.Name -contains 'Remediated') { $Row.Remediated } else { 'No' }
            Current    = if ($Row.PSObject.Properties.Name -contains 'Current')    { $Row.Current }    else { '' }
        }
    }
}
