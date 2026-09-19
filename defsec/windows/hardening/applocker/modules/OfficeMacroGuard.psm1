<#
.SYNOPSIS
    Opt-in module: reports/enables the Microsoft Defender Attack Surface Reduction (ASR) rules
    that interrupt the "enable macros to view this document" phishing chain.

.DESCRIPTION
    AppLocker controls what EXEs/scripts/DLLs are allowed to run - it has no visibility into what
    a VBA macro inside an already-allowed, signed copy of Word/Excel does once it's running. That
    blind spot is exactly how most malicious-macro phishing works: the Office app itself is fully
    trusted, so AppLocker never gets a say. Two Defender ASR rules close that specific gap:

        D4F940AB-401B-4EFC-AADC-AD5F3C50688A - Block all Office applications from creating
            child processes (stops a macro from launching powershell.exe/cmd.exe/mshta.exe/etc.)
        92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B - Block Win32 API calls from Office macros

    Opt-in (not in the orchestrator's default module set) because it requires Microsoft Defender
    Antivirus to be the active real-time protection engine - under a third-party AV these rules
    are silently ineffective, or the cmdlets may be entirely absent. Status and hardening both
    detect that case and say so rather than failing unhelpfully.

    No AppLocker policy fragment - this module manages Defender ASR preferences, not AppLocker
    rules.
#>

$script:AsrRules = [ordered]@{
    'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' = 'Block all Office applications from creating child processes'
    '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' = 'Block Win32 API calls from Office macros'
}
$script:AsrActionLabels = @{ 0 = 'Disabled'; 1 = 'Block'; 2 = 'Audit'; 6 = 'Warn' }

function Get-OfficeMacroGuardStatus {
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        return @('Microsoft Defender PowerShell cmdlets not present - skipping (third-party AV, or Defender features unavailable).')
    }
    try {
        $pref = Get-MpPreference
        $ids = @($pref.AttackSurfaceReductionRules_Ids)
        $actions = @($pref.AttackSurfaceReductionRules_Actions)
        $results = @()
        foreach ($ruleId in $script:AsrRules.Keys) {
            $idx = [array]::IndexOf($ids, $ruleId)
            if ($idx -ge 0) {
                $code = [int]$actions[$idx]
                $label = $script:AsrActionLabels[$code]
                if (-not $label) { $label = "Unknown($code)" }
            } else {
                $label = 'NotConfigured'
            }
            $results += "$($script:AsrRules[$ruleId]): $label"
        }
        $results
    } catch {
        @("Unable to read Defender ASR rule state: $($_.Exception.Message)")
    }
}

function Invoke-OfficeMacroGuardHardening {
    param([switch]$Remediate)
    if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) {
        return @('Microsoft Defender PowerShell cmdlets not present - skipping.')
    }
    $results = @()
    foreach ($ruleId in $script:AsrRules.Keys) {
        if ($Remediate) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled
            $results += "Enabled ASR rule: $($script:AsrRules[$ruleId])"
        } else {
            $results += "(dry run) Would enable ASR rule: $($script:AsrRules[$ruleId])"
        }
    }
    $results
}

function Invoke-OfficeMacroGuardRollback {
    param([switch]$Remediate)
    if (-not (Get-Command Remove-MpPreference -ErrorAction SilentlyContinue)) {
        return @('Microsoft Defender PowerShell cmdlets not present - skipping.')
    }
    $results = @()
    foreach ($ruleId in $script:AsrRules.Keys) {
        if ($Remediate) {
            try {
                Remove-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -ErrorAction Stop
                $results += "Removed ASR rule: $($script:AsrRules[$ruleId])"
            } catch {
                Write-Warning "Failed to remove ASR rule $ruleId`: $($_.Exception.Message)"
                $results += "FAILED ($ruleId): $($_.Exception.Message)"
            }
        } else {
            $results += "(dry run) Would remove ASR rule: $($script:AsrRules[$ruleId])"
        }
    }
    $results
}

Export-ModuleMember -Function Get-OfficeMacroGuardStatus, Invoke-OfficeMacroGuardHardening, Invoke-OfficeMacroGuardRollback
