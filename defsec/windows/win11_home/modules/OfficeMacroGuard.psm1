<#
.SYNOPSIS
    Opt-in: enables the Microsoft Defender ASR rules that interrupt the "enable macros to view
    this document" phishing chain.

.DESCRIPTION
    Ported from the applocker baseline. A malicious VBA macro runs inside an already-trusted
    copy of Word/Excel, so nothing gates what it does next - that's the whole point of the
    lure. Two Defender ASR rules close that gap:

        D4F940AB-401B-4EFC-AADC-AD5F3C50688A - Block all Office applications from creating child
            processes (stops a macro from launching powershell.exe/cmd.exe/mshta.exe/etc.)
        92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B - Block Win32 API calls from Office macros

    Opt-in because it requires Microsoft Defender to be the active AV (under a third-party AV
    these are silently ineffective or the cmdlets are absent - status/hardening detect that and
    say so). Also opt-in because it can break legitimate macro automation; enable it on machines
    that don't depend on trusted line-of-business macros.

    Note: if you run the stig\ layer, the Defender STIG already enables the full ASR set
    including these two - this module is here for a standalone Home deployment that skips STIG.
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
            try {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
                $results += "Enabled ASR rule: $($script:AsrRules[$ruleId])"
            } catch {
                # Defender may be inactive (third-party AV), tamper-protected, or the service
                # stopped. Report and keep going rather than aborting the run.
                $results += "Could not enable '$($script:AsrRules[$ruleId])': $($_.Exception.Message) (is Defender the active AV, with Tamper Protection allowing policy changes?)"
            }
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
                $results += "FAILED ($ruleId): $($_.Exception.Message)"
            }
        } else {
            $results += "(dry run) Would remove ASR rule: $($script:AsrRules[$ruleId])"
        }
    }
    $results
}

Export-ModuleMember -Function Get-OfficeMacroGuardStatus, Invoke-OfficeMacroGuardHardening, Invoke-OfficeMacroGuardRollback
