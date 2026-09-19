<#
.SYNOPSIS
    Turns OS-level SmartScreen up from "Warn" (click-through) to "Block", and enables PUA
    (potentially-unwanted-app) blocking - so a user who clicks through every warning can't run a
    bad-reputation download or installer.

.DESCRIPTION
    The Windows STIG turns SmartScreen on but leaves it at "Warn," which a non-technical user
    just clicks past - for that population "Warn" is barely better than off. This module:

    - ShellSmartScreenLevel = Block (with EnableSmartScreen=1): a download/app with a bad or
      unknown reputation is BLOCKED, not merely warned, and there is no "run anyway" button.
    - SmartScreen for Microsoft Store apps enabled.
    - Defender PUA protection = Block: adware, bundleware, fake "PC cleaners", coin miners and
      other junk that isn't quite malware but is the on-ramp to it.

    Balance: the only real cost is that a genuinely obscure, unsigned indie tool may be blocked -
    something a typical home user essentially never needs, and which a household admin can still
    allow deliberately. Registry-only, reversible.
#>

$script:SysPolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
$script:DefenderPolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'

function Get-SmartScreenOsGuardStatus {
    $en    = (Get-ItemProperty -Path $script:SysPolicyKey -Name 'EnableSmartScreen' -ErrorAction SilentlyContinue).EnableSmartScreen
    $level = (Get-ItemProperty -Path $script:SysPolicyKey -Name 'ShellSmartScreenLevel' -ErrorAction SilentlyContinue).ShellSmartScreenLevel
    $pua   = (Get-ItemProperty -Path $script:DefenderPolicyKey -Name 'PUAProtection' -ErrorAction SilentlyContinue).PUAProtection
    @(
        "OS SmartScreen: $(if ($en -eq 1 -and $level -eq 'Block') { 'enabled at Block (no click-through)' } elseif ($en -eq 1) { "enabled at '$level' (click-through)" } else { 'not enforced by policy' })."
        "Potentially-unwanted-app blocking: $(if ($pua -eq 1) { 'on (Block)' } else { 'not enforced' })."
    )
}

function Set-SmartScreenValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type)
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -ErrorAction Stop
        $null
    } catch { "SKIPPED ${Path}\${Name}: $($_.Exception.Message)" }
}

function Invoke-SmartScreenOsGuardHardening {
    param([switch]$Remediate)
    if (-not $Remediate) {
        return @(
            "(dry run) Would set EnableSmartScreen=1 and ShellSmartScreenLevel=Block at $script:SysPolicyKey.",
            "(dry run) Would set Defender PUAProtection=1 at $script:DefenderPolicyKey."
        )
    }
    $out = @()
    $errs = @()
    $errs += Set-SmartScreenValue -Path $script:SysPolicyKey -Name 'EnableSmartScreen' -Value 1 -Type DWord
    $errs += Set-SmartScreenValue -Path $script:SysPolicyKey -Name 'ShellSmartScreenLevel' -Value 'Block' -Type String
    $out += 'Set OS SmartScreen to Block (no click-through on bad-reputation apps/files).'
    $errs += Set-SmartScreenValue -Path $script:DefenderPolicyKey -Name 'PUAProtection' -Value 1 -Type DWord
    $out += 'Enabled Defender PUA (potentially-unwanted-app) blocking.'
    $errs = @($errs | Where-Object { $_ })
    if ($errs) { $out += $errs }
    $out
}

function Invoke-SmartScreenOsGuardRollback {
    param([switch]$Remediate)
    if ($Remediate) {
        Remove-ItemProperty -Path $script:SysPolicyKey -Name 'ShellSmartScreenLevel' -Force -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $script:DefenderPolicyKey -Name 'PUAProtection' -Force -ErrorAction SilentlyContinue
        # Leave EnableSmartScreen=1 in place (turning SmartScreen off entirely would be a downgrade).
        @('Removed the SmartScreen Block level and PUA override (SmartScreen remains enabled at the Windows default).')
    } else {
        @('(dry run) Would remove ShellSmartScreenLevel and PUAProtection overrides (SmartScreen stays on at default).')
    }
}

Export-ModuleMember -Function Get-SmartScreenOsGuardStatus, Invoke-SmartScreenOsGuardHardening, Invoke-SmartScreenOsGuardRollback
