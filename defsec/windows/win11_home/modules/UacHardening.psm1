<#
.SYNOPSIS
    Turns User Account Control up to "always prompt on the secure desktop" and puts the built-in
    Administrator into Admin Approval Mode - so silent, script-driven elevation on the initial
    vector dies and every real elevation is a visible gate.

.DESCRIPTION
    The single biggest weakness of a stock Home install is that the daily account is a local
    Administrator and UAC on its default setting auto-elevates several Windows paths without a
    prompt. This module doesn't change *who* is an admin (converting the daily account to a
    standard user is a manual, lock-out-sensitive step - see the status output and README), but it
    makes the admin token far harder to abuse:

    - EnableLUA=1: UAC on (non-negotiable; disabling it breaks the whole model and all UWP apps).
    - ConsentPromptBehaviorAdmin=2: admins must click through a consent prompt on the secure
      desktop for elevation (stricter than the default 5, which auto-consents for signed Windows
      binaries that malware abuses via UAC-bypass COM/auto-elevate tricks).
    - PromptOnSecureDesktop=1: the prompt is on the isolated secure desktop, so malware can't
      spoof or auto-click it.
    - ConsentPromptBehaviorUser=3: standard users get a credential prompt on the secure desktop
      (lets the household admin approve with a password rather than being denied outright).
    - FilterAdministratorToken=1: even the built-in Administrator runs in Admin Approval Mode.
    - EnableInstallerDetection=1: heuristic installer elevation still prompts.

    Balance: near-zero day-to-day friction - the user already answers "Yes" to install prompts;
    the change is that those prompts can no longer be bypassed silently and appear on the secure
    desktop. EnableLUA changes take effect after a reboot; the prompt-behavior values apply
    immediately.

    NOT done here (deliberately): auto-demoting the current account. Removing the last admin, or
    demoting the account you're logged into without a second admin present, can lock a
    non-technical user out of their own machine. The status output flags a lone-admin machine and
    the README documents the safe manual path (create a second admin, then set the daily account
    to Standard in Settings > Accounts).
#>

$script:PolicyKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

# name -> @{ Secure = hardened value; Default = Windows default (restored on rollback) }
$script:UacValues = [ordered]@{
    EnableLUA                     = @{ Secure = 1; Default = 1 }
    ConsentPromptBehaviorAdmin    = @{ Secure = 2; Default = 5 }
    ConsentPromptBehaviorUser     = @{ Secure = 3; Default = 3 }
    PromptOnSecureDesktop         = @{ Secure = 1; Default = 1 }
    FilterAdministratorToken      = @{ Secure = 1; Default = 0 }
    EnableInstallerDetection      = @{ Secure = 1; Default = 1 }
}

function Get-UacHardeningStatus {
    $out = @()
    $admin = (Get-ItemProperty -Path $script:PolicyKey -Name 'ConsentPromptBehaviorAdmin' -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
    $sd    = (Get-ItemProperty -Path $script:PolicyKey -Name 'PromptOnSecureDesktop' -ErrorAction SilentlyContinue).PromptOnSecureDesktop
    $fat   = (Get-ItemProperty -Path $script:PolicyKey -Name 'FilterAdministratorToken' -ErrorAction SilentlyContinue).FilterAdministratorToken
    $out += "UAC admin prompt: $(if ($admin -eq 2) { 'consent on secure desktop (hardened)' } else { "default/other ($admin)" }); secure desktop: $(if ($sd -eq 1) { 'on' } else { 'off' }); built-in admin approval mode: $(if ($fat -eq 1) { 'on' } else { 'off' })."

    # Lone-admin warning: enumerate enabled local admins.
    try {
        $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Where-Object { $_.ObjectClass -eq 'User' })
        $enabledLocalAdmins = @($admins | Where-Object {
                $n = ($_.Name -split '\\')[-1]
                $u = Get-LocalUser -Name $n -ErrorAction SilentlyContinue
                $u -and $u.Enabled
            })
        if ($enabledLocalAdmins.Count -le 1) {
            $out += "Account model: this machine's daily account appears to be the ONLY admin. Strongest single improvement: create a second admin, then set the daily account to Standard (Settings > Accounts). See README."
        } else {
            $out += "Account model: $($enabledLocalAdmins.Count) enabled local admin accounts. Consider running day-to-day as a Standard user."
        }
    } catch {
        $out += 'Account model: could not enumerate local admins (non-fatal).'
    }
    $out
}

function Invoke-UacHardeningHardening {
    param([switch]$Remediate)
    $out = @()
    foreach ($name in $script:UacValues.Keys) {
        if ($Remediate) {
            try {
                if (-not (Test-Path $script:PolicyKey)) { New-Item -Path $script:PolicyKey -Force -ErrorAction Stop | Out-Null }
                Set-ItemProperty -Path $script:PolicyKey -Name $name -Value $script:UacValues[$name].Secure -Type DWord -ErrorAction Stop
                $out += "Set $name = $($script:UacValues[$name].Secure)."
            } catch {
                $out += "SKIPPED ${name}: $($_.Exception.Message)"
            }
        } else {
            $out += "(dry run) Would set $name = $($script:UacValues[$name].Secure) at $script:PolicyKey."
        }
    }
    if ($Remediate) { $out += 'UAC hardened. EnableLUA changes take effect after a reboot; prompt behavior applies immediately.' }
    $out
}

function Invoke-UacHardeningRollback {
    param([switch]$Remediate)
    $out = @()
    # Restore Windows DEFAULT values rather than deleting - deleting EnableLUA could disable UAC.
    foreach ($name in $script:UacValues.Keys) {
        if ($Remediate) {
            try {
                Set-ItemProperty -Path $script:PolicyKey -Name $name -Value $script:UacValues[$name].Default -Type DWord -ErrorAction Stop
                $out += "Restored $name to the Windows default ($($script:UacValues[$name].Default))."
            } catch {
                $out += "Could not restore ${name}: $($_.Exception.Message)"
            }
        } else {
            $out += "(dry run) Would restore $name to its Windows default ($($script:UacValues[$name].Default))."
        }
    }
    $out
}

Export-ModuleMember -Function Get-UacHardeningStatus, Invoke-UacHardeningHardening, Invoke-UacHardeningRollback
