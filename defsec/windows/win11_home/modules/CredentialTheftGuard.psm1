<#
.SYNOPSIS
    Runs LSASS as a Protected Process Light (RunAsPPL) so a compromised admin session cannot
    dump credentials and pivot with them.

.DESCRIPTION
    The single highest-value post-compromise move is reading LSASS memory (Mimikatz,
    comsvcs.dll MiniDump, nanodump and friends) to steal password hashes and Kerberos tickets
    for lateral movement. LSA Protection (RunAsPPL=1) makes LSASS a Protected Process Light:
    even code running as full Administrator cannot open it with the access rights needed to
    read memory - the attacker is forced to bring a vulnerable driver (BYOVD), which is far
    noisier and separately mitigated by Defender's vulnerable-driver blocklist.

    New Windows 11 22H2+ installs enable this by default, but upgrades from Windows 10 and
    machines where an AV product or user turned it off do not have it - this module makes the
    state explicit and enforced. Works on every edition including Home.

    Complementary controls deliberately NOT set here:
    - WDigest UseLogonCredential=0 and Credential Guard (LsaCfgFlags): already covered by the
      stig\win11 baseline (WN11-CC-000038, WN11-CC-000075), which is registry-driven and runs
      on Home too.
    - Defender Tamper Protection: cannot be enabled by script by design (that's the point of
      it) - the Status output tells you to verify it in the Windows Security app.

    Compatibility note: the rare thing RunAsPPL breaks is a third-party credential provider or
    authentication plugin that injects into LSASS unsigned. If smartcard/biometric/SSO login
    breaks after a reboot, roll back this module only.
#>

$script:LsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

function Get-CredentialTheftGuardStatus {
    $out = @()
    $ppl = (Get-ItemProperty -Path $script:LsaKey -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL
    if ($ppl -eq 1 -or $ppl -eq 2) {
        $out += "LSA Protection (RunAsPPL): enabled ($ppl) - LSASS memory cannot be dumped from user mode."
    } else {
        $out += 'LSA Protection (RunAsPPL): NOT enabled - an elevated attacker can dump LSASS and steal credentials.'
    }
    $out += 'Reminder: verify Tamper Protection is On in Windows Security > Virus & threat protection settings (not scriptable by design).'
    $out
}

function Invoke-CredentialTheftGuardHardening {
    param([switch]$Remediate)
    if ($Remediate) {
        Set-ItemProperty -Path $script:LsaKey -Name 'RunAsPPL' -Value 1 -Type DWord
        @('Enabled LSA Protection (RunAsPPL=1). Takes effect after the next reboot; LSASS then runs as a protected process.')
    } else {
        @("(dry run) Would set $script:LsaKey\RunAsPPL = 1 (LSASS as Protected Process Light, effective after reboot).")
    }
}

function Invoke-CredentialTheftGuardRollback {
    param([switch]$Remediate)
    if ($Remediate) {
        try {
            Remove-ItemProperty -Path $script:LsaKey -Name 'RunAsPPL' -Force -ErrorAction Stop
            @('Removed the RunAsPPL value (effective after reboot). Note: Windows 11 22H2+ may re-enable LSA protection on its own default schedule.')
        } catch {
            @("RunAsPPL not present or not removable: $($_.Exception.Message)")
        }
    } else {
        $ppl = (Get-ItemProperty -Path $script:LsaKey -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL
        @("(dry run) Would remove $script:LsaKey\RunAsPPL (currently $(if ($null -ne $ppl) { $ppl } else { 'not set' })).")
    }
}

Export-ModuleMember -Function Get-CredentialTheftGuardStatus, Invoke-CredentialTheftGuardHardening, Invoke-CredentialTheftGuardRollback
