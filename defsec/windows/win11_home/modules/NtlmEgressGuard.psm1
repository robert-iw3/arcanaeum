<#
.SYNOPSIS
    Opt-in: blocks all outgoing NTLM authentication so this machine's credentials cannot be
    coerced, captured, or relayed by anything on the network.

.DESCRIPTION
    Even with LLMNR/NetBIOS poisoning shut down (NameResolutionGuard), an attacker who lures
    this machine into authenticating to a rogue endpoint - a UNC path in a shortcut/document,
    a coerced SMB connection, a captured WebDAV request - receives an NTLM challenge/response
    to crack offline or relay to another host. Denying outgoing NTLM entirely
    (RestrictSendingNTLMTraffic=2, Kerberos and local logons unaffected) removes that whole
    class of credential exposure.

    OPT-IN because the collateral is real for exactly the devices homes keep longest: NAS
    boxes, older printers/scanners with SMB shares, and some VPN/file servers authenticate
    with NTLM only - those connections will fail with this enabled. Workflow: run the audit
    step first (value 1, below), watch for legitimate NTLM use, then decide.

        # Audit only - log outgoing NTLM (Event Viewer: Microsoft-Windows-NTLM/Operational)
        Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictSendingNTLMTraffic' -Value 1 -Type DWord

    This module's Hardening applies the full deny (2). Rollback removes the restriction.
#>

$script:Msv1Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'

function Get-NtlmEgressGuardStatus {
    $val = (Get-ItemProperty -Path $script:Msv1Key -Name 'RestrictSendingNTLMTraffic' -ErrorAction SilentlyContinue).RestrictSendingNTLMTraffic
    switch ($val) {
        2 { @('Outgoing NTLM: DENIED (RestrictSendingNTLMTraffic=2) - credentials cannot be captured/relayed via NTLM.') }
        1 { @('Outgoing NTLM: audit mode (logged to Microsoft-Windows-NTLM/Operational, not blocked).') }
        default { @('Outgoing NTLM: allowed (default) - a lured/coerced connection hands out a crackable, relayable NTLM response.') }
    }
}

function Invoke-NtlmEgressGuardHardening {
    param([switch]$Remediate)
    if ($Remediate) {
        Set-ItemProperty -Path $script:Msv1Key -Name 'RestrictSendingNTLMTraffic' -Value 2 -Type DWord
        @('Denied all outgoing NTLM (RestrictSendingNTLMTraffic=2). NAS/printer shares that only speak NTLM will stop authenticating - roll back this module alone if that happens.')
    } else {
        @("(dry run) Would set $script:Msv1Key\RestrictSendingNTLMTraffic = 2 (deny all outgoing NTLM). Consider audit mode (=1) first; see module help.")
    }
}

function Invoke-NtlmEgressGuardRollback {
    param([switch]$Remediate)
    if ($Remediate) {
        try {
            Remove-ItemProperty -Path $script:Msv1Key -Name 'RestrictSendingNTLMTraffic' -Force -ErrorAction Stop
            @('Restored outgoing NTLM to the Windows default (restriction removed).')
        } catch {
            @("RestrictSendingNTLMTraffic not present: nothing to undo.")
        }
    } else {
        $val = (Get-ItemProperty -Path $script:Msv1Key -Name 'RestrictSendingNTLMTraffic' -ErrorAction SilentlyContinue).RestrictSendingNTLMTraffic
        @("(dry run) Would remove $script:Msv1Key\RestrictSendingNTLMTraffic (currently $(if ($null -ne $val) { $val } else { 'not set' })).")
    }
}

Export-ModuleMember -Function Get-NtlmEgressGuardStatus, Invoke-NtlmEgressGuardHardening, Invoke-NtlmEgressGuardRollback
