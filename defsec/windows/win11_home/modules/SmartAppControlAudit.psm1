<#
.SYNOPSIS
    Status-only: reports Smart App Control state - Microsoft's built-in application-allowlisting
    layer and the closest thing Windows 11 Home has to AppLocker.

.DESCRIPTION
    Smart App Control (SAC) blocks untrusted/unsigned applications using the same WDAC engine
    enterprises use, works on every edition including Home, and cannot be tampered with from
    user mode. It is the single best AppLocker substitute on Home - but it has a hard
    constraint this baseline cannot script around: SAC can only be switched ON while it is in
    its post-install evaluation period (or after a clean install/reset). Once it has turned
    itself off, only a Windows reset re-arms it.

    Because of that, this module is deliberately status-only (no Hardening/Rollback): it tells
    you which of the three states the machine is in and what your options are, so the decision
    is made by a human at the right moment (ideally: reset/reinstall -> SAC stays in evaluation
    -> confirm it flips to On before piling on third-party tooling that would trip it to Off).

    States (HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy, VerifiedAndReputablePolicyState):
        1 = On          - untrusted apps are blocked. Keep it that way.
        2 = Evaluation  - Windows is deciding; avoid unsigned dev tools if you want it to latch On.
        0 = Off         - cannot be re-enabled without a Windows reset; the other modules in
                          this baseline are then your compensating controls.
#>

$script:SacKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'

function Get-SmartAppControlAuditStatus {
    $state = (Get-ItemProperty -Path $script:SacKey -Name 'VerifiedAndReputablePolicyState' -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
    switch ($state) {
        1 { @('Smart App Control: ON - untrusted/unsigned apps are blocked (best-available allowlisting on this edition). Do not turn it off; it cannot be re-enabled without a reset.') }
        2 { @('Smart App Control: EVALUATION - Windows is deciding whether to enable it. Avoid running unsigned/low-reputation tools during this period if you want it to latch On (Windows Security > App & browser control).') }
        0 { @('Smart App Control: OFF - it can only be re-enabled by resetting/reinstalling Windows. The other modules in this baseline are the compensating controls; on Pro/Enterprise, deploy the applocker baseline instead.') }
        default { @('Smart App Control: state unknown (registry value not present - pre-22H2 build or unsupported).') }
    }
}

Export-ModuleMember -Function Get-SmartAppControlAuditStatus
