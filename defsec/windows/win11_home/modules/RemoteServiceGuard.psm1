<#
.SYNOPSIS
    Disables the remote-management services adversaries pivot through (WinRM, Remote Registry)
    - services a home/standalone machine has no business exposing.

.DESCRIPTION
    Lateral movement's favorite doors after credential theft are the built-in remote-management
    channels: WinRM (Invoke-Command / winrs, used by virtually every post-exploitation framework)
    and Remote Registry (remote credential/secret harvesting and remote persistence). On a
    domain-managed fleet these are legitimate tools; on a home or standalone workstation nothing
    uses them - they are pure inbound attack surface for an adversary who has landed on any
    other device on the same network.

    This module stops and disables both services. The stig\win11 baseline already hardens
    WinRM's authentication (no Basic, no unencrypted, no stored RunAs) but leaves the service
    present; here it is turned off outright.

    Trade-offs (see README balance section):
    - Enter-PSSession/Invoke-Command TO this machine stops working. Outbound remoting FROM this
      machine to others is unaffected.
    - Deliberately NOT touched: Print Spooler (printing), LanmanServer (sharing folders/printers
      to the household), Quick Assist (the sanctioned way to get remote help), and RDP (not a
      host feature on Home; STIG covers its policy hardening on Pro+).
#>

$script:Services = @(
    @{ Name = 'WinRM';          Reason = 'PowerShell remoting host - the standard lateral-movement channel' },
    @{ Name = 'RemoteRegistry'; Reason = 'remote registry read/write - remote secret harvesting and persistence' }
)

function Get-RemoteServiceGuardStatus {
    $out = @()
    foreach ($s in $script:Services) {
        $svc = Get-Service -Name $s.Name -ErrorAction SilentlyContinue
        if (-not $svc) {
            $out += "$($s.Name): not installed."
        } elseif ($svc.StartType -eq 'Disabled') {
            $out += "$($s.Name): disabled (status: $($svc.Status))."
        } else {
            $out += "$($s.Name): $($svc.Status), StartType=$($svc.StartType) - available as a pivot channel ($($s.Reason))."
        }
    }
    $out
}

function Invoke-RemoteServiceGuardHardening {
    param([switch]$Remediate)
    $out = @()
    foreach ($s in $script:Services) {
        $svc = Get-Service -Name $s.Name -ErrorAction SilentlyContinue
        if (-not $svc) {
            $out += "$($s.Name): not installed - nothing to do."
            continue
        }
        if ($Remediate) {
            if ($svc.Status -ne 'Stopped') {
                Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
            }
            try {
                Set-Service -Name $s.Name -StartupType Disabled -ErrorAction Stop
                $out += "Stopped and disabled $($s.Name) ($($s.Reason))."
            } catch {
                $out += "Could not disable $($s.Name): $($_.Exception.Message) (requires elevation)."
            }
        } else {
            $out += "(dry run) Would stop and disable $($s.Name) (currently $($svc.Status), StartType=$($svc.StartType))."
        }
    }
    $out
}

function Invoke-RemoteServiceGuardRollback {
    param([switch]$Remediate)
    $out = @()
    # Windows defaults: WinRM=Manual, RemoteRegistry=Disabled on Windows 11 client. Restore
    # those defaults rather than blindly enabling everything.
    $defaults = @{ WinRM = 'Manual'; RemoteRegistry = 'Disabled' }
    foreach ($s in $script:Services) {
        $svc = Get-Service -Name $s.Name -ErrorAction SilentlyContinue
        if (-not $svc) {
            $out += "$($s.Name): not installed - nothing to undo."
            continue
        }
        $target = $defaults[$s.Name]
        if ($Remediate) {
            try {
                Set-Service -Name $s.Name -StartupType $target -ErrorAction Stop
                $out += "Restored $($s.Name) startup type to the Windows 11 default ($target)."
            } catch {
                $out += "Could not restore $($s.Name): $($_.Exception.Message) (requires elevation)."
            }
        } else {
            $out += "(dry run) Would restore $($s.Name) startup type to $target (currently $($svc.StartType))."
        }
    }
    $out
}

Export-ModuleMember -Function Get-RemoteServiceGuardStatus, Invoke-RemoteServiceGuardHardening, Invoke-RemoteServiceGuardRollback
