<#
.SYNOPSIS
    Opt-in: blocks known remote-access/RMM tools by filename using Image File Execution Options -
    the Home-edition replacement for the applocker baseline's "*\AnyDesk.exe" deny rules - plus a
    confined-account fallback for genuine support sessions.

.DESCRIPTION
    Two abuse patterns share one tool list:

    1. Tech-support scams talk a non-technical victim into downloading a portable remote-access
       tool (AnyDesk, UltraViewer, TeamViewer QuickSupport) so the "helper" can take over the
       machine and drain an account or install malware.
    2. CISA/NSA/MS-ISAC document legitimate RMM software (ScreenConnect, Atera, Splashtop,
       NetSupport) abused by ransomware actors for initial access and persistence because it's
       signed, normal-looking software.

    The applocker baseline denied these with "*\<name>.exe" Exe rules. Home has no AppLocker, so
    this module uses the equivalent OS primitive: an Image File Execution Options "Debugger"
    redirect. For each listed filename, launching a process with that image name runs a harmless
    no-op (systray.exe) instead of the tool. Like AppLocker's rule, IFEO matches by the leaf
    filename only, so it catches the tool run portable straight out of Downloads under any path.

    OPT-IN, and read this before enabling: ScreenConnect/Atera/Splashtop are the ACTUAL
    sanctioned remote-management tool for many MSPs and IT departments. Remove the specific
    entry that matches your environment from $script:KnownRemoteAccessTools rather than skipping
    the whole module. IFEO is also bypassable by renaming the executable, and ScreenConnect
    supports per-deployment rebranding, so this catches default filenames, not a determined
    rename - it's a scam/opportunistic-abuse control, not an allowlist.

.NOTES
    Limiting a legitimate support session: prefer Microsoft Quick Assist (Microsoft-signed,
    control actions still pass local UAC - the remote party can't silently take over). If a
    vendor mandates a blocked tool, run that one session under a disposable non-admin account
    (Enable-RemoteAccessToolGuardSupportSession below) so Windows' own permission boundary
    confines it, and roll back this module for the session's duration, then re-apply it and call
    Disable-RemoteAccessToolGuardSupportSession.
#>

$script:IfeoRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
# A harmless, always-present Windows binary to redirect blocked launches to. It opens/exits
# without doing anything, so the tool simply fails to start.
$script:NoOpDebugger = "$env:SystemRoot\System32\systray.exe"

$script:KnownRemoteAccessTools = @(
    # Tech-support-scam pattern - rarely the sanctioned tool for a household/business.
    @{ FileName = 'AnyDesk.exe'; Label = 'AnyDesk' },
    @{ FileName = 'UltraViewer_Desktop.exe'; Label = 'UltraViewer' },
    @{ FileName = 'TeamViewerQS.exe'; Label = 'TeamViewer QuickSupport' },
    @{ FileName = 'TeamViewerQS_x64.exe'; Label = 'TeamViewer QuickSupport (64-bit)' },
    # CISA-documented "legitimate RMM abused for ransomware" pattern - commonly the ACTUAL
    # sanctioned tool for many MSPs. Double-check before enabling.
    @{ FileName = 'ScreenConnect.ClientService.exe'; Label = 'ConnectWise ScreenConnect (client service)' },
    @{ FileName = 'ScreenConnect.WindowsClient.exe'; Label = 'ConnectWise ScreenConnect (on-demand client)' },
    @{ FileName = 'AteraAgent.exe'; Label = 'Atera' },
    @{ FileName = 'SplashtopStreamer.exe'; Label = 'Splashtop' },
    @{ FileName = 'client32.exe'; Label = 'NetSupport Manager (generic filename - higher false-positive risk)' }
)
$script:SupportAccountName = 'RemoteSupport'

function Get-RemoteAccessToolGuardTarget {
    <#
    .SYNOPSIS
        The remote-access tool filenames this module blocks.
    #>
    $script:KnownRemoteAccessTools
}

function Get-RemoteAccessToolGuardStatus {
    $results = @()
    $blocked = @()
    foreach ($tool in $script:KnownRemoteAccessTools) {
        $key = Join-Path $script:IfeoRoot $tool.FileName
        $dbg = (Get-ItemProperty -Path $key -Name 'Debugger' -ErrorAction SilentlyContinue).Debugger
        if ($dbg) { $blocked += $tool.Label }
    }
    $results += "Blocked by IFEO: $(if ($blocked.Count) { $blocked -join ', ' } else { '(none yet - run -Remediate)' })"

    $supportUser = Get-LocalUser -Name $script:SupportAccountName -ErrorAction SilentlyContinue
    if ($supportUser) {
        $results += "Supervised support account '$($script:SupportAccountName)': $(if ($supportUser.Enabled) { "enabled, expires $($supportUser.AccountExpires)" } else { 'disabled' })"
    }
    $results
}

function Invoke-RemoteAccessToolGuardHardening {
    param([switch]$Remediate)
    $out = @()
    foreach ($tool in $script:KnownRemoteAccessTools) {
        $key = Join-Path $script:IfeoRoot $tool.FileName
        if ($Remediate) {
            if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
            Set-ItemProperty -Path $key -Name 'Debugger' -Value $script:NoOpDebugger -Type String
            $out += "Blocked $($tool.Label) by filename ($($tool.FileName)) via IFEO - launching it runs a no-op instead."
        } else {
            $out += "(dry run) Would block $($tool.Label) ($($tool.FileName)) via an IFEO Debugger redirect at $key."
        }
    }
    if ($Remediate) {
        $out += 'For genuine support, use Microsoft Quick Assist (not blocked). To run a mandated tool, roll back this module for the session and confine it with Enable-RemoteAccessToolGuardSupportSession.'
    }
    $out
}

function Enable-RemoteAccessToolGuardSupportSession {
    <#
    .SYNOPSIS
        Creates (or re-enables) a disposable, non-administrator, time-limited local account for
        running a vendor-mandated remote-access tool under a confined identity.
    #>
    param(
        [int]$DurationHours = 4,
        [switch]$Remediate
    )
    if (-not $Remediate) {
        return @("(dry run) Would create/enable a non-admin local account '$($script:SupportAccountName)' expiring in $DurationHours hour(s).")
    }

    $expiry = (Get-Date).AddHours($DurationHours)
    $existing = Get-LocalUser -Name $script:SupportAccountName -ErrorAction SilentlyContinue
    if ($existing) {
        Set-LocalUser -Name $script:SupportAccountName -AccountExpires $expiry
        Enable-LocalUser -Name $script:SupportAccountName
    } else {
        $bytes = New-Object byte[] 18
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        $securePassword = ConvertTo-SecureString -String ([Convert]::ToBase64String($bytes)) -AsPlainText -Force
        New-LocalUser -Name $script:SupportAccountName -Password $securePassword -AccountExpires $expiry `
            -FullName 'Remote Support (temporary)' `
            -Description 'Temporary non-admin remote-support account' | Out-Null
    }
    Remove-LocalGroupMember -Group 'Administrators' -Member $script:SupportAccountName -ErrorAction SilentlyContinue

    @(
        "Created/enabled standard (non-admin) local account '$($script:SupportAccountName)', expires $expiry."
        "Switch to this account (Win+L > Other user) before starting the remote-support session. It cannot reach other users' data or perform admin actions, regardless of the tool's control mode."
        "The IFEO block still applies system-wide. To run a mandated tool during the session, roll back this module (Invoke-RemoteAccessToolGuardRollback -Remediate), then re-apply hardening and run Disable-RemoteAccessToolGuardSupportSession when the session ends."
    )
}

function Disable-RemoteAccessToolGuardSupportSession {
    param([switch]$Remediate)
    if (-not $Remediate) {
        return @("(dry run) Would disable local account '$($script:SupportAccountName)'.")
    }
    if (Get-LocalUser -Name $script:SupportAccountName -ErrorAction SilentlyContinue) {
        Disable-LocalUser -Name $script:SupportAccountName
        @("Disabled local account '$($script:SupportAccountName)'.")
    } else {
        @("No '$($script:SupportAccountName)' account found.")
    }
}

function Invoke-RemoteAccessToolGuardRollback {
    param([switch]$Remediate)
    $out = @()
    foreach ($tool in $script:KnownRemoteAccessTools) {
        $key = Join-Path $script:IfeoRoot $tool.FileName
        if ($Remediate) {
            if (Test-Path $key) {
                Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
                $out += "Unblocked $($tool.Label) (removed IFEO key)."
            }
        } else {
            $out += "(dry run) Would remove the IFEO block for $($tool.Label) at $key."
        }
    }
    # The support account is torn down here too, so a full rollback leaves nothing behind.
    if ($Remediate) {
        if (Get-LocalUser -Name $script:SupportAccountName -ErrorAction SilentlyContinue) {
            try {
                Remove-LocalUser -Name $script:SupportAccountName -ErrorAction Stop
                $out += "Removed local account '$($script:SupportAccountName)'."
            } catch {
                $out += "FAILED removing '$($script:SupportAccountName)': $($_.Exception.Message)"
            }
        }
    }
    if ($out.Count -eq 0) { $out += 'No IFEO blocks present - nothing to undo.' }
    $out
}

Export-ModuleMember -Function Get-RemoteAccessToolGuardStatus, Get-RemoteAccessToolGuardTarget, Invoke-RemoteAccessToolGuardHardening, `
    Enable-RemoteAccessToolGuardSupportSession, Disable-RemoteAccessToolGuardSupportSession, `
    Invoke-RemoteAccessToolGuardRollback
