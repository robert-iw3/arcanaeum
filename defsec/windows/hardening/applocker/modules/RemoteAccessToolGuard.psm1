<#
.SYNOPSIS
    Opt-in AppLocker baseline module: denies remote-access/RMM tools commonly abused either in
    consumer tech-support scams or as a "living off the land" initial-access/persistence tool in
    ransomware intrusions, and provides a confined-account fallback for genuine support sessions.

.DESCRIPTION
    Two distinct but related abuse patterns land on the same list here:

    1. Tech-support scams disproportionately target older and non-technical users: a fake warning
       or a cold call talks the victim into downloading a portable remote-access tool so the
       scammer can "fix" the PC (and actually drain a bank account, install malware, or hold files
       for ransom). AnyDesk, UltraViewer, and TeamViewer QuickSupport are the tools most cited in
       this specific scam pattern.
    2. CISA/NSA/MS-ISAC have separately documented legitimate RMM software (ScreenConnect, Atera,
       Splashtop, NetSupport Manager, among others) being abused by ransomware actors as an
       initial-access or persistence tool precisely because it's signed, "normal" software that
       blends in - the same property that makes it hard to stop with allowlisting alone, since
       "is this session legitimate" isn't something AppLocker can judge.

    Matched by filename anywhere on disk (a leading wildcard path, e.g. "*\AnyDesk.exe") rather
    than by install location, since these are commonly run portable straight out of Downloads
    with no installation step, or get installed to non-standard paths.

    Opt-in, not in the orchestrator's default module set, and the warning matters more here than
    for the other modules in this folder: several of these (ScreenConnect, Atera, Splashtop in
    particular) are the actual sanctioned remote-management platform for a great many MSPs and IT
    departments. Confirm what your organization actually uses before enabling this, and remove any
    entry that matches it from $script:KnownRemoteAccessTools rather than disabling the whole
    module if only one tool is the conflict.

    Filename matching is also inherently weaker for ScreenConnect specifically - it supports
    rebranding/renaming the installed client per deployment, so this only catches the default,
    unbranded filenames.

.NOTES
    On "view only" / limiting what a legitimate support session can do:

    AppLocker only gates whether a binary is allowed to launch - it has no concept of letting a
    process run with a restricted capability set (no "allow it to view the screen but not control
    the system"). That distinction, when it exists at all, is a feature of the remote-access
    application itself, not something the OS or AppLocker can impose on an already-running,
    already-permitted process.

    For genuine, honest tech support, two real (OS-enforced) options exist, in preference order:

    1. Use Microsoft Quick Assist instead of a third-party tool. It's signed by Microsoft and
       already covered by the base policy's Windows-folder allow rule, so it needs no exception
       here. It natively enforces almost exactly the model being asked for: the helper can view
       the screen, but any actual control action still goes through Windows' normal UAC consent
       prompts on the local machine - the remote party cannot silently take over or escalate.

    2. If a vendor mandates one of the tools this module denies, don't carve out a permanent
       AppLocker exception for it (Deny always wins over Allow for the same rule collection in
       AppLocker, so a coexisting "allow for this one account" rule wouldn't override the deny
       anyway). Instead, run that one session under a disposable, non-administrator local account
       (see Enable-RemoteAccessToolGuardSupportSession below) and temporarily redeploy the
       baseline without this module for the session's duration. Windows' own account/permission
       boundary then limits what the remote operator can reach - no other user's files, no admin
       actions, no system-wide changes - regardless of whether the tool's own UI says "full
       control" or "view only". Restore the module immediately after the session ends.
#>

$script:KnownRemoteAccessTools = @(
    # Tech-support-scam pattern - rarely the sanctioned tool for a business.
    @{ FileName = 'AnyDesk.exe'; Label = 'AnyDesk' },
    @{ FileName = 'UltraViewer_Desktop.exe'; Label = 'UltraViewer' },
    @{ FileName = 'TeamViewerQS.exe'; Label = 'TeamViewer QuickSupport' },
    @{ FileName = 'TeamViewerQS_x64.exe'; Label = 'TeamViewer QuickSupport (64-bit)' },
    # CISA-documented "legitimate RMM abused for ransomware initial access/persistence" pattern -
    # commonly the ACTUAL sanctioned tool for many MSPs. Double-check before enabling.
    @{ FileName = 'ScreenConnect.ClientService.exe'; Label = 'ConnectWise ScreenConnect (client service)' },
    @{ FileName = 'ScreenConnect.WindowsClient.exe'; Label = 'ConnectWise ScreenConnect (on-demand client)' },
    @{ FileName = 'AteraAgent.exe'; Label = 'Atera' },
    @{ FileName = 'SplashtopStreamer.exe'; Label = 'Splashtop' },
    @{ FileName = 'client32.exe'; Label = 'NetSupport Manager (generic filename - higher false-positive risk)' }
)
$script:SupportAccountName = 'RemoteSupport'

function Get-RemoteAccessToolGuardStatus {
    $results = @()
    try {
        $exeCollection = @((Get-AppLockerPolicy -Local).RuleCollections | Where-Object { $_.RuleCollectionType -eq 'Exe' })
        $denyNames = @($exeCollection | Where-Object { $_.Action -eq 'Deny' } | Select-Object -ExpandProperty Name)
        $covered = $script:KnownRemoteAccessTools | Where-Object {
            $label = $_.Label
            $denyNames | Where-Object { $_ -match [regex]::Escape($label) }
        }
        $results += "Denied: $(if ($covered) { ($covered | ForEach-Object { $_.Label }) -join ', ' } else { '(none yet - run -Remediate)' })"
    } catch {
        $results += "AppLocker Exe rule collection not readable yet."
    }
    $supportUser = Get-LocalUser -Name $script:SupportAccountName -ErrorAction SilentlyContinue
    if ($supportUser) {
        $results += "Supervised support account '$($script:SupportAccountName)': $(if ($supportUser.Enabled) { "enabled, expires $($supportUser.AccountExpires)" } else { 'disabled' })"
    }
    $results
}

function Get-RemoteAccessToolGuardPolicyFragment {
    foreach ($tool in $script:KnownRemoteAccessTools) {
        $id = [guid]::NewGuid().ToString()
        $name = "Deny $($tool.Label) (tech-support scam remote-access tool)"
        [PSCustomObject]@{
            CollectionType = 'Exe'
            Name           = $name
            Xml            = @"
<FilePathRule Id="$id" Name="$name" Description="Blocks $($tool.Label) anywhere on disk. Commonly abused in tech-support scams that talk a victim into installing a remote-access tool. For genuine support needs, prefer Microsoft Quick Assist, or see Enable-RemoteAccessToolGuardSupportSession in modules/RemoteAccessToolGuard.psm1 for a confined-account fallback." UserOrGroupSid="S-1-1-0" Action="Deny">
    <Conditions>
        <FilePathCondition Path="*\$($tool.FileName)" />
    </Conditions>
</FilePathRule>
"@
        }
    }
}

function Enable-RemoteAccessToolGuardSupportSession {
    <#
    .SYNOPSIS
        Creates (or re-enables) a disposable, non-administrator local account scoped to a single
        time-limited window, for running a vendor-mandated remote-access tool under a confined
        identity instead of the regular (possibly privileged) user account.

    .DESCRIPTION
        This does NOT punch an AppLocker exception for the denied tools - Deny always wins over
        Allow in AppLocker, so no per-account carve-out is possible here. Temporarily redeploy the
        baseline with this module excluded (-Modules without RemoteAccessToolGuard) for the
        session, have the support session run under this account, then re-deploy with the module
        included again and call Disable-RemoteAccessToolGuardSupportSession.
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
        "Switch to this account (Win+L > Other user) before starting the remote-support session. It cannot reach other users' data or perform admin actions, regardless of the tool's own control mode."
        "AppLocker still denies the curated tool list system-wide. To actually run one during the session, temporarily redeploy this baseline with -Modules excluding RemoteAccessToolGuard, then re-include it and run Disable-RemoteAccessToolGuardSupportSession when the session ends."
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
    if ($Remediate) {
        if (Get-LocalUser -Name $script:SupportAccountName -ErrorAction SilentlyContinue) {
            try {
                Remove-LocalUser -Name $script:SupportAccountName -ErrorAction Stop
                @("Removed local account '$($script:SupportAccountName)'.")
            } catch {
                Write-Warning "Failed to remove local account '$($script:SupportAccountName)': $($_.Exception.Message). Requires an elevated session."
                @("FAILED: $($_.Exception.Message)")
            }
        } else {
            @("No '$($script:SupportAccountName)' account found.")
        }
    } else {
        @("(dry run) Would remove local account '$($script:SupportAccountName)' if it exists.")
    }
}

Export-ModuleMember -Function Get-RemoteAccessToolGuardStatus, Get-RemoteAccessToolGuardPolicyFragment, `
    Enable-RemoteAccessToolGuardSupportSession, Disable-RemoteAccessToolGuardSupportSession, `
    Invoke-RemoteAccessToolGuardRollback
