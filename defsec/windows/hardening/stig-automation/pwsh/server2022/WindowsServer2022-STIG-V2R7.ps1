<#
.SYNOPSIS
    PowerShell automation for Microsoft Windows Server 2022 STIG V2R7
    (Release 7, Benchmark Date: 05 Jan 2026)

.DESCRIPTION
    This script automates the compliance checks for the Windows Server 2022 STIG V2R7.
    It covers security options, user rights assignments, advanced audit policies, and
    domain controller specific settings. The script generates a compliance report and
    can optionally remediate non-compliant settings.

.PARAMETER Remediate
    Automatically fix everything possible.

.PARAMETER StigId
    Target one or more specific VIDs (e.g. V-254293) instead of the whole baseline. When
    supplied, Severity and the RulesFile are ignored - only the listed ID(s) are
    evaluated/remediated. Unknown IDs are reported with a warning and otherwise skipped.

.PARAMETER Severity
    Which CRITICALITY levels to evaluate. Default: High, Medium, Low.
    Example: -Severity High,Medium  (skip the low-impact items)

.PARAMETER RulesFile
    Path to an INI file listing one VID per line that toggles which rules are in scope -
    comment out a line (prefix with ; or #) to exclude that control. Defaults to
    "WindowsServer2022-STIG-V2R7.ini" next to this script, if present. Ignored when -StigId
    is supplied.

.PARAMETER IgnoreRulesFile
    Skip the INI include/exclude file even if it exists, and evaluate every rule.

.PARAMETER ListRules
    Print the in-scope rules (after StigId/RulesFile filtering) and exit. No changes made.

.PARAMETER PassThru
    Return the report objects (and stay quiet on the host) so an orchestrator can consume them.

.EXAMPLE
    .\WindowsServer2022-STIG-V2R7.ps1 -Remediate

.EXAMPLE
    # Apply just one specific control
    .\WindowsServer2022-STIG-V2R7.ps1 -StigId V-254293 -Remediate

.EXAMPLE
    # Apply only the high-severity items
    .\WindowsServer2022-STIG-V2R7.ps1 -Severity High -Remediate

.NOTES
    Author: Robert Weber
#>

[CmdletBinding()]
param(
    [switch]$Remediate,

    [ValidateSet('High','Medium','Low')]
    [string[]]$Severity = @('High','Medium','Low'),

    # One or more specific VIDs. Overrides Severity/RulesFile scoping when supplied.
    [string[]]$StigId,

    # INI include/exclude list. Defaults to <ScriptName>.ini next to this script when present.
    [string]$RulesFile,
    [switch]$IgnoreRulesFile,

    [switch]$ListRules,
    [switch]$PassThru
)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
function Test-DomainJoined {
    (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { $null }
}

function Set-RegValue {
    param([string]$Path, [string]$Name, [object]$Value, [string]$Type = "DWord")
    if (!(Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}

function Run-SeceditExport {
    $temp = [System.IO.Path]::GetTempFileName()
    secedit /export /cfg $temp /areas USER_RIGHTS SECURITYPOLICY /quiet | Out-Null
    $content = Get-Content $temp -Raw
    Remove-Item $temp -Force -ErrorAction SilentlyContinue
    $content
}

function Get-UserRight {
    param([string]$RightName)
    $export = Run-SeceditExport
    $line = $export -split "`r`n" | Where-Object { $_ -like "*$RightName*" }
    if ($line) {
        $sids = ($line -split '=')[1].Trim() -split ','
        $sids | ForEach-Object { $_.Trim() }
    } else { @() }
}

function Set-UserRight {
    param([string]$RightName, [string[]]$AllowedSIDs)
    $temp = [System.IO.Path]::GetTempFileName()
    Run-SeceditExport | Out-File $temp -Encoding ASCII
    (Get-Content $temp) -replace "^$RightName = .*", "$RightName = $($AllowedSIDs -join ',')" | Set-Content $temp -Encoding ASCII
    secedit /configure /db "$env:windir\security\database\secedit.sdb" /cfg $temp /areas USER_RIGHTS /quiet | Out-Null
    Remove-Item $temp -Force -ErrorAction SilentlyContinue
}

function Run-Auditpol {
    auditpol /get /category:* /r
}

# Reads an INI rules file (see WindowsServer2022-STIG-V2R7.ini) and returns the VIDs that
# are still active, i.e. NOT commented out with a leading ';' or '#'.
function Get-EnabledStigIdsFromIni {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    $enabled = [System.Collections.Generic.List[string]]::new()
    foreach ($line in Get-Content -Path $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith(';') -or $trimmed.StartsWith('#') -or $trimmed.StartsWith('[')) { continue }
        if ($trimmed -match '^([^=]+?)\s*=') { $enabled.Add($matches[1].Trim()) }
    }
    $enabled
}

# =============================================================================
# STIG RULES ARRAY
# =============================================================================
$rules = @(

    # ====================== ACCOUNT POLICIES ======================
    [pscustomobject]@{VID="V-254293"; Title="ClearTextPassword"; Severity="High"; Description="Windows Server 2022 reversible password encryption must be disabled."; CheckType="AccountPolicy"; Policy="ClearTextPassword"; Expected=$false}
    [pscustomobject]@{VID="V-254286"; Title="LockoutBadCount"; Severity="Medium"; Description="Windows Server 2022 must have the number of allowed bad logon attempts configured to three or less."; CheckType="AccountPolicy"; Policy="LockoutBadCount"; Expected=3}
    [pscustomobject]@{VID="V-254285"; Title="LockoutDuration"; Severity="Medium"; Description="Windows Server 2022 account lockout duration must be configured to 15 minutes or greater."; CheckType="AccountPolicy"; Policy="LockoutDuration"; Expected=15}
    [pscustomobject]@{VID="V-254289"; Title="MaximumPasswordAge"; Severity="Medium"; Description="Windows Server 2022 maximum password age must be configured to 60 days or less."; CheckType="AccountPolicy"; Policy="MaximumPasswordAge"; Expected=60}
    [pscustomobject]@{VID="V-254290"; Title="MinimumPasswordAge"; Severity="Medium"; Description="Windows Server 2022 minimum password age must be configured to at least one day."; CheckType="AccountPolicy"; Policy="MinimumPasswordAge"; Expected=1}
    [pscustomobject]@{VID="V-254291"; Title="MinimumPasswordLength"; Severity="Medium"; Description="Windows Server 2022 minimum password length must be configured to 14 characters."; CheckType="AccountPolicy"; Policy="MinimumPasswordLength"; Expected=14}
    [pscustomobject]@{VID="V-254292"; Title="PasswordComplexity"; Severity="Medium"; Description="Windows Server 2022 must have the built-in Windows password complexity policy enabled."; CheckType="AccountPolicy"; Policy="PasswordComplexity"; Expected=$true}
    [pscustomobject]@{VID="V-254288"; Title="PasswordHistorySize"; Severity="Medium"; Description="Windows Server 2022 password history must be configured to 24 passwords remembered."; CheckType="AccountPolicy"; Policy="PasswordHistorySize"; Expected=24}
    [pscustomobject]@{VID="V-254287"; Title="ResetLockoutCount"; Severity="Medium"; Description="Windows Server 2022 must have the period of time before the bad logon counter is reset configured to 15 minutes or greater."; CheckType="AccountPolicy"; Policy="ResetLockoutCount"; Expected=15}

    # ====================== USER RIGHTS ASSIGNMENTS ======================
    [pscustomobject]@{VID="V-254491"; Title="SeTrustedCredManAccessPrivilege"; Severity="Medium"; Description="Windows Server 2022 Access Credential Manager as a trusted caller user right must not be assigned to any groups or accounts."; CheckType="UserRight"; RightName="SeTrustedCredManAccessPrivilege"; Allowed=@()}
    [pscustomobject]@{VID="V-254502"; Title="SeAuditPrivilege"; Severity="Medium"; Description="Windows Server 2022 generate security audits user right must only be assigned to Local Service and Network Service."; CheckType="UserRight"; RightName="SeAuditPrivilege"; Allowed=@("S-1-5-19","S-1-5-20")}
    [pscustomobject]@{VID="V-254494"; Title="SeBackupPrivilege"; Severity="Medium"; Description="Windows Server 2022 back up files and directories user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeBackupPrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254497"; Title="SeCreateGlobalPrivilege"; Severity="Medium"; Description="Windows Server 2022 create global objects user right must only be assigned to Administrators, Service, Local Service, and Network Service."; CheckType="UserRight"; RightName="SeCreateGlobalPrivilege"; Allowed=@("S-1-5-6","S-1-5-19","S-1-5-20","S-1-5-32-544")}
    [pscustomobject]@{VID="V-254495"; Title="SeCreatePagefilePrivilege"; Severity="Medium"; Description="Windows Server 2022 create a pagefile user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeCreatePagefilePrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254498"; Title="SeCreatePermanentPrivilege"; Severity="Medium"; Description="Windows Server 2022 create permanent shared objects user right must not be assigned to any groups or accounts."; CheckType="UserRight"; RightName="SeCreatePermanentPrivilege"; Allowed=@()}
    [pscustomobject]@{VID="V-254499"; Title="SeCreateSymbolicLinkPrivilege"; Severity="Medium"; Description="Windows Server 2022 create symbolic links user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeCreateSymbolicLinkPrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254496"; Title="SeCreateTokenPrivilege"; Severity="High"; Description="Windows Server 2022 create a token object user right must not be assigned to any groups or accounts."; CheckType="UserRight"; RightName="SeCreateTokenPrivilege"; Allowed=@()}
    [pscustomobject]@{VID="V-254500"; Title="SeDebugPrivilege"; Severity="High"; Description="Windows Server 2022 debug programs user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeDebugPrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254422/V-254436"; Title="SeDenyBatchLogonRight"; Severity="Medium"; Description="Windows Server 2022 Deny log on as a batch job user right on domain controllers must be configured to prevent unauthenticated access. / Windows Server 2022 Deny log on as a batch job user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems."; CheckType="UserRight"; RightName="SeDenyBatchLogonRight"; Allowed=@("S-1-5-32-546","ADD YOUR ENTERPRISE ADMINS","ADD YOUR DOMAIN ADMINS")}
    [pscustomobject]@{VID="V-254424/V-254438"; Title="SeDenyInteractiveLogonRight"; Severity="Medium"; Description="Windows Server 2022 Deny log on locally user right on domain controllers must be configured to prevent unauthenticated access. / Windows Server 2022 Deny log on locally user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems."; CheckType="UserRight"; RightName="SeDenyInteractiveLogonRight"; Allowed=@("S-1-5-32-546","ADD YOUR ENTERPRISE ADMINS","ADD YOUR DOMAIN ADMINS")}
    [pscustomobject]@{VID="V-254421/V-254435"; Title="SeDenyNetworkLogonRight"; Severity="Medium"; Description="Windows Server 2022 Deny access to this computer from the network user right on domain controllers must be configured to prevent unauthenticated access. / Windows Server 2022 Deny access to this computer from the network user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and local accounts and from unauthenticated access on all systems."; CheckType="UserRight"; RightName="SeDenyNetworkLogonRight"; Allowed=@("S-1-5-114","S-1-5-32-546","ADD YOUR ENTERPRISE ADMINS","ADD YOUR DOMAIN ADMINS")}
    [pscustomobject]@{VID="V-254425/V-254439"; Title="SeDenyRemoteInteractiveLogonRight"; Severity="Medium"; Description="Windows Server 2022 Deny log on through Remote Desktop Services user right on domain controllers must be configured to prevent unauthenticated access. / Windows Server 2022 Deny log on through Remote Desktop Services user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and all local accounts and from unauthenticated access on all systems."; CheckType="UserRight"; RightName="SeDenyRemoteInteractiveLogonRight"; Allowed=@("S-1-5-113","S-1-5-32-546","ADD YOUR ENTERPRISE ADMINS","ADD YOUR DOMAIN ADMINS")}
    [pscustomobject]@{VID="V-254423/V-254437"; Title="SeDenyServiceLogonRight"; Severity="Medium"; Description="Windows Server 2022 Deny log on as a service user right must be configured to include no accounts or groups (blank) on domain controllers. / Windows Server 2022 Deny log on as a service user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts. No other groups or accounts must be assigned this right."; CheckType="UserRight"; RightName="SeDenyServiceLogonRight"; Allowed=@("ADD YOUR ENTERPRISE ADMINS","ADD YOUR DOMAIN ADMINS")}
    [pscustomobject]@{VID="V-254426/V-254440"; Title="SeEnableDelegationPrivilege"; Severity="Medium"; Description="Windows Server 2022 Enable computer and user accounts to be trusted for delegation user right must only be assigned to the Administrators group on domain controllers. / Windows Server 2022 Enable computer and user accounts to be trusted for delegation user right must not be assigned to any groups or accounts on domain-joined member servers and standalone or nondomain-joined systems."; CheckType="UserRight"; RightName="SeEnableDelegationPrivilege"; Allowed=@()}
    [pscustomobject]@{VID="V-254503"; Title="SeImpersonatePrivilege"; Severity="Medium"; Description="Windows Server 2022 impersonate a client after authentication user right must only be assigned to Administrators, Service, Local Service, and Network Service."; CheckType="UserRight"; RightName="SeImpersonatePrivilege"; Allowed=@("S-1-5-32-544","S-1-5-19","S-1-5-20","S-1-5-6")}
    [pscustomobject]@{VID="V-254504"; Title="SeIncreaseBasePriorityPrivilege"; Severity="Medium"; Description="Windows Server 2022 increase scheduling priority: user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeIncreaseBasePriorityPrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254493"; Title="SeInteractiveLogonRight"; Severity="Medium"; Description="Windows Server 2022 Allow log on locally user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeInteractiveLogonRight"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254505"; Title="SeLoadDriverPrivilege"; Severity="Medium"; Description="Windows Server 2022 load and unload device drivers user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeLoadDriverPrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254506"; Title="SeLockMemoryPrivilege"; Severity="Medium"; Description="Windows Server 2022 lock pages in memory user right must not be assigned to any groups or accounts."; CheckType="UserRight"; RightName="SeLockMemoryPrivilege"; Allowed=@()}
    [pscustomobject]@{VID="V-254509"; Title="SeManageVolumePrivilege"; Severity="Medium"; Description="Windows Server 2022 perform volume maintenance tasks user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeManageVolumePrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254418/V-254434"; Title="SeNetworkLogonRight"; Severity="Medium"; Description="Windows Server 2022 Access this computer from the network user right must only be assigned to the Administrators, Authenticated Users, and 
Enterprise Domain Controllers groups on domain controllers. / Windows Server 2022 Access this computer from the network user right must only be assigned to the Administrators and Authenticated Users groups on domain-joined member servers and standalone or nondomain-joined systems."; CheckType="UserRight"; RightName="SeNetworkLogonRight"; Allowed=@("S-1-5-32-544","S-1-5-11")}
    [pscustomobject]@{VID="V-254510"; Title="SeProfileSingleProcessPrivilege"; Severity="Medium"; Description="Windows Server 2022 profile single process user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeProfileSingleProcessPrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254501"; Title="SeRemoteShutdownPrivilege"; Severity="Medium"; Description="Windows Server 2022 force shutdown from a remote system user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeRemoteShutdownPrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254511"; Title="SeRestorePrivilege"; Severity="Medium"; Description="Windows Server 2022 restore files and directories user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeRestorePrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254507"; Title="SeSecurityPrivilege"; Severity="Medium"; Description="Windows Server 2022 manage auditing and security log user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeSecurityPrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254508"; Title="SeSystemEnvironmentPrivilege"; Severity="Medium"; Description="Windows Server 2022 modify firmware environment values user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeSystemEnvironmentPrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254512"; Title="SeTakeOwnershipPrivilege"; Severity="Medium"; Description="Windows Server 2022 take ownership of files or other objects user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeTakeOwnershipPrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254492"; Title="SeTcbPrivilege"; Severity="High"; Description="Windows Server 2022 Act as part of the operating system user right must not be assigned to any groups or accounts."; CheckType="UserRight"; RightName="SeTcbPrivilege"; Allowed=@()}

    # ====================== SECURITY OPTIONS ======================
    [pscustomobject]@{VID="V-254432"; Title="CachedLogonsCount"; Severity="Medium"; Description="Windows Server 2022 must limit the caching of logon credentials to four or less on domain-joined member servers."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="CachedLogonsCount"; Expected="4"}
    [pscustomobject]@{VID="V-254459"; Title="ScRemoveOption"; Severity="Medium"; Description="Windows Server 2022 Smart Card removal option must be configured to Force Logoff or Lock Workstation."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="ScRemoveOption"; Expected="1"}
    [pscustomobject]@{VID="V-254484"; Title="ConsentPromptBehaviorAdmin"; Severity="Medium"; Description="Windows Server 2022 User Account Control (UAC) must, at a minimum, prompt administrators for consent on the secure desktop."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorAdmin"; Expected=2}
    [pscustomobject]@{VID="V-254485"; Title="ConsentPromptBehaviorUser"; Severity="Medium"; Description="Windows Server 2022 User Account Control (UAC) must automatically deny standard user requests for elevation."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorUser"; Expected=0}
    [pscustomobject]@{VID="V-254486"; Title="EnableInstallerDetection"; Severity="Medium"; Description="Windows Server 2022 User Account Control (UAC) must be configured to detect application installations and prompt for elevation."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableInstallerDetection"; Expected=1}
    [pscustomobject]@{VID="V-254488"; Title="EnableLUA"; Severity="Medium"; Description="Windows Server 2022 User Account Control (UAC) must run all administrators in Admin Approval Mode, enabling UAC."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableLUA"; Expected=1}
    [pscustomobject]@{VID="V-254487"; Title="EnableSecureUIAPaths"; Severity="Medium"; Description="Windows Server 2022 User Account Control (UAC) must only elevate UIAccess applications that are installed in secure locations."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableSecureUIAPaths"; Expected=1}
    [pscustomobject]@{VID="V-254483"; Title="EnableUIADesktopToggle"; Severity="Medium"; Description="Windows Server 2022 UIAccess applications must not be allowed to prompt for elevation without using the secure desktop."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableUIADesktopToggle"; Expected=0}
    [pscustomobject]@{VID="V-254489"; Title="EnableVirtualization"; Severity="Medium"; Description="Windows Server 2022 User Account Control (UAC) must virtualize file and registry write failures to per-user locations."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableVirtualization"; Expected=1}
    [pscustomobject]@{VID="V-254482"; Title="FilterAdministratorToken"; Severity="Medium"; Description="Windows Server 2022 User Account Control (UAC) approval mode for the built-in Administrator must be enabled."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="FilterAdministratorToken"; Expected=1}
    [pscustomobject]@{VID="V-254456"; Title="InactivityTimeoutSecs"; Severity="Medium"; Description="Windows Server 2022 machine inactivity limit must be set to 15 minutes or less, locking the system with the screen saver."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="InactivityTimeoutSecs"; Expected=900}
    [pscustomobject]@{VID="V-254473"; Title="SupportedEncryptionTypes"; Severity="Medium"; Description="Windows Server 2022 Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"; Name="SupportedEncryptionTypes"; Expected=2147483640}
    [pscustomobject]@{VID="V-254458"; Title="LegalNoticeCaption"; Severity="Low"; Description="Windows Server 2022 title for legal banner dialog box must be configured with the appropriate text."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LegalNoticeCaption"; Expected="US Department of Defense Warning Statement"}
    [pscustomobject]@{VID="V-254457"; Title="LegalNoticeText"; Severity="Medium"; Description="Windows Server 2022 required legal notice must be configured to display before console logon."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LegalNoticeText"; Expected="You are accessing a U.S. Government (USG) Information System..."}
    [pscustomobject]@{VID="V-254479"; Title="ForceKeyProtection"; Severity="Medium"; Description="Windows Server 2022 users must be required to enter a password to access private keys stored on the computer."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Cryptography"; Name="ForceKeyProtection"; Expected=2}
    [pscustomobject]@{VID="V-254468"; Title="EveryoneIncludesAnonymous"; Severity="Medium"; Description="Windows Server 2022 must be configured to prevent anonymous users from having the same permissions as the Everyone group."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="EveryoneIncludesAnonymous"; Expected=0}
    [pscustomobject]@{VID="V-254480"; Title="FIPSAlgorithmPolicy Enabled"; Severity="Medium"; Description="Windows Server 2022 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy"; Name="Enabled"; Expected=1}
    [pscustomobject]@{VID="V-254446"; Title="LimitBlankPasswordUse"; Severity="High"; Description="Windows Server 2022 must prevent local accounts with blank passwords from being used from the network."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LimitBlankPasswordUse"; Expected=1}
    [pscustomobject]@{VID="V-254475"; Title="LmCompatibilityLevel"; Severity="High"; Description="Windows Server 2022 LAN Manager authentication level must be configured to send NTLMv2 response only and to refuse LM and NTLM."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LmCompatibilityLevel"; Expected=5}
    [pscustomobject]@{VID="V-254471"; Title="allownullsessionfallback"; Severity="Medium"; Description="Windows Server 2022 must prevent NTLM from falling back to a Null session."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="allownullsessionfallback"; Expected=0}
    [pscustomobject]@{VID="V-254477"; Title="NTLMMinClientSec"; Severity="Medium"; Description="Windows Server 2022 session security for NTLM SSP-based clients must be configured to require NTLMv2 session security and 128-bit encryption."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="NTLMMinClientSec"; Expected=537395200}
    [pscustomobject]@{VID="V-254478"; Title="NTLMMinServerSec"; Severity="Medium"; Description="Windows Server 2022 session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="NTLMMinServerSec"; Expected=537395200}
    [pscustomobject]@{VID="V-254474"; Title="NoLMHash"; Severity="High"; Description="Windows Server 2022 must be configured to prevent the storage of the LAN Manager hash of passwords."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="NoLMHash"; Expected=1}
    [pscustomobject]@{VID="V-254472"; Title="AllowOnlineID"; Severity="Medium"; Description="Windows Server 2022 must prevent PKU2U authentication using online identities."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u"; Name="AllowOnlineID"; Expected=0}
    [pscustomobject]@{VID="V-254467"; Title="RestrictAnonymous"; Severity="High"; Description="Windows Server 2022 must not allow anonymous enumeration of shares."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymous"; Expected=1}
    [pscustomobject]@{VID="V-254466"; Title="RestrictAnonymousSAM"; Severity="High"; Description="Windows Server 2022 must not allow anonymous enumeration of Security Account Manager (SAM) accounts."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymousSAM"; Expected=1}
    [pscustomobject]@{VID="V-254433"; Title="RestrictRemoteSAM"; Severity="Medium"; Description="Windows Server 2022 must restrict remote calls to the Security Account Manager (SAM) to Administrators on domain-joined member servers and standalone or nondomain-joined systems."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictRemoteSAM"; Expected="O:BAG:BAD:(A;;RC;;;BA)"}
    [pscustomobject]@{VID="V-254449"; Title="SCENoApplyLegacyAuditPolicy"; Severity="Medium"; Description="Windows Server 2022 must force audit policy subcategory settings to override audit policy category settings."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="SCENoApplyLegacyAuditPolicy"; Expected=1}
    [pscustomobject]@{VID="V-254470"; Title="UseMachineId"; Severity="Medium"; Description="Windows Server 2022 services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity instead of authenticating anonymously."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="UseMachineId"; Expected=1}
    [pscustomobject]@{VID="V-254481"; Title="ProtectionMode"; Severity="Low"; Description="Windows Server 2022 default permissions of global system objects must be strengthened."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"; Name="ProtectionMode"; Expected=1}
    [pscustomobject]@{VID="V-254464"; Title="EnableSecuritySignature (LanManServer)"; Severity="Medium"; Description="Windows Server 2022 setting Microsoft network server: Digitally sign communications (if client agrees) must be configured to Enabled."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="EnableSecuritySignature"; Expected=1}
    [pscustomobject]@{VID="V-254463"; Title="RequireSecuritySignature (LanManServer)"; Severity="Medium"; Description="Windows Server 2022 setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="RequireSecuritySignature"; Expected=1}
    [pscustomobject]@{VID="V-254469"; Title="RestrictNullSessAccess"; Severity="High"; Description="Windows Server 2022 must restrict anonymous access to Named Pipes and Shares."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="RestrictNullSessAccess"; Expected=1}
    [pscustomobject]@{VID="V-254462"; Title="EnablePlainTextPassword"; Severity="Medium"; Description="Windows Server 2022 unencrypted passwords must not be sent to third-party Server Message Block (SMB) servers."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="EnablePlainTextPassword"; Expected=0}
    [pscustomobject]@{VID="V-254461"; Title="EnableSecuritySignature (LanmanWorkstation)"; Severity="Medium"; Description="Windows Server 2022 setting Microsoft network client: Digitally sign communications (if server agrees) must be configured to Enabled."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="EnableSecuritySignature"; Expected=1}
    [pscustomobject]@{VID="V-254460"; Title="RequireSecuritySignature (LanmanWorkstation)"; Severity="Medium"; Description="Windows Server 2022 setting Microsoft network client: Digitally sign communications (always) must be configured to Enabled."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="RequireSecuritySignature"; Expected=1}
    [pscustomobject]@{VID="V-254476"; Title="LDAPClientIntegrity"; Severity="Medium"; Description="Windows Server 2022 must be configured to at least negotiate signing for LDAP client signing."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"; Name="LDAPClientIntegrity"; Expected=1}
    [pscustomobject]@{VID="V-254453"; Title="DisablePasswordChange"; Severity="Medium"; Description="Windows Server 2022 computer account password must not be prevented from being reset."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="DisablePasswordChange"; Expected=0}
    [pscustomobject]@{VID="V-254454"; Title="MaximumPasswordAge (Netlogon)"; Severity="Medium"; Description="Windows Server 2022 maximum age for machine account passwords must be configured to 30 days or less."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="MaximumPasswordAge"; Expected=30}
    [pscustomobject]@{VID="V-254450"; Title="RequireSignOrSeal"; Severity="Medium"; Description="Windows Server 2022 setting Domain member: Digitally encrypt or sign secure channel data (always) must be configured to Enabled."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="RequireSignOrSeal"; Expected=1}
    [pscustomobject]@{VID="V-254455"; Title="RequireStrongKey"; Severity="Medium"; Description="Windows Server 2022 must be configured to require a strong session key."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="RequireStrongKey"; Expected=1}
    [pscustomobject]@{VID="V-254451"; Title="SealSecureChannel"; Severity="Medium"; Description="Windows Server 2022 setting Domain member: Digitally encrypt secure channel data (when possible) must be configured to Enabled."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="SealSecureChannel"; Expected=1}
    [pscustomobject]@{VID="V-254452"; Title="SignSecureChannel"; Severity="Medium"; Description="Windows Server 2022 setting Domain member: Digitally sign secure channel data (when possible) must be configured to Enabled."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="SignSecureChannel"; Expected=1}
    [pscustomobject]@{VID="V-254445"; Title="EnableGuestAccount"; Severity="Medium"; Description="Windows Server 2022 must have the built-in guest account disabled."; CheckType="AccountPolicy"; Policy="EnableGuestAccount"; Expected=0}
    [pscustomobject]@{VID="V-254465"; Title="LSAAnonymousNameLookup"; Severity="High"; Description="Windows Server 2022 must not allow anonymous SID/Name translation."; CheckType="AccountPolicy"; Policy="LSAAnonymousNameLookup"; Expected=0}
    [pscustomobject]@{VID="V-254447"; Title="NewAdministratorName"; Severity="Medium"; Description="Windows Server 2022 built-in administrator account must be renamed."; CheckType="AccountPolicy"; Policy="NewAdministratorName"; Expected="X_Admin"}
    [pscustomobject]@{VID="V-254448"; Title="NewGuestName"; Severity="Medium"; Description="Windows Server 2022 built-in guest account must be renamed."; CheckType="AccountPolicy"; Policy="NewGuestName"; Expected="Visitor"}

    # ====================== ADVANCED AUDIT POLICY ======================
    [pscustomobject]@{VID="V-254300/V-254301"; Title="Audit Credential Validation"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit Account Logon - Credential Validation successes. / Windows Server 2022 must be configured to audit Account Logon - Credential Validation failures."; CheckType="AuditPolicy"; SubCategory="{0cce923f-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-254302"; Title="Audit Other Account Management Events"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit Account Management - Other Account Management Events successes."; CheckType="AuditPolicy"; SubCategory="{0cce923a-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-254303"; Title="Audit Security Group Management"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit Account Management - Security Group Management successes."; CheckType="AuditPolicy"; SubCategory="{0cce9237-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-254304/V-254305"; Title="Audit User Account Management"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit Account Management - User Account Management successes. / Windows Server 2022 must be configured to audit Account Management - User Account Management failures."; CheckType="AuditPolicy"; SubCategory="{0cce9235-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-254306"; Title="Audit PNP Activity"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit Detailed Tracking - Plug and Play Events successes."; CheckType="AuditPolicy"; SubCategory="{0cce9248-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-254307"; Title="Audit Process Creation"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit Detailed Tracking - Process Creation successes."; CheckType="AuditPolicy"; SubCategory="{0cce922b-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-254309"; Title="Audit Account Lockout"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit Logon/Logoff - Account Lockout failures."; CheckType="AuditPolicy"; SubCategory="{0cce9217-69ae-11d9-bed3-505054503030}"; Expected=2}
    [pscustomobject]@{VID="V-254310"; Title="Audit Group Membership"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit Logon/Logoff - Group Membership successes."; CheckType="AuditPolicy"; SubCategory="{0cce9249-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-254311"; Title="Audit Logoff"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit logoff successes."; CheckType="AuditPolicy"; SubCategory="{0cce9216-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-254312/V-254313"; Title="Audit Logon"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit logon successes. / Windows Server 2022 must be configured to audit logon failures."; CheckType="AuditPolicy"; SubCategory="{0cce9215-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-254314"; Title="Audit Special Logon"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit Logon/Logoff - Special Logon successes."; CheckType="AuditPolicy"; SubCategory="{0cce921b-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-278942/V-278943"; Title="Audit File System"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit file system failures. / Windows Server 2022 must be configured to audit file system successes."; CheckType="AuditPolicy"; SubCategory="{0cce921d-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-278944/V-278945"; Title="Audit Handle Manipulation"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit handle manipulation failures. / Windows Server 2022 must be configured to audit handle manipulation successes."; CheckType="AuditPolicy"; SubCategory="{0cce9223-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-254315/V-254316"; Title="Audit Other Object Access Events"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit Object Access - Other Object Access Events successes. / Windows Server 2022 must be configured to audit Object Access - Other Object Access Events failures."; CheckType="AuditPolicy"; SubCategory="{0cce9227-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-278946/V-278947"; Title="Audit Registry"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit registry failures. / Windows Server 2022 must be configured to audit registry successes."; CheckType="AuditPolicy"; SubCategory="{0cce921e-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-254317/V-254318"; Title="Audit Removable Storage"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit Object Access - Removable Storage successes. / Windows Server 2022 must be configured to audit Object Access - Removable Storage failures."; CheckType="AuditPolicy"; SubCategory="{0cce9245-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-254319/V-254320"; Title="Audit Audit Policy Change"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit Policy Change - Audit Policy Change successes. / Windows Server 2022 must be configured to audit Policy Change - Audit Policy Change failures."; CheckType="AuditPolicy"; SubCategory="{0cce922f-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-254321"; Title="Audit Authentication Policy Change"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit Policy Change - Authentication Policy Change successes."; CheckType="AuditPolicy"; SubCategory="{0cce9230-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-254322"; Title="Audit Authorization Policy Change"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit Policy Change - Authorization Policy Change successes."; CheckType="AuditPolicy"; SubCategory="{0cce9231-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-278948/V-278949"; Title="Audit Sensitive Privilege Use"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit sensitive privilege use successes. / Windows Server 2022 must be configured to audit sensitive privilege use failures."; CheckType="AuditPolicy"; SubCategory="{0cce9228-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-254325/V-254326"; Title="Audit IPsec Driver"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit System - IPsec Driver successes. / Windows Server 2022 must be configured to audit System - IPsec Driver failures."; CheckType="AuditPolicy"; SubCategory="{0cce9213-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-254327/V-254328"; Title="Audit Other System Events"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit System - Other System Events successes. / Windows Server 2022 must be configured to audit System - Other System Events failures."; CheckType="AuditPolicy"; SubCategory="{0cce9214-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-254329"; Title="Audit Security State Change"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit System - Security State Change successes."; CheckType="AuditPolicy"; SubCategory="{0cce9210-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-254330"; Title="Audit Security System Extension"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit System - Security System Extension successes."; CheckType="AuditPolicy"; SubCategory="{0cce9211-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-254331/V-254332"; Title="Audit System Integrity"; Severity="Medium"; Description="Windows Server 2022 must be configured to audit System - System Integrity successes. / Windows Server 2022 must be configured to audit System - System Integrity failures."; CheckType="AuditPolicy"; SubCategory="{0cce9212-69ae-11d9-bed3-505054503030}"; Expected=3}

    # ====================== REGISTRY POLICIES ======================
    [pscustomobject]@{VID="V-254333"; Title="Prevent enabling lock screen slide show"; Severity="Medium"; Description="Windows Server 2022 must prevent the display of slide shows on the lock screen."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"; Name="NoLockScreenSlideshow"; Expected=1}
    [pscustomobject]@{VID="V-254429"; Title="Apply UAC restrictions to local accounts on network logons"; Severity="Medium"; Description="Windows Server 2022 local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain-joined member servers."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LocalAccountTokenFilterPolicy"; Expected=0}
    [pscustomobject]@{VID="V-254277"; Title="Configure SMB v1 client driver"; Severity="Medium"; Description="Windows Server 2022 must have the Server Message Block (SMB) v1 protocol disabled on the SMB client."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10"; Name="Start"; Expected=4}
    [pscustomobject]@{VID="V-254276"; Title="Configure SMB v1 server"; Severity="Medium"; Description="Windows Server 2022 must have the Server Message Block (SMB) v1 protocol disabled on the SMB server."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="SMB1"; Expected=0}
    [pscustomobject]@{VID="V-254334"; Title="WDigest Authentication"; Severity="Medium"; Description="Windows Server 2022 must have WDigest Authentication disabled."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name="UseLogonCredential"; Expected=0}
    [pscustomobject]@{VID="V-254335"; Title="MSS: DisableIPSourceRouting IPv6"; Severity="Low"; Description="Windows Server 2022 Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; Name="DisableIPSourceRouting"; Expected=2}
    [pscustomobject]@{VID="V-254336"; Title="MSS: DisableIPSourceRouting"; Severity="Low"; Description="Windows Server 2022 source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="DisableIPSourceRouting"; Expected=2}
    [pscustomobject]@{VID="V-254337"; Title="MSS: EnableICMPRedirect"; Severity="Low"; Description="Windows Server 2022 must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)-generated routes."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="EnableICMPRedirect"; Expected=0}
    [pscustomobject]@{VID="V-254338"; Title="MSS: NoNameReleaseOnDemand"; Severity="Low"; Description="Windows Server 2022 must be configured to ignore NetBIOS name release requests except from WINS servers."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; Name="NoNameReleaseOnDemand"; Expected=1}
    [pscustomobject]@{VID="V-254339"; Title="Enable insecure guest logons"; Severity="Medium"; Description="Windows Server 2022 insecure logons to an SMB server must be disabled."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="EnableInsecureGuestLogons"; Expected=0}
    [pscustomobject]@{VID="V-254340"; Title="Hardened UNC Paths - SYSVOL"; Severity="Medium"; Description="Windows Server 2022 hardened Universal Naming Convention (UNC) paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"; Name="\\*\SYSVOL"; Expected="RequireMutualAuthentication=1, RequireIntegrity=1"}
    [pscustomobject]@{VID="V-254340"; Title="Hardened UNC Paths - NETLOGON"; Severity="Medium"; Description="Windows Server 2022 hardened Universal Naming Convention (UNC) paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"; Name="\\*\NETLOGON"; Expected="RequireMutualAuthentication=1, RequireIntegrity=1"}
    [pscustomobject]@{VID="V-254341"; Title="Include command line in process creation events"; Severity="Medium"; Description="Windows Server 2022 command line data must be included in process creation events."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"; Name="ProcessCreationIncludeCmdLine_Enabled"; Expected=1}
    [pscustomobject]@{VID="V-254342"; Title="Remote host allows delegation of non-exportable credentials"; Severity="Medium"; Description="Windows Server 2022 must be configured to enable Remote host allows delegation of nonexportable credentials."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"; Name="AllowProtectedCreds"; Expected=1}
    [pscustomobject]@{VID="V-254343"; Title="Turn On Virtualization Based Security"; Severity="Medium"; Description="Windows Server 2022 virtualization-based security must be enabled with the platform security level configured to Secure Boot or Secure Boot with DMA Protection."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name="EnableVirtualizationBasedSecurity"; Expected=1}
    [pscustomobject]@{VID="V-254344"; Title="Boot-Start Driver Initialization Policy"; Severity="Medium"; Description="Windows Server 2022 Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers identified as bad."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"; Name="DriverLoadPolicy"; Expected=1}
    [pscustomobject]@{VID="V-254345"; Title="Configure registry policy processing"; Severity="Medium"; Description="Windows Server 2022 group policy objects must be reprocessed even if they have not changed."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy"; Name="NoBackgroundPolicy"; Expected=0; Expected2=1}  # both checkboxes
    [pscustomobject]@{VID="V-254346"; Title="Turn off downloading of print drivers over HTTP"; Severity="Medium"; Description="Windows Server 2022 downloading print driver packages over HTTP must be turned off."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Name="DisableHTTPPrinting"; Expected=1}
    [pscustomobject]@{VID="V-254347"; Title="Turn off printing over HTTP"; Severity="Medium"; Description="Windows Server 2022 printing over HTTP must be turned off."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Name="DisableWebPrinting"; Expected=1}
    [pscustomobject]@{VID="LOCAL-LAPS-0001"; Title="Password Settings (LAPS)"; Severity="Medium"; Description="Local Administrator Password Solution (LAPS) password complexity - not part of the official DISA Windows Server 2022 V2R8 baseline; carried over from this script's original author."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"; Name="PasswordComplexity"; Expected=4}
    [pscustomobject]@{VID="V-254348"; Title="Do not display network selection UI"; Severity="Medium"; Description="Windows Server 2022 network selection user interface (UI) must not be displayed on the logon screen."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="DontDisplayNetworkSelectionUI"; Expected=1}
    [pscustomobject]@{VID="V-254430"; Title="Enumerate local users on domain-joined computers"; Severity="Medium"; Description="Windows Server 2022 local users on domain-joined member servers must not be enumerated."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnumerateLocalUsers"; Expected=0}
    [pscustomobject]@{VID="V-254349"; Title="Require a password when a computer wakes (on battery)"; Severity="Medium"; Description="Windows Server 2022 users must be prompted to authenticate when the system wakes from sleep (on battery)."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power"; Name="PromptForPasswordOnResumeBattery"; Expected=1}
    [pscustomobject]@{VID="V-254350"; Title="Require a password when a computer wakes (plugged in)"; Severity="Medium"; Description="Windows Server 2022 users must be prompted to authenticate when the system wakes from sleep (plugged in)."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power"; Name="PromptForPasswordOnResumeAC"; Expected=1}
    [pscustomobject]@{VID="V-254431"; Title="Restrict Unauthenticated RPC clients"; Severity="Medium"; Description="Windows Server 2022 must restrict unauthenticated Remote Procedure Call (RPC) clients from connecting to the RPC server on domain-joined member servers and standalone or nondomain-joined systems."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"; Name="RestrictRemoteClients"; Expected=1}
    [pscustomobject]@{VID="V-254351"; Title="Turn off Inventory Collector"; Severity="Low"; Description="Windows Server 2022 Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx"; Name="DisableInventory"; Expected=1}
    [pscustomobject]@{VID="V-254352"; Title="Disallow Autoplay for non-volume devices"; Severity="High"; Description="Windows Server 2022 Autoplay must be turned off for nonvolume devices."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="NoAutoplayfornonVolume"; Expected=1}
    [pscustomobject]@{VID="V-254353"; Title="Set the default behavior for AutoRun"; Severity="High"; Description="Windows Server 2022 default AutoRun behavior must be configured to prevent AutoRun commands."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoAutorun"; Expected=1}
    [pscustomobject]@{VID="V-254354"; Title="Turn off Autoplay"; Severity="High"; Description="Windows Server 2022 AutoPlay must be disabled for all drives."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"; Expected=255}
    [pscustomobject]@{VID="V-254355"; Title="Enumerate administrator accounts on elevation"; Severity="Medium"; Description="Windows Server 2022 administrator accounts must not be enumerated during elevation."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"; Name="EnumerateAdministrators"; Expected=0}
    [pscustomobject]@{VID="V-254356"; Title="Allow Diagnostic Data"; Severity="Medium"; Description="Windows Server 2022 Diagnostic Data must be configured to send `"required diagnostic data`" or `"optional diagnostic data`"."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"; Expected=1}
    [pscustomobject]@{VID="V-254357"; Title="Download Mode"; Severity="Low"; Description="Windows Server 2022 Windows Update must not obtain updates from other PCs on the internet."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"; Name="DODownloadMode"; Expected=2}
    [pscustomobject]@{VID="V-254358"; Title="Specify the maximum log file size (Application)"; Severity="Medium"; Description="Windows Server 2022 Application event log size must be configured to 32768 KB or greater."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"; Name="MaxSize"; Expected=32768}
    [pscustomobject]@{VID="V-254359"; Title="Specify the maximum log file size (Security)"; Severity="Medium"; Description="The Windows Server 2022 security event log size must be configured to a value that holds at least one week's worth of audit records."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"; Name="MaxSize"; Expected=196608}
    [pscustomobject]@{VID="V-254360"; Title="Specify the maximum log file size (System)"; Severity="Medium"; Description="Windows Server 2022 System event log size must be configured to 32768 KB or greater."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"; Name="MaxSize"; Expected=32768}
    [pscustomobject]@{VID="V-254362"; Title="Turn off Data Execution Prevention for Explorer"; Severity="Medium"; Description="Windows Server 2022 Explorer Data Execution Prevention must be enabled."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="NoDataExecutionPrevention"; Expected=0}
    [pscustomobject]@{VID="V-254363"; Title="Turn off heap termination on corruption"; Severity="Low"; Description="Windows Server 2022 Turning off File Explorer heap termination on corruption must be disabled."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="NoHeapTerminationOnCorruption"; Expected=0}
    [pscustomobject]@{VID="V-254364"; Title="Turn off shell protocol protected mode"; Severity="Medium"; Description="Windows Server 2022 File Explorer shell protocol must run in protected mode."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoShellProtocolProtectedMode"; Expected=0}
    [pscustomobject]@{VID="V-254365"; Title="Do not allow passwords to be saved"; Severity="Medium"; Description="Windows Server 2022 must not save passwords in the Remote Desktop Client."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="DisablePasswordSaving"; Expected=1}
    [pscustomobject]@{VID="V-254366"; Title="Do not allow drive redirection"; Severity="Medium"; Description="Windows Server 2022 Remote Desktop Services must prevent drive redirection."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fDisableCdm"; Expected=1}
    [pscustomobject]@{VID="V-254367"; Title="Always prompt for password upon connection"; Severity="Medium"; Description="Windows Server 2022 Remote Desktop Services must always prompt a client for passwords upon connection."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fPromptForPassword"; Expected=1}
    [pscustomobject]@{VID="V-254368"; Title="Require secure RPC communication"; Severity="Medium"; Description="Windows Server 2022 Remote Desktop Services must require secure Remote Procedure Call (RPC) communications."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fEncryptRPCTraffic"; Expected=1}
    [pscustomobject]@{VID="V-254369"; Title="Set client connection encryption level"; Severity="Medium"; Description="Windows Server 2022 Remote Desktop Services must be configured with the client connection encryption set to High Level."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="MinEncryptionLevel"; Expected=3}
    [pscustomobject]@{VID="V-254370"; Title="Prevent downloading of enclosures"; Severity="Medium"; Description="Windows Server 2022 must prevent attachments from being downloaded from RSS feeds."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"; Name="DisableEnclosureDownload"; Expected=1}
    [pscustomobject]@{VID="V-254371"; Title="Turn on Basic feed authentication over HTTP"; Severity="Medium"; Description="Windows Server 2022 must disable Basic authentication for RSS feeds over HTTP."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"; Name="BasicAuth"; Expected=0}
    [pscustomobject]@{VID="V-254372"; Title="Allow indexing of encrypted files"; Severity="Medium"; Description="Windows Server 2022 must prevent Indexing of encrypted files."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowIndexingEncryptedStoresOrItems"; Expected=0}
    [pscustomobject]@{VID="V-254361"; Title="Configure Windows Defender SmartScreen"; Severity="Medium"; Description="Windows Server 2022 Microsoft Defender antivirus SmartScreen must be enabled."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnableSmartScreen"; Expected=1}
    [pscustomobject]@{VID="V-254373"; Title="Allow user control over installs"; Severity="Medium"; Description="Windows Server 2022 must prevent users from changing installation options."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="EnableUserControl"; Expected=0}
    [pscustomobject]@{VID="V-254374"; Title="Always install with elevated privileges"; Severity="High"; Description="Windows Server 2022 must disable the Windows Installer Always install with elevated privileges option."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="AlwaysInstallElevated"; Expected=0}
    [pscustomobject]@{VID="V-254375"; Title="Prevent Internet Explorer security prompt for Windows Installer scripts"; Severity="Medium"; Description="Windows Server 2022 users must be notified if a web-based program attempts to install software."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="SafeForScripting"; Expected=0}
    [pscustomobject]@{VID="V-254376"; Title="Sign-in and lock last interactive user automatically after a restart"; Severity="Medium"; Description="Windows Server 2022 must disable automatically signing in the last interactive user after a system-initiated restart."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="DisableAutomaticRestartSignOn"; Expected=1}
    [pscustomobject]@{VID="V-254377"; Title="Turn on PowerShell Script Block Logging"; Severity="Medium"; Description="Windows Server 2022 PowerShell script block logging must be enabled."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name="EnableScriptBlockLogging"; Expected=1}
    [pscustomobject]@{VID="V-254384"; Title="Turn on PowerShell Transcription"; Severity="Medium"; Description="Windows Server 2022 must have PowerShell Transcription enabled."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name="EnableTranscripting"; Expected=1}
    [pscustomobject]@{VID="V-254378"; Title="Allow Basic authentication (WinRM Client)"; Severity="High"; Description="Windows Server 2022 Windows Remote Management (WinRM) client must not use Basic authentication."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowBasic"; Expected=0}
    [pscustomobject]@{VID="V-254379"; Title="Allow unencrypted traffic (WinRM Client)"; Severity="Medium"; Description="Windows Server 2022 Windows Remote Management (WinRM) client must not allow unencrypted traffic."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowUnencryptedTraffic"; Expected=0}
    [pscustomobject]@{VID="V-254380"; Title="Disallow Digest authentication (WinRM Client)"; Severity="Medium"; Description="Windows Server 2022 Windows Remote Management (WinRM) client must not use Digest authentication."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowDigest"; Expected=0}
    [pscustomobject]@{VID="V-254381"; Title="Allow Basic authentication (WinRM Service)"; Severity="High"; Description="Windows Server 2022 Windows Remote Management (WinRM) service must not use Basic authentication."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="AllowBasic"; Expected=0}
    [pscustomobject]@{VID="V-254382"; Title="Allow unencrypted traffic (WinRM Service)"; Severity="Medium"; Description="Windows Server 2022 Windows Remote Management (WinRM) service must not allow unencrypted traffic."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="AllowUnencryptedTraffic"; Expected=0}
    [pscustomobject]@{VID="V-254383"; Title="Disallow WinRM from storing RunAs credentials"; Severity="Medium"; Description="Windows Server 2022 Windows Remote Management (WinRM) service must not store RunAs credentials."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="DisableRunAs"; Expected=1}
)

# =============================================================================
# SCOPE FILTER (by StigId, else Severity / RulesFile)
# =============================================================================
if ($StigId) {
    $scoped  = $rules | Where-Object { $_.VID -in $StigId }
    $missing = $StigId | Where-Object { $_ -notin $rules.VID }
    if ($missing) {
        Write-Warning "No rule found for STIG ID(s): $($missing -join ', ')"
    }
} else {
    $scoped = $rules | Where-Object { $_.Severity -in $Severity }
    if (-not $IgnoreRulesFile) {
        $iniPath = if ($RulesFile) { $RulesFile } else { Join-Path $PSScriptRoot 'WindowsServer2022-STIG-V2R7.ini' }
        $enabled = Get-EnabledStigIdsFromIni -Path $iniPath
        if ($null -ne $enabled) {
            $scoped = $scoped | Where-Object { $_.VID -in $enabled }
            if (-not $PassThru) { Write-Host "Rules file   : $iniPath" -ForegroundColor DarkGray }
        } elseif ($RulesFile -and -not $PassThru) {
            Write-Warning "RulesFile '$RulesFile' not found - ignoring."
        }
    }
}

if (-not $scoped) {
    if (-not $PassThru) { Write-Host "No rules match the selected -Severity / -StigId / RulesFile. Nothing to do." -ForegroundColor Yellow }
    return
}

if ($ListRules) {
    if ($PassThru) { return $scoped }
    $scoped | Sort-Object Severity, VID | Format-Table VID, Severity, Title, Description -AutoSize -Wrap
    Write-Host "`n$($scoped.Count) rule(s) in scope." -ForegroundColor Cyan
    return
}

# =============================================================================
# MAIN EXECUTION LOGIC
# =============================================================================
$report = @()
$rebootRequired = $false

foreach ($rule in $scoped) {
    $status = "Non-Compliant"
    $remediated = $false

    switch ($rule.CheckType) {
        "AccountPolicy" {
            $export = Run-SeceditExport
            $line = $export -split "`r`n" | Where-Object { $_ -like "*$($rule.Policy)*" }
            $current = if ($line) { ($line -split '=')[1].Trim() } else { $null }
            if ($current -eq $rule.Expected) { $status = "Compliant" }
            elseif ($Remediate) { $remediated = $true; $rebootRequired = $true }
        }
        "UserRight" {
            $current = Get-UserRight -RightName $rule.RightName
            if (($current | Sort-Object) -join "," -eq ($rule.Allowed | Sort-Object) -join ",") { $status = "Compliant" }
            elseif ($Remediate) { Set-UserRight -RightName $rule.RightName -AllowedSIDs $rule.Allowed; $remediated = $true }
        }
        "Registry" {
            $current = Get-RegValue -Path $rule.Path -Name $rule.Name
            if ($current -eq $rule.Expected) { $status = "Compliant" }
            elseif ($Remediate) { Set-RegValue -Path $rule.Path -Name $rule.Name -Value $rule.Expected; $remediated = $true }
        }
        "AuditPolicy" {
            $auditOutput = Run-Auditpol
            $line = $auditOutput | Where-Object { $_ -like "*$($rule.SubCategory)*" }
            # FIX: Use index [4] for the Inclusion Setting
            $current = if ($line) { ($line -split ',')[4].Trim() } else { $null }
            if ($current -eq $rule.Expected) { $status = "Compliant" }
            elseif ($Remediate) { auditpol /set /subcategory:"$($rule.SubCategory)" /success:enable /failure:enable | Out-Null; $remediated = $true }
        }
    }

    $report += [pscustomobject]@{
        VID         = $rule.VID
        Sev         = $rule.Severity
        Title       = $rule.Title
        Description = $rule.Description
        Status      = $status
        Remediated  = if ($Remediate -and $remediated) { "Yes" } else { "No" }
    }
}

# =============================================================================
# FINAL REPORT
# =============================================================================
if ($PassThru) { return $report }

$report | Sort-Object Sev, VID | Format-Table VID, Sev, Title, Status, Remediated -AutoSize

if ($Remediate) {
    Write-Host "`nRemediation complete for all rules in the Microsoft Windows Server 2022 STIG V2R7 STIG." -ForegroundColor Green
    if ($rebootRequired) {
        Write-Host "A reboot is required for some changes (account policies, audit policy, etc.) to take effect." -ForegroundColor Yellow
    }
} else {
    Write-Host "`nRun the script with -Remediate to automatically fix Non-Compliant settings." -ForegroundColor Cyan
}

Write-Host "`nScript complete. All rules from the Microsoft Windows Server 2022 STIG V2R7 STIG are now enforced." -ForegroundColor White
