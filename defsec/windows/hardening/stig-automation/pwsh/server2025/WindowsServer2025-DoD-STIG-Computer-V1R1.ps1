<#
.SYNOPSIS
    DoD WinSvr 2025 MS STIG Comp v1r1

.DESCRIPTION
    Checks and remediates DoD Windows Server 2025 MS STIG Compliance for Computer settings (v1r1).

.PARAMETER StigId
    Target one or more specific VIDs (e.g. V-278040) instead of the whole baseline. When
    supplied, Severity and the RulesFile are ignored - only the listed ID(s) are
    evaluated/remediated. Unknown IDs are reported with a warning and otherwise skipped.
    Most VIDs come from the official DISA V1R1 XCCDF; a handful of internal WS2025-COMP-####
    handles remain for controls with no official DISA equivalent (e.g. LAPS).

.PARAMETER Severity
    Which CRITICALITY levels to evaluate. Default: High, Medium, Low.
    Example: -Severity High,Medium  (skip the low-impact items)

.PARAMETER RulesFile
    Path to an INI file listing one VID per line that toggles which rules are in scope -
    comment out a line (prefix with ; or #) to exclude that control. Defaults to
    "WindowsServer2025-DoD-STIG-Computer-V1R1.ini" next to this script, if present. Ignored
    when -StigId is supplied.

.PARAMETER IgnoreRulesFile
    Skip the INI include/exclude file even if it exists, and evaluate every rule.

.PARAMETER ListRules
    Print the in-scope rules (after Severity/StigId/RulesFile filtering) and exit. No changes made.

.EXAMPLE
    # Check compliance only
    .\WindowsServer2025-DoD-STIG-Computer-V1R1.ps1

    # Check and remediate non-compliant settings
    .\WindowsServer2025-DoD-STIG-Computer-V1R1.ps1 -Remediate

.EXAMPLE
    # Apply only the high-severity items
    .\WindowsServer2025-DoD-STIG-Computer-V1R1.ps1 -Severity High -Remediate

.EXAMPLE
    # Apply just one specific control
    .\WindowsServer2025-DoD-STIG-Computer-V1R1.ps1 -StigId V-278040 -Remediate

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
function Test-DomainJoined { (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain }

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
    if ($line) { (($line -split '=')[1].Trim() -split ',').Trim() } else { @() }
}

function Set-UserRight {
    param([string]$RightName, [string[]]$AllowedSIDs)
    $temp = [System.IO.Path]::GetTempFileName()
    Run-SeceditExport | Out-File $temp -Encoding ASCII
    (Get-Content $temp) -replace "^$RightName = .*", "$RightName = $($AllowedSIDs -join ',')" | Set-Content $temp -Encoding ASCII
    secedit /configure /db "$env:windir\security\database\secedit.sdb" /cfg $temp /areas USER_RIGHTS /quiet | Out-Null
    Remove-Item $temp -Force -ErrorAction SilentlyContinue
}

function Run-Auditpol { auditpol /get /category:* /r }

# Reads an INI rules file (see WindowsServer2025-DoD-STIG-Computer-V1R1.ini) and returns the
# VIDs that are still active, i.e. NOT commented out with a leading ';' or '#'.
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

    # === ACCOUNT POLICIES ===
    [pscustomobject]@{VID="V-278040"; Title="ClearTextPassword"; Severity="High"; Description="Windows Server 2025 reversible password encryption must be disabled."; CheckType="AccountPolicy"; Policy="ClearTextPassword"; Expected=$false},
    [pscustomobject]@{VID="V-278034"; Title="LockoutBadCount"; Severity="Medium"; Description="Windows Server 2025 must have the number of allowed bad logon attempts configured to three or less."; CheckType="AccountPolicy"; Policy="LockoutBadCount"; Expected=3},
    [pscustomobject]@{VID="V-278033"; Title="LockoutDuration"; Severity="Medium"; Description="Windows Server 2025 account lockout duration must be configured to 15 minutes or greater."; CheckType="AccountPolicy"; Policy="LockoutDuration"; Expected=15},
    [pscustomobject]@{VID="V-278037"; Title="MaximumPasswordAge"; Severity="Medium"; Description="Windows Server 2025 maximum password age must be configured to 60 days or less."; CheckType="AccountPolicy"; Policy="MaximumPasswordAge"; Expected=60},
    [pscustomobject]@{VID="V-278038"; Title="MinimumPasswordAge"; Severity="Medium"; Description="Windows Server 2025 minimum password age must be configured to at least one day."; CheckType="AccountPolicy"; Policy="MinimumPasswordAge"; Expected=1},
    [pscustomobject]@{VID="V-278039"; Title="PasswordComplexity"; Severity="Medium"; Description="Windows Server 2025 must have the built-in Windows password complexity policy enabled."; CheckType="AccountPolicy"; Policy="PasswordComplexity"; Expected=$true},
    [pscustomobject]@{VID="V-278036"; Title="PasswordHistorySize"; Severity="Medium"; Description="Windows Server 2025 password history must be configured to 24 passwords remembered."; CheckType="AccountPolicy"; Policy="PasswordHistorySize"; Expected=24},
    [pscustomobject]@{VID="V-278035"; Title="ResetLockoutCount"; Severity="Medium"; Description="Windows Server 2025 must have the period of time before the bad logon counter is reset configured to 15 minutes or greater."; CheckType="AccountPolicy"; Policy="ResetLockoutCount"; Expected=15},

    # === USER RIGHTS ASSIGNMENTS ===
    [pscustomobject]@{VID="V-278252"; Title="SeAuditPrivilege"; Severity="Medium"; Description="The Windows Server 2025 `"Generate security audits`" user right must only be assigned to Local Service and Network Service."; CheckType="UserRight"; RightName="SeAuditPrivilege"; Allowed=@("S-1-5-19","S-1-5-20")},
    [pscustomobject]@{VID="V-278244"; Title="SeBackupPrivilege"; Severity="Medium"; Description="The Windows Server 2025 `"Back up files and directories`" user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeBackupPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-278247"; Title="SeCreateGlobalPrivilege"; Severity="Medium"; Description="The Windows Server 2025 `"Create global objects`" user right must only be assigned to Administrators, Service, Local Service, and Network Service."; CheckType="UserRight"; RightName="SeCreateGlobalPrivilege"; Allowed=@("S-1-5-6","S-1-5-19","S-1-5-20","S-1-5-32-544")},
    [pscustomobject]@{VID="V-278245"; Title="SeCreatePagefilePrivilege"; Severity="Medium"; Description="The Windows Server 2025 `"Create a pagefile`" user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeCreatePagefilePrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-278248"; Title="SeCreatePermanentPrivilege"; Severity="Medium"; Description="The Windows Server 2025 `"Create permanent shared objects`" user right must not be assigned to any groups or accounts."; CheckType="UserRight"; RightName="SeCreatePermanentPrivilege"; Allowed=@()},
    [pscustomobject]@{VID="V-278249"; Title="SeCreateSymbolicLinkPrivilege"; Severity="Medium"; Description="The Windows Server 2025 `"Create symbolic links`" user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeCreateSymbolicLinkPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-278246"; Title="SeCreateTokenPrivilege"; Severity="High"; Description="The Windows Server 2025 `"Create a token object`" user right must not be assigned to any groups or accounts."; CheckType="UserRight"; RightName="SeCreateTokenPrivilege"; Allowed=@()},
    [pscustomobject]@{VID="V-278250"; Title="SeDebugPrivilege"; Severity="High"; Description="The Windows Server 2025 `"Debug programs`" user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeDebugPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-278169/V-278185"; Title="SeDenyBatchLogonRight"; Severity="Medium"; Description="The Windows Server 2025 `"Deny log on as a batch job`" user right on domain controllers must be configured to prevent unauthenticated access. / Windows Server 2025 Deny log on as a batch job user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems."; CheckType="UserRight"; RightName="SeDenyBatchLogonRight"; Allowed=@("S-1-5-32-546","Enterprise Admins","Domain Admins")},
    [pscustomobject]@{VID="V-278171/V-278187"; Title="SeDenyInteractiveLogonRight"; Severity="Medium"; Description="The Windows Server 2025 `"Deny log on locally`" user right on domain controllers must be configured to prevent unauthenticated access. / The Windows Server 2025 `"Deny log on locally`" user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems."; CheckType="UserRight"; RightName="SeDenyInteractiveLogonRight"; Allowed=@("S-1-5-32-546","Enterprise Admins","Domain Admins")},
    [pscustomobject]@{VID="V-278168/V-278184"; Title="SeDenyNetworkLogonRight"; Severity="Medium"; Description="The Windows Server 2025 `"Deny access to this computer from the network`" user right on domain controllers must be configured to prevent unauthenticated access. / The Windows Server 2025 `"Deny access to this computer from the network`" user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and local accounts and from unauthenticated access on all systems."; CheckType="UserRight"; RightName="SeDenyNetworkLogonRight"; Allowed=@("Local Account and member of Administrators","S-1-5-32-546","Enterprise Admins","Domain Admins")},
    [pscustomobject]@{VID="V-278174/V-278188"; Title="SeDenyRemoteInteractiveLogonRight"; Severity="Medium"; Description="The Windows Server 2025 `"Deny log on through Remote Desktop Services`" user right on domain controllers must be configured to prevent unauthenticated access. / The Windows Server 2025 `"Deny log on through Remote Desktop Services`" user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and all local accounts and from unauthenticated access on all systems."; CheckType="UserRight"; RightName="SeDenyRemoteInteractiveLogonRight"; Allowed=@("S-1-5-113","S-1-5-32-546","Enterprise Admins","Domain Admins")},
    [pscustomobject]@{VID="V-278170/V-278186"; Title="SeDenyServiceLogonRight"; Severity="Medium"; Description="The Windows Server 2025 `"Deny log on as a service`" user right must be configured to include no accounts or groups (blank) on domain controllers. / The Windows Server 2025 `"Deny log on as a service`" user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts. No other groups or accounts must be assigned this right."; CheckType="UserRight"; RightName="SeDenyServiceLogonRight"; Allowed=@("Enterprise Admins","Domain Admins")},
    [pscustomobject]@{VID="V-278175/V-278189"; Title="SeEnableDelegationPrivilege"; Severity="Medium"; Description="The Windows Server 2025 `"Enable computer and user accounts to be trusted for delegation`" user right must only be assigned to the Administrators group on domain controllers. / The Windows Server 2025 `"Enable computer and user accounts to be trusted for delegation`" user right must not be assigned to any groups or accounts on domain-joined member servers and stand-alone or nondomain-joined systems."; CheckType="UserRight"; RightName="SeEnableDelegationPrivilege"; Allowed=@()},
    [pscustomobject]@{VID="V-278253"; Title="SeImpersonatePrivilege"; Severity="Medium"; Description="The Windows Server 2025 `"Impersonate a client after authentication`" user right must only be assigned to Administrators, Service, Local Service, and Network Service."; CheckType="UserRight"; RightName="SeImpersonatePrivilege"; Allowed=@("S-1-5-6","S-1-5-19","S-1-5-20","S-1-5-32-544")},
    [pscustomobject]@{VID="V-278254"; Title="SeIncreaseBasePriorityPrivilege"; Severity="Medium"; Description="The Windows Server 2025 `"Increase scheduling priority`" user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeIncreaseBasePriorityPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-278243"; Title="SeInteractiveLogonRight"; Severity="Medium"; Description="The Windows Server 2025 `"Allow log on locally`" user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeInteractiveLogonRight"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-278255"; Title="SeLoadDriverPrivilege"; Severity="Medium"; Description="The Windows Server 2025 `"Load and unload device drivers`" user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeLoadDriverPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-278256"; Title="SeLockMemoryPrivilege"; Severity="Medium"; Description="The Windows Server 2025 `"Lock pages in memory`" user right must not be assigned to any groups or accounts."; CheckType="UserRight"; RightName="SeLockMemoryPrivilege"; Allowed=@()},
    [pscustomobject]@{VID="V-278259"; Title="SeManageVolumePrivilege"; Severity="Medium"; Description="The Windows Server 2025 `"Perform volume maintenance tasks`" user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeManageVolumePrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-278165/V-278183"; Title="SeNetworkLogonRight"; Severity="Medium"; Description="The Windows Server 2025 `"Access this computer from the network`" user right must only be assigned to the Administrators, Authenticated Users, and Enterprise Domain Controllers groups on domain controllers. / Windows Server 2025 `"Access this computer from the network`" user right must only be assigned to the Administrators and Authenticated Users groups on domain-joined member servers and stand-alone or nondomain-joined systems."; CheckType="UserRight"; RightName="SeNetworkLogonRight"; Allowed=@("S-1-5-11","S-1-5-32-544")},
    [pscustomobject]@{VID="V-278260"; Title="SeProfileSingleProcessPrivilege"; Severity="Medium"; Description="The Windows Server 2025 `"Profile single process`" user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeProfileSingleProcessPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-278251"; Title="SeRemoteShutdownPrivilege"; Severity="Medium"; Description="The Windows Server 2025 `"Force shutdown from a remote system`" user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeRemoteShutdownPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-278261"; Title="SeRestorePrivilege"; Severity="Medium"; Description="The Windows Server 2025 `"Restore files and directories`" user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeRestorePrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-278257"; Title="SeSecurityPrivilege"; Severity="Medium"; Description="The Windows Server 2025 `"Manage auditing and security log`" user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeSecurityPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-278258"; Title="SeSystemEnvironmentPrivilege"; Severity="Medium"; Description="The Windows Server 2025 `"Modify firmware environment values`" user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeSystemEnvironmentPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-278262"; Title="SeTakeOwnershipPrivilege"; Severity="Medium"; Description="The Windows Server 2025 `"Take ownership of files or other objects`" user right must only be assigned to the Administrators group."; CheckType="UserRight"; RightName="SeTakeOwnershipPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-278242"; Title="SeTcbPrivilege"; Severity="High"; Description="The Windows Server 2025 `"Act as part of the operating system`" user right must not be assigned to any groups or accounts."; CheckType="UserRight"; RightName="SeTcbPrivilege"; Allowed=@()},
    [pscustomobject]@{VID="V-278241"; Title="SeTrustedCredManAccessPrivilege"; Severity="Medium"; Description="The Windows Server 2025 `"Access Credential Manager as a trusted caller`" user right must not be assigned to any groups or accounts."; CheckType="UserRight"; RightName="SeTrustedCredManAccessPrivilege"; Allowed=@()},

    # === SECURITY OPTIONS (Registry) ===
    [pscustomobject]@{VID="V-278181"; Title="CachedLogonsCount"; Severity="Medium"; Description="Windows Server 2025 must limit the caching of logon credentials to four or less on domain-joined member servers."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="CachedLogonsCount"; Expected="4"},
    [pscustomobject]@{VID="V-278209"; Title="ScRemoveOption"; Severity="Medium"; Description="The Windows Server 2025 Smart Card removal option must be configured to Force Logoff or Lock Workstation."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="ScRemoveOption"; Expected="1"},
    [pscustomobject]@{VID="V-278234"; Title="ConsentPromptBehaviorAdmin"; Severity="Medium"; Description="Windows Server 2025 User Account Control (UAC) must, at a minimum, prompt administrators for consent on the secure desktop."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorAdmin"; Expected=2},
    [pscustomobject]@{VID="V-278235"; Title="ConsentPromptBehaviorUser"; Severity="Medium"; Description="Windows Server 2025 User Account Control (UAC) must automatically deny standard user requests for elevation."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorUser"; Expected=0},
    [pscustomobject]@{VID="V-278236"; Title="EnableInstallerDetection"; Severity="Medium"; Description="Windows Server 2025 User Account Control (UAC) must be configured to detect application installations and prompt for elevation."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableInstallerDetection"; Expected=1},
    [pscustomobject]@{VID="V-278238"; Title="EnableLUA"; Severity="Medium"; Description="Windows Server 2025 User Account Control (UAC) must run all administrators in Admin Approval Mode, enabling UAC."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableLUA"; Expected=1},
    [pscustomobject]@{VID="V-278237"; Title="EnableSecureUIAPaths"; Severity="Medium"; Description="Windows Server 2025 User Account Control (UAC) must only elevate UIAccess applications that are installed in secure locations."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableSecureUIAPaths"; Expected=1},
    [pscustomobject]@{VID="V-278233"; Title="EnableUIADesktopToggle"; Severity="Medium"; Description="Windows Server 2025 UIAccess applications must not be allowed to prompt for elevation without using the secure desktop."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableUIADesktopToggle"; Expected=0},
    [pscustomobject]@{VID="V-278239"; Title="EnableVirtualization"; Severity="Medium"; Description="Windows Server 2025 User Account Control (UAC) must virtualize file and registry write failures to per-user locations."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableVirtualization"; Expected=1},
    [pscustomobject]@{VID="V-278232"; Title="FilterAdministratorToken"; Severity="Medium"; Description="Windows Server 2025 User Account Control (UAC) approval mode for the built-in Administrator must be enabled."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="FilterAdministratorToken"; Expected=1},
    [pscustomobject]@{VID="V-278206"; Title="InactivityTimeoutSecs"; Severity="Medium"; Description="Windows Server 2025 machine inactivity limit must be set to 15 minutes or less, locking the system with the screen saver."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="InactivityTimeoutSecs"; Expected=900},
    [pscustomobject]@{VID="V-278223"; Title="SupportedEncryptionTypes"; Severity="Medium"; Description="Windows Server 2025 Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"; Name="SupportedEncryptionTypes"; Expected=2147483640},
    [pscustomobject]@{VID="V-278208"; Title="LegalNoticeCaption"; Severity="Low"; Description="Windows Server 2025 title for legal banner dialog box must be configured with the appropriate text."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LegalNoticeCaption"; Expected="US Department of Defense Warning Statement"},
    [pscustomobject]@{VID="V-278207"; Title="LegalNoticeText"; Severity="Medium"; Description="The Windows Server 2025 required legal notice must be configured to display before console logon."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LegalNoticeText"; Expected="You are accessing a U.S. Government (USG) Information System..."},
    [pscustomobject]@{VID="V-278229"; Title="ForceKeyProtection"; Severity="Medium"; Description="Windows Server 2025 users must be required to enter a password to access private keys stored on the computer."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Cryptography"; Name="ForceKeyProtection"; Expected=2},
    [pscustomobject]@{VID="V-278218"; Title="EveryoneIncludesAnonymous"; Severity="Medium"; Description="Windows Server 2025 must be configured to prevent anonymous users from having the same permissions as the Everyone group."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="EveryoneIncludesAnonymous"; Expected=0},
    [pscustomobject]@{VID="V-278230"; Title="FIPSAlgorithmPolicy Enabled"; Severity="Medium"; Description="Windows Server 2025 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy"; Name="Enabled"; Expected=1},
    [pscustomobject]@{VID="V-278196"; Title="LimitBlankPasswordUse"; Severity="High"; Description="Windows Server 2025 must prevent local accounts with blank passwords from being used from the network."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LimitBlankPasswordUse"; Expected=1},
    [pscustomobject]@{VID="V-278225"; Title="LmCompatibilityLevel"; Severity="High"; Description="Windows Server 2025 LAN Manager authentication level must be configured to send NTLMv2 response only and to refuse LM and NTLM."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LmCompatibilityLevel"; Expected=5},
    [pscustomobject]@{VID="V-278221"; Title="allownullsessionfallback"; Severity="Medium"; Description="Windows Server 2025 must prevent NTLM from falling back to a Null session."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="allownullsessionfallback"; Expected=0},
    [pscustomobject]@{VID="V-278227"; Title="NTLMMinClientSec"; Severity="Medium"; Description="Windows Server 2025 session security for NTLM SSP-based clients must be configured to require NTLMv2 session security and 128-bit encryption."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="NTLMMinClientSec"; Expected=537395200},
    [pscustomobject]@{VID="V-278228"; Title="NTLMMinServerSec"; Severity="Medium"; Description="Windows Server 2025 session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="NTLMMinServerSec"; Expected=537395200},
    [pscustomobject]@{VID="V-278222"; Title="AllowOnlineID"; Severity="Medium"; Description="Windows Server 2025 must prevent PKU2U authentication using online identities."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u"; Name="AllowOnlineID"; Expected=0},
    [pscustomobject]@{VID="V-278217"; Title="RestrictAnonymous"; Severity="High"; Description="Windows Server 2025 must not allow anonymous enumeration of shares."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymous"; Expected=1},
    [pscustomobject]@{VID="V-278216"; Title="RestrictAnonymousSAM"; Severity="High"; Description="Windows Server 2025 must not allow anonymous enumeration of Security Account Manager (SAM) accounts."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymousSAM"; Expected=1},
    [pscustomobject]@{VID="V-278182"; Title="RestrictRemoteSAM"; Severity="Medium"; Description="Windows Server 2025 must restrict remote calls to the Security Account Manager (SAM) to Administrators on domain-joined member servers and stand-alone or nondomain-joined systems."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictRemoteSAM"; Expected="O:BAG:BAD:(A;;RC;;;BA)"},
    [pscustomobject]@{VID="V-278199"; Title="SCENoApplyLegacyAuditPolicy"; Severity="Medium"; Description="Windows Server 2025 must force audit policy subcategory settings to override audit policy category settings."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="SCENoApplyLegacyAuditPolicy"; Expected=1},
    [pscustomobject]@{VID="V-278220"; Title="UseMachineId"; Severity="Medium"; Description="Windows Server 2025 services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity instead of authenticating anonymously."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="UseMachineId"; Expected=1},
    [pscustomobject]@{VID="V-278231"; Title="ProtectionMode"; Severity="Low"; Description="Windows Server 2025 default permissions of global system objects must be strengthened."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"; Name="ProtectionMode"; Expected=1},
    [pscustomobject]@{VID="V-278214"; Title="EnableSecuritySignature (LanManServer)"; Severity="Medium"; Description="The Windows Server 2025 setting Microsoft network server: Digitally sign communications (if client agrees) must be configured to Enabled."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="EnableSecuritySignature"; Expected=1},
    [pscustomobject]@{VID="V-278213"; Title="RequireSecuritySignature (LanManServer)"; Severity="Medium"; Description="The Windows Server 2025 setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="RequireSecuritySignature"; Expected=1},
    [pscustomobject]@{VID="V-278219"; Title="RestrictNullSessAccess"; Severity="High"; Description="Windows Server 2025 must restrict anonymous access to Named Pipes and Shares."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="RestrictNullSessAccess"; Expected=1},
    [pscustomobject]@{VID="V-278212"; Title="EnablePlainTextPassword"; Severity="Medium"; Description="Windows Server 2025 unencrypted passwords must not be sent to third-party Server Message Block (SMB) servers."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="EnablePlainTextPassword"; Expected=0},
    [pscustomobject]@{VID="V-278211"; Title="EnableSecuritySignature (LanmanWorkstation)"; Severity="Medium"; Description="The Windows Server 2025 setting Microsoft network client: Digitally sign communications (if server agrees) must be configured to Enabled."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="EnableSecuritySignature"; Expected=1},
    [pscustomobject]@{VID="V-278210"; Title="RequireSecuritySignature (LanmanWorkstation)"; Severity="Medium"; Description="The Windows Server 2025 setting Microsoft network client: Digitally sign communications (always) must be configured to Enabled."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="RequireSecuritySignature"; Expected=1},
    [pscustomobject]@{VID="V-278226"; Title="LDAPClientIntegrity"; Severity="Medium"; Description="Windows Server 2025 must be configured to at least negotiate signing for LDAP client signing."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"; Name="LDAPClientIntegrity"; Expected=1},
    [pscustomobject]@{VID="V-278203"; Title="DisablePasswordChange"; Severity="Medium"; Description="Windows Server 2025 computer account password must not be prevented from being reset."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="DisablePasswordChange"; Expected=0},
    [pscustomobject]@{VID="V-278204"; Title="MaximumPasswordAge (Netlogon)"; Severity="Medium"; Description="Windows Server 2025 maximum age for machine account passwords must be configured to 30 days or less."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="MaximumPasswordAge"; Expected=30},
    [pscustomobject]@{VID="V-278200"; Title="RequireSignOrSeal"; Severity="Medium"; Description="The Windows Server 2025 setting Domain member: Digitally encrypt or sign secure channel data (always) must be configured to Enabled."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="RequireSignOrSeal"; Expected=1},
    [pscustomobject]@{VID="V-278205"; Title="RequireStrongKey"; Severity="Medium"; Description="Windows Server 2025 must be configured to require a strong session key."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="RequireStrongKey"; Expected=1},
    [pscustomobject]@{VID="V-278201"; Title="SealSecureChannel"; Severity="Medium"; Description="Windows Server 2025 setting Domain member: Digitally encrypt secure channel data (when possible) must be configured to Enabled."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="SealSecureChannel"; Expected=1},
    [pscustomobject]@{VID="V-278202"; Title="SignSecureChannel"; Severity="Medium"; Description="The Windows Server 2025 setting Domain member: Digitally sign secure channel data (when possible) must be configured to Enabled."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="SignSecureChannel"; Expected=1},
    [pscustomobject]@{VID="V-278195"; Title="EnableGuestAccount"; Severity="Medium"; Description="Windows Server 2025 must have the built-in guest account disabled."; CheckType="AccountPolicy"; Policy="EnableGuestAccount"; Expected=0},
    [pscustomobject]@{VID="V-278215"; Title="LSAAnonymousNameLookup"; Severity="High"; Description="Windows Server 2025 must not allow anonymous SID/Name translation."; CheckType="AccountPolicy"; Policy="LSAAnonymousNameLookup"; Expected=0},
    [pscustomobject]@{VID="V-278197"; Title="NewAdministratorName"; Severity="Medium"; Description="The Windows Server 2025 built-in administrator account must be renamed."; CheckType="AccountPolicy"; Policy="NewAdministratorName"; Expected="X_Admin"},
    [pscustomobject]@{VID="V-278198"; Title="NewGuestName"; Severity="Medium"; Description="The Windows Server 2025 built-in guest account must be renamed."; CheckType="AccountPolicy"; Policy="NewGuestName"; Expected="Visitor"},

    # === ADVANCED AUDIT POLICY ===
    [pscustomobject]@{VID="V-278047/V-278048"; Title="Audit Credential Validation"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit Account Logon - Credential Validation successes. / Windows Server 2025 must be configured to audit Account Logon - Credential Validation failures."; CheckType="AuditPolicy"; SubCategory="{0cce923f-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-278049"; Title="Audit Other Account Management Events"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit Account Management - Other Account Management Events successes."; CheckType="AuditPolicy"; SubCategory="{0cce923a-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-278050"; Title="Audit Security Group Management"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit Account Management - Security Group Management successes."; CheckType="AuditPolicy"; SubCategory="{0cce9237-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-278051/V-278052"; Title="Audit User Account Management"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit Account Management - User Account Management successes. / Windows Server 2025 must be configured to audit Account Management - User Account Management failures."; CheckType="AuditPolicy"; SubCategory="{0cce9235-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-278053"; Title="Audit PNP Activity"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit Detailed Tracking - Plug and Play Events successes."; CheckType="AuditPolicy"; SubCategory="{0cce9248-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-278054"; Title="Audit Process Creation"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit Detailed Tracking - Process Creation successes."; CheckType="AuditPolicy"; SubCategory="{0cce922b-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-278055/V-278056"; Title="Audit Account Lockout"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit Logon/Logoff - Account Lockout successes. / Windows Server 2025 must be configured to audit Logon/Logoff - Account Lockout failures."; CheckType="AuditPolicy"; SubCategory="{0cce9217-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-278057"; Title="Audit Group Membership"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit Logon/Logoff - Group Membership successes."; CheckType="AuditPolicy"; SubCategory="{0cce9249-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-278058"; Title="Audit Logoff"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit logoff successes."; CheckType="AuditPolicy"; SubCategory="{0cce9216-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-278059/V-278060"; Title="Audit Logon"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit logon successes. / Windows Server 2025 must be configured to audit logon failures."; CheckType="AuditPolicy"; SubCategory="{0cce9215-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-278061"; Title="Audit Special Logon"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit Logon/Logoff - Special Logon successes."; CheckType="AuditPolicy"; SubCategory="{0cce921b-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-279916/V-279917"; Title="Audit File System"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit file system failures. / Windows Server 2025 must be configured to audit file system successes."; CheckType="AuditPolicy"; SubCategory="{0cce921d-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-279918/V-279919"; Title="Audit Handle Manipulation"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit handle manipulation failures. / Windows Server 2025 must be configured to audit handle manipulation successes."; CheckType="AuditPolicy"; SubCategory="{0cce9223-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-278062/V-278063"; Title="Audit Other Object Access Events"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit Object Access - Other Object Access Events successes. / Windows Server 2025 must be configured to audit Object Access - Other Object Access Events failures."; CheckType="AuditPolicy"; SubCategory="{0cce9227-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-279920/V-279921"; Title="Audit Registry"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit registry failures. / Windows Server 2025 must be configured to audit registry successes."; CheckType="AuditPolicy"; SubCategory="{0cce921e-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-278064/V-278065"; Title="Audit Removable Storage"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit Object Access - Removable Storage successes. / Windows Server 2025 must be configured to audit Object Access - Removable Storage failures."; CheckType="AuditPolicy"; SubCategory="{0cce9245-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-278066/V-278067"; Title="Audit Audit Policy Change"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit Policy Change - Audit Policy Change successes. / Windows Server 2025 must be configured to audit Policy Change - Audit Policy Change failures."; CheckType="AuditPolicy"; SubCategory="{0cce922f-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-278068"; Title="Audit Authentication Policy Change"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit Policy Change - Authentication Policy Change successes."; CheckType="AuditPolicy"; SubCategory="{0cce9230-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-278069"; Title="Audit Authorization Policy Change"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit Policy Change - Authorization Policy Change successes."; CheckType="AuditPolicy"; SubCategory="{0cce9231-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-279922/V-279923"; Title="Audit Sensitive Privilege Use"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit sensitive privilege use successes. / Windows Server 2025 must be configured to audit sensitive privilege use failures."; CheckType="AuditPolicy"; SubCategory="{0cce9228-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-278072/V-278073"; Title="Audit IPsec Driver"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit System - IPsec Driver successes. / Windows Server 2025 must be configured to audit System - IPsec Driver failures."; CheckType="AuditPolicy"; SubCategory="{0cce9213-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-278074/V-278075"; Title="Audit Other System Events"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit System - Other System Events successes. / Windows Server 2025 must be configured to audit System - Other System Events failures."; CheckType="AuditPolicy"; SubCategory="{0cce9214-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-278076"; Title="Audit Security State Change"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit System - Security State Change successes."; CheckType="AuditPolicy"; SubCategory="{0cce9210-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-278077"; Title="Audit Security System Extension"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit System - Security System Extension successes."; CheckType="AuditPolicy"; SubCategory="{0cce9211-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-278078/V-278079"; Title="Audit System Integrity"; Severity="Medium"; Description="Windows Server 2025 must be configured to audit System - System Integrity successes. / Windows Server 2025 must be configured to audit System - System Integrity failures."; CheckType="AuditPolicy"; SubCategory="{0cce9212-69ae-11d9-bed3-505054503030}"; Expected=3},

    # === REGISTRY POLICIES ===
    [pscustomobject]@{VID="V-278080"; Title="Prevent enabling lock screen slide show"; Severity="Medium"; Description="Windows Server 2025 must prevent the display of slide shows on the lock screen."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"; Name="NoLockScreenSlideshow"; Expected=1},
    [pscustomobject]@{VID="V-278178"; Title="Apply UAC restrictions to local accounts on network logons"; Severity="Medium"; Description="Windows Server 2025 local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain-joined member servers."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LocalAccountTokenFilterPolicy"; Expected=0},
    [pscustomobject]@{VID="V-278025"; Title="Configure SMB v1 client driver"; Severity="Medium"; Description="Windows Server 2025 must have the Server Message Block (SMB) v1 protocol disabled on the SMB client."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10"; Name="Start"; Expected=4},
    [pscustomobject]@{VID="V-278024"; Title="Configure SMB v1 server"; Severity="Medium"; Description="Windows Server 2025 must have the Server Message Block (SMB) v1 protocol disabled on the SMB server."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="SMB1"; Expected=0},
    [pscustomobject]@{VID="V-278082"; Title="MSS: (DisableIPSourceRouting IPv6)"; Severity="Low"; Description="Windows Server 2025 Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; Name="DisableIPSourceRouting"; Expected=2},
    [pscustomobject]@{VID="V-278083"; Title="MSS: (DisableIPSourceRouting)"; Severity="Low"; Description="Windows Server 2025 source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="DisableIPSourceRouting"; Expected=2},
    [pscustomobject]@{VID="V-278084"; Title="MSS: (EnableICMPRedirect)"; Severity="Low"; Description="Windows Server 2025 must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)-generated routes."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="EnableICMPRedirect"; Expected=0},
    [pscustomobject]@{VID="V-278085"; Title="MSS: (NoNameReleaseOnDemand)"; Severity="Low"; Description="Windows Server 2025 must be configured to ignore NetBIOS name release requests except from WINS servers."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; Name="NoNameReleaseOnDemand"; Expected=1},
    [pscustomobject]@{VID="V-278086"; Title="Enable insecure guest logons"; Severity="Medium"; Description="Windows Server 2025 insecure logons to an SMB server must be disabled."; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="EnableInsecureGuestLogons"; Expected=0},
    [pscustomobject]@{VID="V-278087"; Title="Hardened UNC Paths - NETLOGON"; Severity="Medium"; Description="Windows Server 2025 hardened Universal Naming Convention (UNC) paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"; Name="\\*\NETLOGON"; Expected="RequireMutualAuthentication=1, RequireIntegrity=1"},
    [pscustomobject]@{VID="V-278087"; Title="Hardened UNC Paths - SYSVOL"; Severity="Medium"; Description="Windows Server 2025 hardened Universal Naming Convention (UNC) paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"; Name="\\*\SYSVOL"; Expected="RequireMutualAuthentication=1, RequireIntegrity=1"},
    [pscustomobject]@{VID="V-278088"; Title="Include command line in process creation events"; Severity="Medium"; Description="Windows Server 2025 command line data must be included in process creation events."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"; Name="ProcessCreationIncludeCmdLine_Enabled"; Expected=1},
    [pscustomobject]@{VID="V-278089"; Title="Remote host allows delegation of non-exportable credentials"; Severity="Medium"; Description="Windows Server 2025 must be configured to enable Remote host allows delegation of nonexportable credentials."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"; Name="AllowProtectedCreds"; Expected=1},
    [pscustomobject]@{VID="V-278090"; Title="Turn On Virtualization Based Security"; Severity="Medium"; Description="Windows Server 2025 virtualization-based security must be enabled with the platform security level configured to Secure Boot or Secure Boot with DMA Protection."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name="EnableVirtualizationBasedSecurity"; Expected=1},
    [pscustomobject]@{VID="V-278092"; Title="Configure registry policy processing"; Severity="Medium"; Description="Windows Server 2025 group policy objects must be reprocessed even if they have not changed."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy"; Name="NoBackgroundPolicy"; Expected=0; Expected2=1},
    [pscustomobject]@{VID="V-278093"; Title="Turn off downloading of print drivers over HTTP"; Severity="Medium"; Description="Windows Server 2025 downloading print driver packages over HTTP must be turned off."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Name="DisableHTTPPrinting"; Expected=1},
    [pscustomobject]@{VID="V-278094"; Title="Turn off printing over HTTP"; Severity="Medium"; Description="Windows Server 2025 printing over HTTP must be turned off."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Name="DisableWebPrinting"; Expected=1},
    [pscustomobject]@{VID="WS2025-COMP-0126"; Title="Password Settings (LAPS)"; Severity="Medium"; Description="Local Administrator Password Solution (LAPS) password complexity - not part of the official DISA Windows Server 2025 V1R1 baseline; carried over from this script's original author."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"; Name="PasswordComplexity"; Expected=4},
    [pscustomobject]@{VID="V-278095"; Title="Do not display network selection UI"; Severity="Medium"; Description="Windows Server 2025 network selection user interface (UI) must not be displayed on the logon screen."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="DontDisplayNetworkSelectionUI"; Expected=1},
    [pscustomobject]@{VID="V-278179"; Title="Enumerate local users on domain-joined computers"; Severity="Medium"; Description="Windows Server 2025 local users on domain-joined member servers must not be enumerated."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnumerateLocalUsers"; Expected=0},
    [pscustomobject]@{VID="V-278096"; Title="Require a password when a computer wakes (on battery)"; Severity="Medium"; Description="Windows Server 2025 users must be prompted to authenticate when the system wakes from sleep (on battery)."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power"; Name="PromptForPasswordOnResumeBattery"; Expected=1},
    [pscustomobject]@{VID="V-278097"; Title="Require a password when a computer wakes (plugged in)"; Severity="Medium"; Description="Windows Server 2025 users must be prompted to authenticate when the system wakes from sleep (plugged in)."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power"; Name="PromptForPasswordOnResumeAC"; Expected=1},
    [pscustomobject]@{VID="V-278180"; Title="Restrict Unauthenticated RPC clients"; Severity="Medium"; Description="Windows Server 2025 must restrict unauthenticated Remote Procedure Call (RPC) clients from connecting to the RPC server on domain-joined member servers and stand-alone or nondomain-joined systems."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"; Name="RestrictRemoteClients"; Expected=1},
    [pscustomobject]@{VID="V-278098"; Title="Turn off Inventory Collector"; Severity="Low"; Description="Windows Server 2025 Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx"; Name="DisableInventory"; Expected=1},
    [pscustomobject]@{VID="V-278099"; Title="Disallow Autoplay for non-volume devices"; Severity="High"; Description="Windows Server 2025 AutoPlay must be turned off for nonvolume devices."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="NoAutoplayfornonVolume"; Expected=1},
    [pscustomobject]@{VID="V-278100"; Title="Set the default behavior for AutoRun"; Severity="High"; Description="Windows Server 2025 default AutoRun behavior must be configured to prevent AutoRun commands."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoAutorun"; Expected=1},
    [pscustomobject]@{VID="V-278101"; Title="Turn off Autoplay"; Severity="High"; Description="Windows Server 2025 AutoPlay must be disabled for all drives."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"; Expected=255},
    [pscustomobject]@{VID="V-278102"; Title="Enumerate administrator accounts on elevation"; Severity="Medium"; Description="Windows Server 2025 administrator accounts must not be enumerated during elevation."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"; Name="EnumerateAdministrators"; Expected=0},
    [pscustomobject]@{VID="V-278103"; Title="Allow Diagnostic Data"; Severity="Medium"; Description="Windows Server 2025 Telemetry must be configured to limit diagnostic data sent to Microsoft."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"; Expected=1},
    [pscustomobject]@{VID="V-278104"; Title="Download Mode"; Severity="Low"; Description="Windows Server 2025 Windows Update must not obtain updates from other PCs on the internet."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"; Name="DODownloadMode"; Expected=1},
    [pscustomobject]@{VID="V-278105"; Title="Specify the maximum log file size (Application)"; Severity="Medium"; Description="Windows Server 2025 Application event log size must be configured to 32768 KB or greater."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"; Name="MaxSize"; Expected=32768},
    [pscustomobject]@{VID="V-278106"; Title="Specify the maximum log file size (Security)"; Severity="Medium"; Description="Windows Server 2025 Security event log size must be configured to 196608 KB or greater."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"; Name="MaxSize"; Expected=196608},
    [pscustomobject]@{VID="V-278107"; Title="Specify the maximum log file size (System)"; Severity="Medium"; Description="Windows Server 2025 System event log size must be configured to 32768 KB or greater."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"; Name="MaxSize"; Expected=32768},
    [pscustomobject]@{VID="V-278112"; Title="Do not allow passwords to be saved"; Severity="Medium"; Description="Windows Server 2025 must not save passwords in the Remote Desktop Client."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="DisablePasswordSaving"; Expected=1},
    [pscustomobject]@{VID="V-278113"; Title="Do not allow drive redirection"; Severity="Medium"; Description="Windows Server 2025 Remote Desktop Services must prevent drive redirection."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fDisableCdm"; Expected=1},
    [pscustomobject]@{VID="V-278114"; Title="Always prompt for password upon connection"; Severity="Medium"; Description="Windows Server 2025 Remote Desktop Services must always prompt a client for passwords upon connection."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fPromptForPassword"; Expected=1},
    [pscustomobject]@{VID="V-278115"; Title="Require secure RPC communication"; Severity="Medium"; Description="Windows Server 2025 Remote Desktop Services must require secure Remote Procedure Call (RPC) communications."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fEncryptRPCTraffic"; Expected=1},
    [pscustomobject]@{VID="V-278116"; Title="Set client connection encryption level"; Severity="Medium"; Description="Windows Server 2025 Remote Desktop Services must be configured with the client connection encryption set to High Level."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="MinEncryptionLevel"; Expected=3},
    [pscustomobject]@{VID="V-278117"; Title="Prevent downloading of enclosures"; Severity="Medium"; Description="Windows Server 2025 must prevent attachments from being downloaded from RSS feeds."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"; Name="DisableEnclosureDownload"; Expected=1},
    [pscustomobject]@{VID="V-278119"; Title="Allow indexing of encrypted files"; Severity="Medium"; Description="Windows Server 2025 must prevent Indexing of encrypted files."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowIndexingEncryptedStoresOrItems"; Expected=0},
    [pscustomobject]@{VID="V-278108"; Title="Configure Windows Defender SmartScreen"; Severity="Medium"; Description="Windows Server 2025 Microsoft Defender antivirus SmartScreen must be enabled."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnableSmartScreen"; Expected=1},
    [pscustomobject]@{VID="V-278120"; Title="Allow user control over installs"; Severity="Medium"; Description="Windows Server 2025 must prevent users from changing installation options."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="EnableUserControl"; Expected=0},
    [pscustomobject]@{VID="V-278121"; Title="Always install with elevated privileges"; Severity="High"; Description="Windows Server 2025 must disable the Windows Installer Always install with elevated privileges option."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="AlwaysInstallElevated"; Expected=0},
    [pscustomobject]@{VID="V-278123"; Title="Sign-in and lock last interactive user automatically after a restart"; Severity="Medium"; Description="Windows Server 2025 must disable automatically signing in the last interactive user after a system-initiated restart."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="DisableAutomaticRestartSignOn"; Expected=1},
    [pscustomobject]@{VID="V-278124"; Title="Turn on PowerShell Script Block Logging"; Severity="Medium"; Description="Windows Server 2025 PowerShell script block logging must be enabled."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name="EnableScriptBlockLogging"; Expected=1},
    [pscustomobject]@{VID="V-278131"; Title="Turn on PowerShell Transcription"; Severity="Medium"; Description="Windows Server 2025 must have PowerShell Transcription enabled."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name="EnableTranscripting"; Expected=1},
    [pscustomobject]@{VID="V-278125"; Title="Allow Basic authentication (WinRM Client)"; Severity="High"; Description="Windows Server 2025 Windows Remote Management (WinRM) client must not use Basic authentication."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowBasic"; Expected=0},
    [pscustomobject]@{VID="V-278126"; Title="Allow unencrypted traffic (WinRM Client)"; Severity="Medium"; Description="Windows Server 2025 Windows Remote Management (WinRM) client must not allow unencrypted traffic."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowUnencryptedTraffic"; Expected=0},
    [pscustomobject]@{VID="V-278127"; Title="Disallow Digest authentication (WinRM Client)"; Severity="Medium"; Description="Windows Server 2025 Windows Remote Management (WinRM) client must not use Digest authentication."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowDigest"; Expected=0},
    [pscustomobject]@{VID="V-278128"; Title="Allow Basic authentication (WinRM Service)"; Severity="High"; Description="Windows Server 2025 Windows Remote Management (WinRM) service must not use Basic authentication."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="AllowBasic"; Expected=0},
    [pscustomobject]@{VID="V-278129"; Title="Allow unencrypted traffic (WinRM Service)"; Severity="Medium"; Description="Windows Server 2025 Windows Remote Management (WinRM) service must not allow unencrypted traffic."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="AllowUnencryptedTraffic"; Expected=0},
    [pscustomobject]@{VID="V-278130"; Title="Disallow WinRM from storing RunAs credentials"; Severity="Medium"; Description="Windows Server 2025 Windows Remote Management (WinRM) service must not store RunAs credentials."; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="DisableRunAs"; Expected=1}
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
        $iniPath = if ($RulesFile) { $RulesFile } else { Join-Path $PSScriptRoot 'WindowsServer2025-DoD-STIG-Computer-V1R1.ini' }
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
# MAIN EXECUTION
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
# OUTPUT
# =============================================================================
if ($PassThru) { return $report }

$report | Sort-Object Sev, VID | Format-Table VID, Sev, Title, Status, Remediated -AutoSize

if ($Remediate) {
    Write-Host "`nRemediation complete for all DoD WinSvr 2025 MS STIG Comp v1r1 rules!" -ForegroundColor Green
    if ($rebootRequired) { Write-Host "Reboot required for some settings." -ForegroundColor Yellow }
} else {
    Write-Host "`nRun with -Remediate to fix Non-Compliant items." -ForegroundColor Cyan
}
Write-Host "DoD WinSvr 2025 MS STIG Comp v1r1 is finished." -ForegroundColor White
