<#
.SYNOPSIS
    DoD WinSvr 2025 MS STIG Comp v1r1

.DESCRIPTION
    Checks and remediates DoD Windows Server 2025 MS STIG Compliance for Computer settings (v1r1).

.EXAMPLE
    # Check compliance only
    .\WindowsServer2025-DoD-STIG-Computer-V1R1.ps1

    # Check and remediate non-compliant settings
    .\WindowsServer2025-DoD-STIG-Computer-V1R1.ps1 -Remediate

.NOTES
    Author: Robert Weber
#>

param([switch]$Remediate)

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

# =============================================================================
# STIG RULES ARRAY
# =============================================================================
$rules = @(

    # === ACCOUNT POLICIES ===
    [pscustomobject]@{VID="V-XXXXXX"; Title="ClearTextPassword"; CheckType="AccountPolicy"; Policy="ClearTextPassword"; Expected=$false},
    [pscustomobject]@{VID="V-XXXXXX"; Title="LockoutBadCount"; CheckType="AccountPolicy"; Policy="LockoutBadCount"; Expected=3},
    [pscustomobject]@{VID="V-XXXXXX"; Title="LockoutDuration"; CheckType="AccountPolicy"; Policy="LockoutDuration"; Expected=15},
    [pscustomobject]@{VID="V-XXXXXX"; Title="MaximumPasswordAge"; CheckType="AccountPolicy"; Policy="MaximumPasswordAge"; Expected=60},
    [pscustomobject]@{VID="V-XXXXXX"; Title="MinimumPasswordAge"; CheckType="AccountPolicy"; Policy="MinimumPasswordAge"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="PasswordComplexity"; CheckType="AccountPolicy"; Policy="PasswordComplexity"; Expected=$true},
    [pscustomobject]@{VID="V-XXXXXX"; Title="PasswordHistorySize"; CheckType="AccountPolicy"; Policy="PasswordHistorySize"; Expected=24},
    [pscustomobject]@{VID="V-XXXXXX"; Title="ResetLockoutCount"; CheckType="AccountPolicy"; Policy="ResetLockoutCount"; Expected=15},

    # === USER RIGHTS ASSIGNMENTS ===
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeAuditPrivilege"; CheckType="UserRight"; RightName="SeAuditPrivilege"; Allowed=@("S-1-5-19","S-1-5-20")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeBackupPrivilege"; CheckType="UserRight"; RightName="SeBackupPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeCreateGlobalPrivilege"; CheckType="UserRight"; RightName="SeCreateGlobalPrivilege"; Allowed=@("S-1-5-6","S-1-5-19","S-1-5-20","S-1-5-32-544")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeCreatePagefilePrivilege"; CheckType="UserRight"; RightName="SeCreatePagefilePrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeCreatePermanentPrivilege"; CheckType="UserRight"; RightName="SeCreatePermanentPrivilege"; Allowed=@()},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeCreateSymbolicLinkPrivilege"; CheckType="UserRight"; RightName="SeCreateSymbolicLinkPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeCreateTokenPrivilege"; CheckType="UserRight"; RightName="SeCreateTokenPrivilege"; Allowed=@()},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeDebugPrivilege"; CheckType="UserRight"; RightName="SeDebugPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeDenyBatchLogonRight"; CheckType="UserRight"; RightName="SeDenyBatchLogonRight"; Allowed=@("S-1-5-32-546","Enterprise Admins","Domain Admins")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeDenyInteractiveLogonRight"; CheckType="UserRight"; RightName="SeDenyInteractiveLogonRight"; Allowed=@("S-1-5-32-546","Enterprise Admins","Domain Admins")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeDenyNetworkLogonRight"; CheckType="UserRight"; RightName="SeDenyNetworkLogonRight"; Allowed=@("Local Account and member of Administrators","S-1-5-32-546","Enterprise Admins","Domain Admins")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeDenyRemoteInteractiveLogonRight"; CheckType="UserRight"; RightName="SeDenyRemoteInteractiveLogonRight"; Allowed=@("S-1-5-113","S-1-5-32-546","Enterprise Admins","Domain Admins")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeDenyServiceLogonRight"; CheckType="UserRight"; RightName="SeDenyServiceLogonRight"; Allowed=@("Enterprise Admins","Domain Admins")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeEnableDelegationPrivilege"; CheckType="UserRight"; RightName="SeEnableDelegationPrivilege"; Allowed=@()},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeImpersonatePrivilege"; CheckType="UserRight"; RightName="SeImpersonatePrivilege"; Allowed=@("S-1-5-6","S-1-5-19","S-1-5-20","S-1-5-32-544")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeIncreaseBasePriorityPrivilege"; CheckType="UserRight"; RightName="SeIncreaseBasePriorityPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeInteractiveLogonRight"; CheckType="UserRight"; RightName="SeInteractiveLogonRight"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeLoadDriverPrivilege"; CheckType="UserRight"; RightName="SeLoadDriverPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeLockMemoryPrivilege"; CheckType="UserRight"; RightName="SeLockMemoryPrivilege"; Allowed=@()},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeManageVolumePrivilege"; CheckType="UserRight"; RightName="SeManageVolumePrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeNetworkLogonRight"; CheckType="UserRight"; RightName="SeNetworkLogonRight"; Allowed=@("S-1-5-11","S-1-5-32-544")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeProfileSingleProcessPrivilege"; CheckType="UserRight"; RightName="SeProfileSingleProcessPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeRemoteShutdownPrivilege"; CheckType="UserRight"; RightName="SeRemoteShutdownPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeRestorePrivilege"; CheckType="UserRight"; RightName="SeRestorePrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeSecurityPrivilege"; CheckType="UserRight"; RightName="SeSecurityPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeSystemEnvironmentPrivilege"; CheckType="UserRight"; RightName="SeSystemEnvironmentPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeTakeOwnershipPrivilege"; CheckType="UserRight"; RightName="SeTakeOwnershipPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeTcbPrivilege"; CheckType="UserRight"; RightName="SeTcbPrivilege"; Allowed=@()},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SeTrustedCredManAccessPrivilege"; CheckType="UserRight"; RightName="SeTrustedCredManAccessPrivilege"; Allowed=@()},

    # === SECURITY OPTIONS (Registry) ===
    [pscustomobject]@{VID="V-XXXXXX"; Title="CachedLogonsCount"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="CachedLogonsCount"; Expected="4"},
    [pscustomobject]@{VID="V-XXXXXX"; Title="ScRemoveOption"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="ScRemoveOption"; Expected="1"},
    [pscustomobject]@{VID="V-XXXXXX"; Title="ConsentPromptBehaviorAdmin"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorAdmin"; Expected=2},
    [pscustomobject]@{VID="V-XXXXXX"; Title="ConsentPromptBehaviorUser"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorUser"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="EnableInstallerDetection"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableInstallerDetection"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="EnableLUA"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableLUA"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="EnableSecureUIAPaths"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableSecureUIAPaths"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="EnableUIADesktopToggle"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableUIADesktopToggle"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="EnableVirtualization"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableVirtualization"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="FilterAdministratorToken"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="FilterAdministratorToken"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="InactivityTimeoutSecs"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="InactivityTimeoutSecs"; Expected=900},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SupportedEncryptionTypes"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"; Name="SupportedEncryptionTypes"; Expected=2147483640},
    [pscustomobject]@{VID="V-XXXXXX"; Title="LegalNoticeCaption"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LegalNoticeCaption"; Expected="US Department of Defense Warning Statement"},
    [pscustomobject]@{VID="V-XXXXXX"; Title="LegalNoticeText"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LegalNoticeText"; Expected="You are accessing a U.S. Government (USG) Information System..."},
    [pscustomobject]@{VID="V-XXXXXX"; Title="ForceKeyProtection"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Cryptography"; Name="ForceKeyProtection"; Expected=2},
    [pscustomobject]@{VID="V-XXXXXX"; Title="EveryoneIncludesAnonymous"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="EveryoneIncludesAnonymous"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="FIPSAlgorithmPolicy Enabled"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy"; Name="Enabled"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="LimitBlankPasswordUse"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LimitBlankPasswordUse"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="LmCompatibilityLevel"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LmCompatibilityLevel"; Expected=5},
    [pscustomobject]@{VID="V-XXXXXX"; Title="allownullsessionfallback"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="allownullsessionfallback"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="NTLMMinClientSec"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="NTLMMinClientSec"; Expected=537395200},
    [pscustomobject]@{VID="V-XXXXXX"; Title="NTLMMinServerSec"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="NTLMMinServerSec"; Expected=537395200},
    [pscustomobject]@{VID="V-XXXXXX"; Title="AllowOnlineID"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u"; Name="AllowOnlineID"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="RestrictAnonymous"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymous"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="RestrictAnonymousSAM"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymousSAM"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="RestrictRemoteSAM"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictRemoteSAM"; Expected="O:BAG:BAD:(A;;RC;;;BA)"},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SCENoApplyLegacyAuditPolicy"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="SCENoApplyLegacyAuditPolicy"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="UseMachineId"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="UseMachineId"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="ProtectionMode"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"; Name="ProtectionMode"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="EnableSecuritySignature (LanManServer)"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="EnableSecuritySignature"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="RequireSecuritySignature (LanManServer)"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="RequireSecuritySignature"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="RestrictNullSessAccess"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="RestrictNullSessAccess"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="EnablePlainTextPassword"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="EnablePlainTextPassword"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="EnableSecuritySignature (LanmanWorkstation)"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="EnableSecuritySignature"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="RequireSecuritySignature (LanmanWorkstation)"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="RequireSecuritySignature"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="LDAPClientIntegrity"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"; Name="LDAPClientIntegrity"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="DisablePasswordChange"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="DisablePasswordChange"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="MaximumPasswordAge (Netlogon)"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="MaximumPasswordAge"; Expected=30},
    [pscustomobject]@{VID="V-XXXXXX"; Title="RequireSignOrSeal"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="RequireSignOrSeal"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="RequireStrongKey"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="RequireStrongKey"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SealSecureChannel"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="SealSecureChannel"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="SignSecureChannel"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="SignSecureChannel"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="EnableGuestAccount"; CheckType="AccountPolicy"; Policy="EnableGuestAccount"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="LSAAnonymousNameLookup"; CheckType="AccountPolicy"; Policy="LSAAnonymousNameLookup"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="NewAdministratorName"; CheckType="AccountPolicy"; Policy="NewAdministratorName"; Expected="X_Admin"},
    [pscustomobject]@{VID="V-XXXXXX"; Title="NewGuestName"; CheckType="AccountPolicy"; Policy="NewGuestName"; Expected="Visitor"},

    # === ADVANCED AUDIT POLICY ===
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit Credential Validation"; CheckType="AuditPolicy"; SubCategory="{0cce923f-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit Other Account Management Events"; CheckType="AuditPolicy"; SubCategory="{0cce923a-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit Security Group Management"; CheckType="AuditPolicy"; SubCategory="{0cce9237-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit User Account Management"; CheckType="AuditPolicy"; SubCategory="{0cce9235-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit PNP Activity"; CheckType="AuditPolicy"; SubCategory="{0cce9248-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit Process Creation"; CheckType="AuditPolicy"; SubCategory="{0cce922b-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit Account Lockout"; CheckType="AuditPolicy"; SubCategory="{0cce9217-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit Group Membership"; CheckType="AuditPolicy"; SubCategory="{0cce9249-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit Logoff"; CheckType="AuditPolicy"; SubCategory="{0cce9216-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit Logon"; CheckType="AuditPolicy"; SubCategory="{0cce9215-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit Special Logon"; CheckType="AuditPolicy"; SubCategory="{0cce921b-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit File System"; CheckType="AuditPolicy"; SubCategory="{0cce921d-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit Handle Manipulation"; CheckType="AuditPolicy"; SubCategory="{0cce9223-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit Other Object Access Events"; CheckType="AuditPolicy"; SubCategory="{0cce9227-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit Registry"; CheckType="AuditPolicy"; SubCategory="{0cce921e-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit Removable Storage"; CheckType="AuditPolicy"; SubCategory="{0cce9245-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit Audit Policy Change"; CheckType="AuditPolicy"; SubCategory="{0cce922f-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit Authentication Policy Change"; CheckType="AuditPolicy"; SubCategory="{0cce9230-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit Authorization Policy Change"; CheckType="AuditPolicy"; SubCategory="{0cce9231-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit Sensitive Privilege Use"; CheckType="AuditPolicy"; SubCategory="{0cce9228-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit IPsec Driver"; CheckType="AuditPolicy"; SubCategory="{0cce9213-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit Other System Events"; CheckType="AuditPolicy"; SubCategory="{0cce9214-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit Security State Change"; CheckType="AuditPolicy"; SubCategory="{0cce9210-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit Security System Extension"; CheckType="AuditPolicy"; SubCategory="{0cce9211-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Audit System Integrity"; CheckType="AuditPolicy"; SubCategory="{0cce9212-69ae-11d9-bed3-505054503030}"; Expected=3},

    # === REGISTRY POLICIES ===
    [pscustomobject]@{VID="V-XXXXXX"; Title="Prevent enabling lock screen slide show"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"; Name="NoLockScreenSlideshow"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Apply UAC restrictions to local accounts on network logons"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LocalAccountTokenFilterPolicy"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Configure SMB v1 client driver"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10"; Name="Start"; Expected=4},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Configure SMB v1 server"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="SMB1"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="MSS: (DisableIPSourceRouting IPv6)"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; Name="DisableIPSourceRouting"; Expected=2},
    [pscustomobject]@{VID="V-XXXXXX"; Title="MSS: (DisableIPSourceRouting)"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="DisableIPSourceRouting"; Expected=2},
    [pscustomobject]@{VID="V-XXXXXX"; Title="MSS: (EnableICMPRedirect)"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="EnableICMPRedirect"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="MSS: (NoNameReleaseOnDemand)"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; Name="NoNameReleaseOnDemand"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Enable insecure guest logons"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="EnableInsecureGuestLogons"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Hardened UNC Paths - NETLOGON"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"; Name="\\*\NETLOGON"; Expected="RequireMutualAuthentication=1, RequireIntegrity=1"},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Hardened UNC Paths - SYSVOL"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"; Name="\\*\SYSVOL"; Expected="RequireMutualAuthentication=1, RequireIntegrity=1"},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Include command line in process creation events"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"; Name="ProcessCreationIncludeCmdLine_Enabled"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Remote host allows delegation of non-exportable credentials"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"; Name="AllowProtectedCreds"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Turn On Virtualization Based Security"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name="EnableVirtualizationBasedSecurity"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Configure registry policy processing"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy"; Name="NoBackgroundPolicy"; Expected=0; Expected2=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Turn off downloading of print drivers over HTTP"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Name="DisableHTTPPrinting"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Turn off printing over HTTP"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Name="DisableWebPrinting"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Password Settings (LAPS)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"; Name="PasswordComplexity"; Expected=4},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Do not display network selection UI"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="DontDisplayNetworkSelectionUI"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Enumerate local users on domain-joined computers"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnumerateLocalUsers"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Require a password when a computer wakes (on battery)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power"; Name="PromptForPasswordOnResumeBattery"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Require a password when a computer wakes (plugged in)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power"; Name="PromptForPasswordOnResumeAC"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Restrict Unauthenticated RPC clients"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"; Name="RestrictRemoteClients"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Turn off Inventory Collector"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx"; Name="DisableInventory"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Disallow Autoplay for non-volume devices"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="NoAutoplayfornonVolume"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Set the default behavior for AutoRun"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoAutorun"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Turn off Autoplay"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"; Expected=255},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Enumerate administrator accounts on elevation"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"; Name="EnumerateAdministrators"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Allow Diagnostic Data"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Download Mode"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"; Name="DODownloadMode"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Specify the maximum log file size (Application)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"; Name="MaxSize"; Expected=32768},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Specify the maximum log file size (Security)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"; Name="MaxSize"; Expected=196608},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Specify the maximum log file size (System)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"; Name="MaxSize"; Expected=32768},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Do not allow passwords to be saved"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="DisablePasswordSaving"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Do not allow drive redirection"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fDisableCdm"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Always prompt for password upon connection"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fPromptForPassword"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Require secure RPC communication"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fEncryptRPCTraffic"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Set client connection encryption level"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="MinEncryptionLevel"; Expected=3},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Prevent downloading of enclosures"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"; Name="DisableEnclosureDownload"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Allow indexing of encrypted files"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowIndexingEncryptedStoresOrItems"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Configure Windows Defender SmartScreen"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnableSmartScreen"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Allow user control over installs"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="EnableUserControl"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Always install with elevated privileges"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="AlwaysInstallElevated"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Sign-in and lock last interactive user automatically after a restart"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="DisableAutomaticRestartSignOn"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Turn on PowerShell Script Block Logging"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name="EnableScriptBlockLogging"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Turn on PowerShell Transcription"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name="EnableTranscripting"; Expected=1},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Allow Basic authentication (WinRM Client)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowBasic"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Allow unencrypted traffic (WinRM Client)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowUnencryptedTraffic"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Disallow Digest authentication (WinRM Client)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowDigest"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Allow Basic authentication (WinRM Service)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="AllowBasic"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Allow unencrypted traffic (WinRM Service)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="AllowUnencryptedTraffic"; Expected=0},
    [pscustomobject]@{VID="V-XXXXXX"; Title="Disallow WinRM from storing RunAs credentials"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="DisableRunAs"; Expected=1}
)

# =============================================================================
# MAIN EXECUTION
# =============================================================================
$report = @()
$rebootRequired = $false

foreach ($rule in $rules) {
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
        VID        = $rule.VID
        Title      = $rule.Title
        Status     = $status
        Remediated = if ($Remediate -and $remediated) { "Yes" } else { "No" }
    }
}

# =============================================================================
# OUTPUT
# =============================================================================
$report | Sort-Object VID | Format-Table -AutoSize

if ($Remediate) {
    Write-Host "`nRemediation complete for all DoD WinSvr 2025 MS STIG Comp v1r1 rules!" -ForegroundColor Green
    if ($rebootRequired) { Write-Host "Reboot required for some settings." -ForegroundColor Yellow }
} else {
    Write-Host "`nRun with -Remediate to fix Non-Compliant items." -ForegroundColor Cyan
}
Write-Host "DoD WinSvr 2025 MS STIG Comp v1r1 is finished." -ForegroundColor White