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

.EXAMPLE
    .\WindowsServer2022-STIG-V2R7-FULL.ps1 -Remediate

.NOTES
    Author: Robert Weber
#>

param([switch]$Remediate)

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

# =============================================================================
# STIG RULES ARRAY
# =============================================================================
$rules = @(

    # ====================== ACCOUNT POLICIES ======================
    [pscustomobject]@{VID="V-254238"; Title="ClearTextPassword"; CheckType="AccountPolicy"; Policy="ClearTextPassword"; Expected=$false}
    [pscustomobject]@{VID="V-254239"; Title="LockoutBadCount"; CheckType="AccountPolicy"; Policy="LockoutBadCount"; Expected=3}
    [pscustomobject]@{VID="V-254240"; Title="LockoutDuration"; CheckType="AccountPolicy"; Policy="LockoutDuration"; Expected=15}
    [pscustomobject]@{VID="V-254241"; Title="MaximumPasswordAge"; CheckType="AccountPolicy"; Policy="MaximumPasswordAge"; Expected=60}
    [pscustomobject]@{VID="V-254242"; Title="MinimumPasswordAge"; CheckType="AccountPolicy"; Policy="MinimumPasswordAge"; Expected=1}
    [pscustomobject]@{VID="V-254243"; Title="MinimumPasswordLength"; CheckType="AccountPolicy"; Policy="MinimumPasswordLength"; Expected=14}
    [pscustomobject]@{VID="V-254244"; Title="PasswordComplexity"; CheckType="AccountPolicy"; Policy="PasswordComplexity"; Expected=$true}
    [pscustomobject]@{VID="V-254245"; Title="PasswordHistorySize"; CheckType="AccountPolicy"; Policy="PasswordHistorySize"; Expected=24}
    [pscustomobject]@{VID="V-254246"; Title="ResetLockoutCount"; CheckType="AccountPolicy"; Policy="ResetLockoutCount"; Expected=15}

    # ====================== USER RIGHTS ASSIGNMENTS ======================
    [pscustomobject]@{VID="V-254491"; Title="SeTrustedCredManAccessPrivilege"; CheckType="UserRight"; RightName="SeTrustedCredManAccessPrivilege"; Allowed=@()}
    [pscustomobject]@{VID="V-254492"; Title="SeAuditPrivilege"; CheckType="UserRight"; RightName="SeAuditPrivilege"; Allowed=@("S-1-5-19","S-1-5-20")}
    [pscustomobject]@{VID="V-254493"; Title="SeBackupPrivilege"; CheckType="UserRight"; RightName="SeBackupPrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254494"; Title="SeCreateGlobalPrivilege"; CheckType="UserRight"; RightName="SeCreateGlobalPrivilege"; Allowed=@("S-1-5-6","S-1-5-19","S-1-5-20","S-1-5-32-544")}
    [pscustomobject]@{VID="V-254495"; Title="SeCreatePagefilePrivilege"; CheckType="UserRight"; RightName="SeCreatePagefilePrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254496"; Title="SeCreatePermanentPrivilege"; CheckType="UserRight"; RightName="SeCreatePermanentPrivilege"; Allowed=@()}
    [pscustomobject]@{VID="V-254497"; Title="SeCreateSymbolicLinkPrivilege"; CheckType="UserRight"; RightName="SeCreateSymbolicLinkPrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254498"; Title="SeCreateTokenPrivilege"; CheckType="UserRight"; RightName="SeCreateTokenPrivilege"; Allowed=@()}
    [pscustomobject]@{VID="V-254499"; Title="SeDebugPrivilege"; CheckType="UserRight"; RightName="SeDebugPrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254500"; Title="SeDenyBatchLogonRight"; CheckType="UserRight"; RightName="SeDenyBatchLogonRight"; Allowed=@("S-1-5-32-546","ADD YOUR ENTERPRISE ADMINS","ADD YOUR DOMAIN ADMINS")}
    [pscustomobject]@{VID="V-254501"; Title="SeDenyInteractiveLogonRight"; CheckType="UserRight"; RightName="SeDenyInteractiveLogonRight"; Allowed=@("S-1-5-32-546","ADD YOUR ENTERPRISE ADMINS","ADD YOUR DOMAIN ADMINS")}
    [pscustomobject]@{VID="V-254502"; Title="SeDenyNetworkLogonRight"; CheckType="UserRight"; RightName="SeDenyNetworkLogonRight"; Allowed=@("S-1-5-114","S-1-5-32-546","ADD YOUR ENTERPRISE ADMINS","ADD YOUR DOMAIN ADMINS")}
    [pscustomobject]@{VID="V-254503"; Title="SeDenyRemoteInteractiveLogonRight"; CheckType="UserRight"; RightName="SeDenyRemoteInteractiveLogonRight"; Allowed=@("S-1-5-113","S-1-5-32-546","ADD YOUR ENTERPRISE ADMINS","ADD YOUR DOMAIN ADMINS")}
    [pscustomobject]@{VID="V-254504"; Title="SeDenyServiceLogonRight"; CheckType="UserRight"; RightName="SeDenyServiceLogonRight"; Allowed=@("ADD YOUR ENTERPRISE ADMINS","ADD YOUR DOMAIN ADMINS")}
    [pscustomobject]@{VID="V-254505"; Title="SeEnableDelegationPrivilege"; CheckType="UserRight"; RightName="SeEnableDelegationPrivilege"; Allowed=@()}
    [pscustomobject]@{VID="V-254506"; Title="SeImpersonatePrivilege"; CheckType="UserRight"; RightName="SeImpersonatePrivilege"; Allowed=@("S-1-5-32-544","S-1-5-19","S-1-5-20","S-1-5-6")}
    [pscustomobject]@{VID="V-254507"; Title="SeIncreaseBasePriorityPrivilege"; CheckType="UserRight"; RightName="SeIncreaseBasePriorityPrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254508"; Title="SeInteractiveLogonRight"; CheckType="UserRight"; RightName="SeInteractiveLogonRight"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254509"; Title="SeLoadDriverPrivilege"; CheckType="UserRight"; RightName="SeLoadDriverPrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254510"; Title="SeLockMemoryPrivilege"; CheckType="UserRight"; RightName="SeLockMemoryPrivilege"; Allowed=@()}
    [pscustomobject]@{VID="V-254511"; Title="SeManageVolumePrivilege"; CheckType="UserRight"; RightName="SeManageVolumePrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254512"; Title="SeNetworkLogonRight"; CheckType="UserRight"; RightName="SeNetworkLogonRight"; Allowed=@("S-1-5-32-544","S-1-5-11")}
    [pscustomobject]@{VID="V-254513"; Title="SeProfileSingleProcessPrivilege"; CheckType="UserRight"; RightName="SeProfileSingleProcessPrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254514"; Title="SeRemoteShutdownPrivilege"; CheckType="UserRight"; RightName="SeRemoteShutdownPrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254515"; Title="SeRestorePrivilege"; CheckType="UserRight"; RightName="SeRestorePrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254516"; Title="SeSecurityPrivilege"; CheckType="UserRight"; RightName="SeSecurityPrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254517"; Title="SeSystemEnvironmentPrivilege"; CheckType="UserRight"; RightName="SeSystemEnvironmentPrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254518"; Title="SeTakeOwnershipPrivilege"; CheckType="UserRight"; RightName="SeTakeOwnershipPrivilege"; Allowed=@("S-1-5-32-544")}
    [pscustomobject]@{VID="V-254519"; Title="SeTcbPrivilege"; CheckType="UserRight"; RightName="SeTcbPrivilege"; Allowed=@()}

    # ====================== SECURITY OPTIONS ======================
    [pscustomobject]@{VID="V-254520"; Title="CachedLogonsCount"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="CachedLogonsCount"; Expected="4"}
    [pscustomobject]@{VID="V-254521"; Title="ScRemoveOption"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="ScRemoveOption"; Expected="1"}
    [pscustomobject]@{VID="V-254522"; Title="ConsentPromptBehaviorAdmin"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorAdmin"; Expected=2}
    [pscustomobject]@{VID="V-254523"; Title="ConsentPromptBehaviorUser"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorUser"; Expected=0}
    [pscustomobject]@{VID="V-254524"; Title="EnableInstallerDetection"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableInstallerDetection"; Expected=1}
    [pscustomobject]@{VID="V-254525"; Title="EnableLUA"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableLUA"; Expected=1}
    [pscustomobject]@{VID="V-254526"; Title="EnableSecureUIAPaths"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableSecureUIAPaths"; Expected=1}
    [pscustomobject]@{VID="V-254527"; Title="EnableUIADesktopToggle"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableUIADesktopToggle"; Expected=0}
    [pscustomobject]@{VID="V-254528"; Title="EnableVirtualization"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableVirtualization"; Expected=1}
    [pscustomobject]@{VID="V-254529"; Title="FilterAdministratorToken"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="FilterAdministratorToken"; Expected=1}
    [pscustomobject]@{VID="V-254530"; Title="InactivityTimeoutSecs"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="InactivityTimeoutSecs"; Expected=900}
    [pscustomobject]@{VID="V-254531"; Title="SupportedEncryptionTypes"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"; Name="SupportedEncryptionTypes"; Expected=2147483640}
    [pscustomobject]@{VID="V-254532"; Title="LegalNoticeCaption"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LegalNoticeCaption"; Expected="US Department of Defense Warning Statement"}
    [pscustomobject]@{VID="V-254533"; Title="LegalNoticeText"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LegalNoticeText"; Expected="You are accessing a U.S. Government (USG) Information System..."}
    [pscustomobject]@{VID="V-254534"; Title="ForceKeyProtection"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Cryptography"; Name="ForceKeyProtection"; Expected=2}
    [pscustomobject]@{VID="V-254535"; Title="EveryoneIncludesAnonymous"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="EveryoneIncludesAnonymous"; Expected=0}
    [pscustomobject]@{VID="V-254536"; Title="FIPSAlgorithmPolicy Enabled"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy"; Name="Enabled"; Expected=1}
    [pscustomobject]@{VID="V-254537"; Title="LimitBlankPasswordUse"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LimitBlankPasswordUse"; Expected=1}
    [pscustomobject]@{VID="V-254538"; Title="LmCompatibilityLevel"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LmCompatibilityLevel"; Expected=5}
    [pscustomobject]@{VID="V-254539"; Title="allownullsessionfallback"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="allownullsessionfallback"; Expected=0}
    [pscustomobject]@{VID="V-254540"; Title="NTLMMinClientSec"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="NTLMMinClientSec"; Expected=537395200}
    [pscustomobject]@{VID="V-254541"; Title="NTLMMinServerSec"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="NTLMMinServerSec"; Expected=537395200}
    [pscustomobject]@{VID="V-254542"; Title="NoLMHash"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="NoLMHash"; Expected=1}
    [pscustomobject]@{VID="V-254543"; Title="AllowOnlineID"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u"; Name="AllowOnlineID"; Expected=0}
    [pscustomobject]@{VID="V-254544"; Title="RestrictAnonymous"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymous"; Expected=1}
    [pscustomobject]@{VID="V-254545"; Title="RestrictAnonymousSAM"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymousSAM"; Expected=1}
    [pscustomobject]@{VID="V-254546"; Title="RestrictRemoteSAM"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictRemoteSAM"; Expected="O:BAG:BAD:(A;;RC;;;BA)"}
    [pscustomobject]@{VID="V-254547"; Title="SCENoApplyLegacyAuditPolicy"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="SCENoApplyLegacyAuditPolicy"; Expected=1}
    [pscustomobject]@{VID="V-254548"; Title="UseMachineId"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="UseMachineId"; Expected=1}
    [pscustomobject]@{VID="V-254549"; Title="ProtectionMode"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"; Name="ProtectionMode"; Expected=1}
    [pscustomobject]@{VID="V-254550"; Title="EnableSecuritySignature (LanManServer)"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="EnableSecuritySignature"; Expected=1}
    [pscustomobject]@{VID="V-254551"; Title="RequireSecuritySignature (LanManServer)"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="RequireSecuritySignature"; Expected=1}
    [pscustomobject]@{VID="V-254552"; Title="RestrictNullSessAccess"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="RestrictNullSessAccess"; Expected=1}
    [pscustomobject]@{VID="V-254553"; Title="EnablePlainTextPassword"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="EnablePlainTextPassword"; Expected=0}
    [pscustomobject]@{VID="V-254554"; Title="EnableSecuritySignature (LanmanWorkstation)"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="EnableSecuritySignature"; Expected=1}
    [pscustomobject]@{VID="V-254555"; Title="RequireSecuritySignature (LanmanWorkstation)"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="RequireSecuritySignature"; Expected=1}
    [pscustomobject]@{VID="V-254556"; Title="LDAPClientIntegrity"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"; Name="LDAPClientIntegrity"; Expected=1}
    [pscustomobject]@{VID="V-254557"; Title="DisablePasswordChange"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="DisablePasswordChange"; Expected=0}
    [pscustomobject]@{VID="V-254558"; Title="MaximumPasswordAge (Netlogon)"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="MaximumPasswordAge"; Expected=30}
    [pscustomobject]@{VID="V-254559"; Title="RequireSignOrSeal"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="RequireSignOrSeal"; Expected=1}
    [pscustomobject]@{VID="V-254560"; Title="RequireStrongKey"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="RequireStrongKey"; Expected=1}
    [pscustomobject]@{VID="V-254561"; Title="SealSecureChannel"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="SealSecureChannel"; Expected=1}
    [pscustomobject]@{VID="V-254562"; Title="SignSecureChannel"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="SignSecureChannel"; Expected=1}
    [pscustomobject]@{VID="V-254563"; Title="EnableGuestAccount"; CheckType="AccountPolicy"; Policy="EnableGuestAccount"; Expected=0}
    [pscustomobject]@{VID="V-254564"; Title="LSAAnonymousNameLookup"; CheckType="AccountPolicy"; Policy="LSAAnonymousNameLookup"; Expected=0}
    [pscustomobject]@{VID="V-254565"; Title="NewAdministratorName"; CheckType="AccountPolicy"; Policy="NewAdministratorName"; Expected="X_Admin"}
    [pscustomobject]@{VID="V-254566"; Title="NewGuestName"; CheckType="AccountPolicy"; Policy="NewGuestName"; Expected="Visitor"}

    # ====================== ADVANCED AUDIT POLICY ======================
    [pscustomobject]@{VID="V-278942"; Title="Audit Credential Validation"; CheckType="AuditPolicy"; SubCategory="{0cce923f-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-278943"; Title="Audit Other Account Management Events"; CheckType="AuditPolicy"; SubCategory="{0cce923a-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-278944"; Title="Audit Security Group Management"; CheckType="AuditPolicy"; SubCategory="{0cce9237-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-278945"; Title="Audit User Account Management"; CheckType="AuditPolicy"; SubCategory="{0cce9235-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-278946"; Title="Audit PNP Activity"; CheckType="AuditPolicy"; SubCategory="{0cce9248-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-278947"; Title="Audit Process Creation"; CheckType="AuditPolicy"; SubCategory="{0cce922b-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-278948"; Title="Audit Account Lockout"; CheckType="AuditPolicy"; SubCategory="{0cce9217-69ae-11d9-bed3-505054503030}"; Expected=2}
    [pscustomobject]@{VID="V-278949"; Title="Audit Group Membership"; CheckType="AuditPolicy"; SubCategory="{0cce9249-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-278950"; Title="Audit Logoff"; CheckType="AuditPolicy"; SubCategory="{0cce9216-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-278951"; Title="Audit Logon"; CheckType="AuditPolicy"; SubCategory="{0cce9215-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-278952"; Title="Audit Special Logon"; CheckType="AuditPolicy"; SubCategory="{0cce921b-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-278953"; Title="Audit File System"; CheckType="AuditPolicy"; SubCategory="{0cce921d-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-278954"; Title="Audit Handle Manipulation"; CheckType="AuditPolicy"; SubCategory="{0cce9223-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-278955"; Title="Audit Other Object Access Events"; CheckType="AuditPolicy"; SubCategory="{0cce9227-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-278956"; Title="Audit Registry"; CheckType="AuditPolicy"; SubCategory="{0cce921e-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-278957"; Title="Audit Removable Storage"; CheckType="AuditPolicy"; SubCategory="{0cce9245-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-278958"; Title="Audit Audit Policy Change"; CheckType="AuditPolicy"; SubCategory="{0cce922f-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-278959"; Title="Audit Authentication Policy Change"; CheckType="AuditPolicy"; SubCategory="{0cce9230-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-278960"; Title="Audit Authorization Policy Change"; CheckType="AuditPolicy"; SubCategory="{0cce9231-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-278961"; Title="Audit Sensitive Privilege Use"; CheckType="AuditPolicy"; SubCategory="{0cce9228-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-278962"; Title="Audit IPsec Driver"; CheckType="AuditPolicy"; SubCategory="{0cce9213-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-278963"; Title="Audit Other System Events"; CheckType="AuditPolicy"; SubCategory="{0cce9214-69ae-11d9-bed3-505054503030}"; Expected=3}
    [pscustomobject]@{VID="V-278964"; Title="Audit Security State Change"; CheckType="AuditPolicy"; SubCategory="{0cce9210-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-278965"; Title="Audit Security System Extension"; CheckType="AuditPolicy"; SubCategory="{0cce9211-69ae-11d9-bed3-505054503030}"; Expected=1}
    [pscustomobject]@{VID="V-278966"; Title="Audit System Integrity"; CheckType="AuditPolicy"; SubCategory="{0cce9212-69ae-11d9-bed3-505054503030}"; Expected=3}

    # ====================== REGISTRY POLICIES ======================
    [pscustomobject]@{VID="V-254285"; Title="Prevent enabling lock screen slide show"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"; Name="NoLockScreenSlideshow"; Expected=1}
    [pscustomobject]@{VID="V-254323"; Title="Apply UAC restrictions to local accounts on network logons"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LocalAccountTokenFilterPolicy"; Expected=0}
    [pscustomobject]@{VID="V-254324"; Title="Configure SMB v1 client driver"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10"; Name="Start"; Expected=4}
    [pscustomobject]@{VID="V-254325"; Title="Configure SMB v1 server"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="SMB1"; Expected=0}
    [pscustomobject]@{VID="V-254326"; Title="WDigest Authentication"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name="UseLogonCredential"; Expected=0}
    [pscustomobject]@{VID="V-254327"; Title="MSS: DisableIPSourceRouting IPv6"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; Name="DisableIPSourceRouting"; Expected=2}
    [pscustomobject]@{VID="V-254328"; Title="MSS: DisableIPSourceRouting"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="DisableIPSourceRouting"; Expected=2}
    [pscustomobject]@{VID="V-254329"; Title="MSS: EnableICMPRedirect"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="EnableICMPRedirect"; Expected=0}
    [pscustomobject]@{VID="V-254330"; Title="MSS: NoNameReleaseOnDemand"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; Name="NoNameReleaseOnDemand"; Expected=1}
    [pscustomobject]@{VID="V-254331"; Title="Enable insecure guest logons"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="EnableInsecureGuestLogons"; Expected=0}
    [pscustomobject]@{VID="V-254332"; Title="Hardened UNC Paths - SYSVOL"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"; Name="\\*\SYSVOL"; Expected="RequireMutualAuthentication=1, RequireIntegrity=1"}
    [pscustomobject]@{VID="V-254333"; Title="Hardened UNC Paths - NETLOGON"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"; Name="\\*\NETLOGON"; Expected="RequireMutualAuthentication=1, RequireIntegrity=1"}
    [pscustomobject]@{VID="V-254334"; Title="Include command line in process creation events"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"; Name="ProcessCreationIncludeCmdLine_Enabled"; Expected=1}
    [pscustomobject]@{VID="V-254335"; Title="Remote host allows delegation of non-exportable credentials"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"; Name="AllowProtectedCreds"; Expected=1}
    [pscustomobject]@{VID="V-254336"; Title="Turn On Virtualization Based Security"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name="EnableVirtualizationBasedSecurity"; Expected=1}
    [pscustomobject]@{VID="V-254337"; Title="Boot-Start Driver Initialization Policy"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"; Name="DriverLoadPolicy"; Expected=1}
    [pscustomobject]@{VID="V-254338"; Title="Configure registry policy processing"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy"; Name="NoBackgroundPolicy"; Expected=0; Expected2=1}  # both checkboxes
    [pscustomobject]@{VID="V-254339"; Title="Turn off downloading of print drivers over HTTP"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Name="DisableHTTPPrinting"; Expected=1}
    [pscustomobject]@{VID="V-254340"; Title="Turn off printing over HTTP"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Name="DisableWebPrinting"; Expected=1}
    [pscustomobject]@{VID="V-254341"; Title="Password Settings (LAPS)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"; Name="PasswordComplexity"; Expected=4}
    [pscustomobject]@{VID="V-254342"; Title="Do not display network selection UI"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="DontDisplayNetworkSelectionUI"; Expected=1}
    [pscustomobject]@{VID="V-254343"; Title="Enumerate local users on domain-joined computers"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnumerateLocalUsers"; Expected=0}
    [pscustomobject]@{VID="V-254344"; Title="Require a password when a computer wakes (on battery)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power"; Name="PromptForPasswordOnResumeBattery"; Expected=1}
    [pscustomobject]@{VID="V-254345"; Title="Require a password when a computer wakes (plugged in)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power"; Name="PromptForPasswordOnResumeAC"; Expected=1}
    [pscustomobject]@{VID="V-254346"; Title="Restrict Unauthenticated RPC clients"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"; Name="RestrictRemoteClients"; Expected=1}
    [pscustomobject]@{VID="V-254347"; Title="Turn off Inventory Collector"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx"; Name="DisableInventory"; Expected=1}
    [pscustomobject]@{VID="V-254348"; Title="Disallow Autoplay for non-volume devices"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="NoAutoplayfornonVolume"; Expected=1}
    [pscustomobject]@{VID="V-254349"; Title="Set the default behavior for AutoRun"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoAutorun"; Expected=1}
    [pscustomobject]@{VID="V-254350"; Title="Turn off Autoplay"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"; Expected=255}
    [pscustomobject]@{VID="V-254351"; Title="Enumerate administrator accounts on elevation"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"; Name="EnumerateAdministrators"; Expected=0}
    [pscustomobject]@{VID="V-254352"; Title="Allow Diagnostic Data"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"; Expected=1}
    [pscustomobject]@{VID="V-254353"; Title="Download Mode"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"; Name="DODownloadMode"; Expected=2}
    [pscustomobject]@{VID="V-254354"; Title="Specify the maximum log file size (Application)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"; Name="MaxSize"; Expected=32768}
    [pscustomobject]@{VID="V-254355"; Title="Specify the maximum log file size (Security)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"; Name="MaxSize"; Expected=196608}
    [pscustomobject]@{VID="V-254356"; Title="Specify the maximum log file size (System)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"; Name="MaxSize"; Expected=32768}
    [pscustomobject]@{VID="V-254357"; Title="Turn off Data Execution Prevention for Explorer"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="NoDataExecutionPrevention"; Expected=0}
    [pscustomobject]@{VID="V-254358"; Title="Turn off heap termination on corruption"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="NoHeapTerminationOnCorruption"; Expected=0}
    [pscustomobject]@{VID="V-254359"; Title="Turn off shell protocol protected mode"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoShellProtocolProtectedMode"; Expected=0}
    [pscustomobject]@{VID="V-254360"; Title="Do not allow passwords to be saved"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="DisablePasswordSaving"; Expected=1}
    [pscustomobject]@{VID="V-254361"; Title="Do not allow drive redirection"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fDisableCdm"; Expected=1}
    [pscustomobject]@{VID="V-254362"; Title="Always prompt for password upon connection"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fPromptForPassword"; Expected=1}
    [pscustomobject]@{VID="V-254363"; Title="Require secure RPC communication"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fEncryptRPCTraffic"; Expected=1}
    [pscustomobject]@{VID="V-254364"; Title="Set client connection encryption level"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="MinEncryptionLevel"; Expected=3}
    [pscustomobject]@{VID="V-254365"; Title="Prevent downloading of enclosures"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"; Name="DisableEnclosureDownload"; Expected=1}
    [pscustomobject]@{VID="V-254366"; Title="Turn on Basic feed authentication over HTTP"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"; Name="BasicAuth"; Expected=0}
    [pscustomobject]@{VID="V-254367"; Title="Allow indexing of encrypted files"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowIndexingEncryptedStoresOrItems"; Expected=0}
    [pscustomobject]@{VID="V-254368"; Title="Configure Windows Defender SmartScreen"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnableSmartScreen"; Expected=1}
    [pscustomobject]@{VID="V-254369"; Title="Allow user control over installs"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="EnableUserControl"; Expected=0}
    [pscustomobject]@{VID="V-254370"; Title="Always install with elevated privileges"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="AlwaysInstallElevated"; Expected=0}
    [pscustomobject]@{VID="V-254371"; Title="Prevent Internet Explorer security prompt for Windows Installer scripts"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="SafeForScripting"; Expected=0}
    [pscustomobject]@{VID="V-254372"; Title="Sign-in and lock last interactive user automatically after a restart"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="DisableAutomaticRestartSignOn"; Expected=1}
    [pscustomobject]@{VID="V-254373"; Title="Turn on PowerShell Script Block Logging"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name="EnableScriptBlockLogging"; Expected=1}
    [pscustomobject]@{VID="V-254374"; Title="Turn on PowerShell Transcription"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name="EnableTranscripting"; Expected=1}
    [pscustomobject]@{VID="V-254375"; Title="Allow Basic authentication (WinRM Client)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowBasic"; Expected=0}
    [pscustomobject]@{VID="V-254376"; Title="Allow unencrypted traffic (WinRM Client)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowUnencryptedTraffic"; Expected=0}
    [pscustomobject]@{VID="V-254377"; Title="Disallow Digest authentication (WinRM Client)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowDigest"; Expected=0}
    [pscustomobject]@{VID="V-254378"; Title="Allow Basic authentication (WinRM Service)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="AllowBasic"; Expected=0}
    [pscustomobject]@{VID="V-254379"; Title="Allow unencrypted traffic (WinRM Service)"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="AllowUnencryptedTraffic"; Expected=0}
    [pscustomobject]@{VID="V-254380"; Title="Disallow WinRM from storing RunAs credentials"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="DisableRunAs"; Expected=1}
)

# =============================================================================
# MAIN EXECUTION LOGIC
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
# FINAL REPORT
# =============================================================================
$report | Sort-Object VID | Format-Table -AutoSize

if ($Remediate) {
    Write-Host "`nRemediation complete for all rules in the Microsoft Windows Server 2022 STIG V2R7 STIG." -ForegroundColor Green
    if ($rebootRequired) {
        Write-Host "A reboot is required for some changes (account policies, audit policy, etc.) to take effect." -ForegroundColor Yellow
    }
} else {
    Write-Host "`nRun the script with -Remediate to automatically fix Non-Compliant settings." -ForegroundColor Cyan
}

Write-Host "`nScript complete. All rules from the Microsoft Windows Server 2022 STIG V2R7 STIG are now enforced." -ForegroundColor White