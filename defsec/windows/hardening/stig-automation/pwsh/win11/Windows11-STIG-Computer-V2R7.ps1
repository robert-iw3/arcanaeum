<#
.SYNOPSIS
    PowerShell automation for the Microsoft Windows 11 STIG V2R7
    (Release 7, Benchmark Date: 01 Apr 2026) - Computer (machine) settings.

.DESCRIPTION
    Same engine/methodology as the Server 2022/2025 scripts (a rules array driven by a
    switch on CheckType), but every rule is tagged with a -Section (what TYPE of control)
    and a -Severity (CRITICALITY), so you can apply a slice of the baseline instead of the
    whole thing. Defaults are tuned for hardening a normal user's laptop: domain-only,
    DoD-only and overly-restrictive controls are shipped but parked in opt-in sections.

    Purely manual / firmware / disk controls (TPM, UEFI, Secure Boot, BitLocker, AppLocker,
    DoD root certificates, NTFS/share/registry ACLs, IE removal) are intentionally NOT
    automated here - they cannot be set with registry/secedit/auditpol.

.PARAMETER Remediate
    Apply the expected value for every Non-Compliant rule in scope. Without it, the script
    only reports (check-only / audit mode).

.PARAMETER Section
    Which control TYPES to evaluate. Default is the "laptop" set:
        AccountPolicy, UserRights, AuditPolicy, SecurityOptions, ComputerConfig, System
    Opt-in (not in the default): Domain, DoD, Restrictive
    Use -Section All to evaluate everything.

.PARAMETER Severity
    Which CRITICALITY levels to evaluate. Default: High, Medium, Low.
    Example: -Severity High,Medium  (skip the low-impact cosmetic items)

.PARAMETER StigId
    Target one or more specific STIG IDs (e.g. WN11-SO-000195) instead of a Section/Severity
    slice. When supplied, Section and Severity filters are ignored - only the listed ID(s) are
    evaluated/remediated, even if they belong to an opt-in section (Domain/DoD/Restrictive).
    Unknown IDs are reported with a warning and otherwise skipped.

.PARAMETER RulesFile
    Path to an INI file listing one STIGID per line that toggles which rules are in scope -
    comment out a line (prefix with ; or #) to exclude that control. Defaults to
    "Windows11-STIG-Computer-V2R7.ini" next to this script, if present. Ignored when -StigId
    is supplied. See that file for the format.

.PARAMETER IgnoreRulesFile
    Skip the INI include/exclude file even if it exists, and evaluate every rule that the
    Section/Severity filters allow.

.PARAMETER ListRules
    Print the in-scope rules (after Section/Severity/StigId/RulesFile filtering) and exit.
    No changes made.

.EXAMPLE
    # Report only
    .\Windows11-STIG-Computer-V2R7.ps1

.EXAMPLE
    # Apply only the high-severity items across all default sections
    .\Windows11-STIG-Computer-V2R7.ps1 -Severity High -Remediate

.EXAMPLE
    # Apply just the audit policy and user-rights sections
    .\Windows11-STIG-Computer-V2R7.ps1 -Section AuditPolicy,UserRights -Remediate

.EXAMPLE
    # Everything, including the domain/DoD/restrictive extras
    .\Windows11-STIG-Computer-V2R7.ps1 -Section All -Remediate

.EXAMPLE
    # Apply just one specific control
    .\Windows11-STIG-Computer-V2R7.ps1 -StigId WN11-SO-000195 -Remediate

.EXAMPLE
    # Check (no -Remediate) a handful of specific controls
    .\Windows11-STIG-Computer-V2R7.ps1 -StigId WN11-SO-000195,WN11-SO-000205

.NOTES
    Author: Robert Weber
    Run from an elevated PowerShell session.
#>

[CmdletBinding()]
param(
    [switch]$Remediate,

    [ValidateSet('All','AccountPolicy','UserRights','AuditPolicy','SecurityOptions',
                 'ComputerConfig','System','Domain','DoD','Restrictive')]
    [string[]]$Section = @('AccountPolicy','UserRights','AuditPolicy','SecurityOptions','ComputerConfig','System'),

    [ValidateSet('High','Medium','Low')]
    [string[]]$Severity = @('High','Medium','Low'),

    # One or more specific STIG IDs. Overrides Section/Severity scoping when supplied.
    [string[]]$StigId,

    # INI include/exclude list. Defaults to <ScriptName>.ini next to this script when present.
    [string]$RulesFile,
    [switch]$IgnoreRulesFile,

    [switch]$ListRules,

    # Return the report objects (and stay quiet on the host) so an orchestrator can consume them.
    [switch]$PassThru
)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
function Test-DomainJoined { (Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain }

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
    $line = ($export -split "`r`n") | Where-Object { $_ -match "^\s*$RightName\s*=" }
    if ($line) {
        (($line -split '=', 2)[1].Trim() -split ',') |
            ForEach-Object { $_.Trim().TrimStart('*') } |
            Where-Object { $_ }
    } else { @() }
}

function Set-UserRight {
    param([string]$RightName, [string[]]$AllowedSIDs)
    $sidString = ($AllowedSIDs | ForEach-Object { "*$_" }) -join ','
    $temp = [System.IO.Path]::GetTempFileName()
@"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
$RightName = $sidString
"@ | Out-File $temp -Encoding ASCII
    secedit /configure /db "$env:windir\security\database\secedit.sdb" /cfg $temp /areas USER_RIGHTS /quiet | Out-Null
    Remove-Item $temp -Force -ErrorAction SilentlyContinue
}

function Get-AuditSetting {
    param([string]$Guid)
    # Setting Value column: 0=None 1=Success 2=Failure 3=Success+Failure
    $line = (auditpol /get /subcategory:"$Guid" /r) | Where-Object { $_ -like "*$Guid*" }
    if ($line) { (($line | Select-Object -First 1) -split ',')[6].Trim() } else { $null }
}

function Set-AuditSetting {
    param([string]$Guid, [int]$Expected)
    switch ($Expected) {
        1 { auditpol /set /subcategory:"$Guid" /success:enable  /failure:disable | Out-Null }
        2 { auditpol /set /subcategory:"$Guid" /success:disable /failure:enable  | Out-Null }
        3 { auditpol /set /subcategory:"$Guid" /success:enable  /failure:enable  | Out-Null }
    }
}

# Reads an INI rules file (see Windows11-STIG-Computer-V2R7.ini) and returns the STIGIDs
# that are still active, i.e. NOT commented out with a leading ';' or '#'.
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
#   Section : control type (filter with -Section)
#   Severity: criticality   (filter with -Severity)
# =============================================================================
$rules = @(

    # ======================= ACCOUNT POLICIES (WN11-AC / WN11-SO) =======================
    [pscustomobject]@{STIGID="WN11-AC-000005"; Title="Account lockout duration >= 15 min";     Section="AccountPolicy"; Severity="Medium"; CheckType="AccountPolicy"; Policy="LockoutDuration";       Expected=15},
    [pscustomobject]@{STIGID="WN11-AC-000010"; Title="Bad logon attempts <= 3";                Section="AccountPolicy"; Severity="Medium"; CheckType="AccountPolicy"; Policy="LockoutBadCount";       Expected=3},
    [pscustomobject]@{STIGID="WN11-AC-000015"; Title="Reset bad logon counter = 15 min";       Section="AccountPolicy"; Severity="Medium"; CheckType="AccountPolicy"; Policy="ResetLockoutCount";     Expected=15},
    [pscustomobject]@{STIGID="WN11-AC-000020"; Title="Password history = 24";                  Section="AccountPolicy"; Severity="Medium"; CheckType="AccountPolicy"; Policy="PasswordHistorySize";   Expected=24},
    [pscustomobject]@{STIGID="WN11-AC-000025"; Title="Maximum password age = 60 days";         Section="AccountPolicy"; Severity="Medium"; CheckType="AccountPolicy"; Policy="MaximumPasswordAge";    Expected=60},
    [pscustomobject]@{STIGID="WN11-AC-000030"; Title="Minimum password age >= 1 day";          Section="AccountPolicy"; Severity="Medium"; CheckType="AccountPolicy"; Policy="MinimumPasswordAge";    Expected=1},
    [pscustomobject]@{STIGID="WN11-AC-000035"; Title="Minimum password length = 14";           Section="AccountPolicy"; Severity="Medium"; CheckType="AccountPolicy"; Policy="MinimumPasswordLength"; Expected=14},
    [pscustomobject]@{STIGID="WN11-AC-000040"; Title="Password complexity enabled";            Section="AccountPolicy"; Severity="Medium"; CheckType="AccountPolicy"; Policy="PasswordComplexity";    Expected=1},
    [pscustomobject]@{STIGID="WN11-AC-000045"; Title="Reversible encryption disabled";         Section="AccountPolicy"; Severity="High";   CheckType="AccountPolicy"; Policy="ClearTextPassword";     Expected=0},
    [pscustomobject]@{STIGID="WN11-SO-000010"; Title="Built-in Guest account disabled";        Section="AccountPolicy"; Severity="Medium"; CheckType="AccountPolicy"; Policy="EnableGuestAccount";    Expected=0},

    # ======================= USER RIGHTS ASSIGNMENTS (WN11-UR) =======================
    [pscustomobject]@{STIGID="WN11-UR-000005"; Title="Access Credential Manager as trusted caller = none"; Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeTrustedCredManAccessPrivilege"; Allowed=@()},
    [pscustomobject]@{STIGID="WN11-UR-000010"; Title="Access this computer from the network";              Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeNetworkLogonRight";             Allowed=@("S-1-5-32-544","S-1-5-32-555")},
    [pscustomobject]@{STIGID="WN11-UR-000015"; Title="Act as part of the operating system = none";         Section="UserRights"; Severity="High";   CheckType="UserRight"; RightName="SeTcbPrivilege";                  Allowed=@()},
    [pscustomobject]@{STIGID="WN11-UR-000025"; Title="Allow log on locally = Admins,Users";                Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeInteractiveLogonRight";         Allowed=@("S-1-5-32-544","S-1-5-32-545")},
    [pscustomobject]@{STIGID="WN11-UR-000030"; Title="Back up files and directories = Admins";             Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeBackupPrivilege";               Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{STIGID="WN11-UR-000035"; Title="Change the system time = Admins,Local Service";      Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeSystemtimePrivilege";           Allowed=@("S-1-5-32-544","S-1-5-19")},
    [pscustomobject]@{STIGID="WN11-UR-000040"; Title="Create a pagefile = Admins";                         Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeCreatePagefilePrivilege";       Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{STIGID="WN11-UR-000045"; Title="Create a token object = none";                       Section="UserRights"; Severity="High";   CheckType="UserRight"; RightName="SeCreateTokenPrivilege";          Allowed=@()},
    [pscustomobject]@{STIGID="WN11-UR-000050"; Title="Create global objects = Admins,Service accounts";    Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeCreateGlobalPrivilege";         Allowed=@("S-1-5-32-544","S-1-5-6","S-1-5-19","S-1-5-20")},
    [pscustomobject]@{STIGID="WN11-UR-000055"; Title="Create permanent shared objects = none";             Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeCreatePermanentPrivilege";      Allowed=@()},
    [pscustomobject]@{STIGID="WN11-UR-000060"; Title="Create symbolic links = Admins";                     Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeCreateSymbolicLinkPrivilege";   Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{STIGID="WN11-UR-000065"; Title="Debug programs = Admins";                            Section="UserRights"; Severity="High";   CheckType="UserRight"; RightName="SeDebugPrivilege";                Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{STIGID="WN11-UR-000070"; Title="Deny access from the network = Guests";              Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeDenyNetworkLogonRight";         Allowed=@("S-1-5-32-546")},
    [pscustomobject]@{STIGID="WN11-UR-000085"; Title="Deny log on locally = Guests";                       Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeDenyInteractiveLogonRight";     Allowed=@("S-1-5-32-546")},
    [pscustomobject]@{STIGID="WN11-UR-000090"; Title="Deny log on through RDP = Guests";                   Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeDenyRemoteInteractiveLogonRight"; Allowed=@("S-1-5-32-546")},
    [pscustomobject]@{STIGID="WN11-UR-000095"; Title="Enable accounts to be trusted for delegation = none";Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeEnableDelegationPrivilege";     Allowed=@()},
    [pscustomobject]@{STIGID="WN11-UR-000100"; Title="Force shutdown from a remote system = Admins";       Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeRemoteShutdownPrivilege";       Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{STIGID="WN11-UR-000110"; Title="Impersonate a client = Admins,Service accounts";     Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeImpersonatePrivilege";          Allowed=@("S-1-5-32-544","S-1-5-6","S-1-5-19","S-1-5-20")},
    [pscustomobject]@{STIGID="WN11-UR-000120"; Title="Load and unload device drivers = Admins";            Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeLoadDriverPrivilege";           Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{STIGID="WN11-UR-000125"; Title="Lock pages in memory = none";                        Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeLockMemoryPrivilege";           Allowed=@()},
    [pscustomobject]@{STIGID="WN11-UR-000130"; Title="Manage auditing and security log = Admins";          Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeSecurityPrivilege";             Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{STIGID="WN11-UR-000140"; Title="Modify firmware environment values = Admins";        Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeSystemEnvironmentPrivilege";    Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{STIGID="WN11-UR-000145"; Title="Perform volume maintenance tasks = Admins";          Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeManageVolumePrivilege";         Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{STIGID="WN11-UR-000150"; Title="Profile single process = Admins";                    Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeProfileSingleProcessPrivilege"; Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{STIGID="WN11-UR-000160"; Title="Restore files and directories = Admins";             Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeRestorePrivilege";              Allowed=@("S-1-5-32-544")},
    [pscustomobject]@{STIGID="WN11-UR-000165"; Title="Take ownership of files or objects = Admins";        Section="UserRights"; Severity="Medium"; CheckType="UserRight"; RightName="SeTakeOwnershipPrivilege";        Allowed=@("S-1-5-32-544")},

    # ======================= ADVANCED AUDIT POLICY (WN11-AU) =======================
    [pscustomobject]@{STIGID="WN11-AU-000005/010"; Title="Audit Credential Validation (S/F)";          Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce923f-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{STIGID="WN11-AU-000030";     Title="Audit Security Group Management (S)";        Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9237-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{STIGID="WN11-AU-000035/040"; Title="Audit User Account Management (S/F)";        Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9235-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{STIGID="WN11-AU-000045";     Title="Audit PNP Activity (S)";                     Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9248-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{STIGID="WN11-AU-000050/585"; Title="Audit Process Creation (S/F)";               Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce922b-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{STIGID="WN11-AU-000054";     Title="Audit Account Lockout (F)";                  Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9217-69ae-11d9-bed3-505054503030}"; Expected=2},
    [pscustomobject]@{STIGID="WN11-AU-000060";     Title="Audit Group Membership (S)";                 Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9249-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{STIGID="WN11-AU-000065";     Title="Audit Logoff (S)";                           Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9216-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{STIGID="WN11-AU-000070/075"; Title="Audit Logon (S/F)";                          Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9215-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{STIGID="WN11-AU-000080";     Title="Audit Special Logon (S)";                    Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce921b-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{STIGID="WN11-AU-000081/082"; Title="Audit File Share (S/F)";                     Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9224-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{STIGID="WN11-AU-000083/084"; Title="Audit Other Object Access Events (S/F)";     Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9227-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{STIGID="WN11-AU-000085/090"; Title="Audit Removable Storage (S/F)";              Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9245-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{STIGID="WN11-AU-000100";     Title="Audit Audit Policy Change (S)";              Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce922f-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{STIGID="WN11-AU-000105";     Title="Audit Authentication Policy Change (S)";     Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9230-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{STIGID="WN11-AU-000107";     Title="Audit Authorization Policy Change (S)";      Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9231-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{STIGID="WN11-AU-000110/115"; Title="Audit Sensitive Privilege Use (S/F)";        Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9228-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{STIGID="WN11-AU-000120";     Title="Audit IPsec Driver (F)";                     Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9213-69ae-11d9-bed3-505054503030}"; Expected=2},
    [pscustomobject]@{STIGID="WN11-AU-000130/135"; Title="Audit Other System Events (S/F)";            Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9214-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{STIGID="WN11-AU-000140";     Title="Audit Security State Change (S)";            Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9210-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{STIGID="WN11-AU-000150";     Title="Audit Security System Extension (S)";        Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9211-69ae-11d9-bed3-505054503030}"; Expected=1},
    [pscustomobject]@{STIGID="WN11-AU-000155/160"; Title="Audit System Integrity (S/F)";               Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9212-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{STIGID="WN11-AU-000555";     Title="Audit Other Policy Change Events (F)";       Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9234-69ae-11d9-bed3-505054503030}"; Expected=2},
    [pscustomobject]@{STIGID="WN11-AU-000560/565"; Title="Audit Other Logon/Logoff Events (S/F)";      Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce921c-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{STIGID="WN11-AU-000570";     Title="Audit Detailed File Share (F)";              Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9244-69ae-11d9-bed3-505054503030}"; Expected=2},
    [pscustomobject]@{STIGID="WN11-AU-000575/580"; Title="Audit MPSSVC Rule-Level Policy Change (S/F)";Section="AuditPolicy";Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9232-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{STIGID="WN11-AU-000581/582"; Title="Audit File System (S/F)";                    Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce921d-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{STIGID="WN11-AU-000583/584"; Title="Audit Handle Manipulation (S/F)";            Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce9223-69ae-11d9-bed3-505054503030}"; Expected=3},
    [pscustomobject]@{STIGID="WN11-AU-000586/589"; Title="Audit Registry (S/F)";                       Section="AuditPolicy"; Severity="Medium"; CheckType="AuditPolicy"; Guid="{0cce921e-69ae-11d9-bed3-505054503030}"; Expected=3},

    # ======================= SECURITY OPTIONS (WN11-SO, registry) =======================
    [pscustomobject]@{STIGID="WN11-SO-000015"; Title="Limit blank-password use to console only";   Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LimitBlankPasswordUse"; Expected=1},
    [pscustomobject]@{STIGID="WN11-SO-000030"; Title="Force audit policy subcategory settings";    Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="SCENoApplyLegacyAuditPolicy"; Expected=1},
    [pscustomobject]@{STIGID="WN11-SO-000035"; Title="Outgoing secure channel encrypt/sign";       Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="RequireSignOrSeal"; Expected=1},
    [pscustomobject]@{STIGID="WN11-SO-000040"; Title="Outgoing secure channel encrypted";          Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="SealSecureChannel"; Expected=1},
    [pscustomobject]@{STIGID="WN11-SO-000045"; Title="Outgoing secure channel signed";             Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="SignSecureChannel"; Expected=1},
    [pscustomobject]@{STIGID="WN11-SO-000050"; Title="Computer account password changes allowed";  Section="SecurityOptions"; Severity="Low";    CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="DisablePasswordChange"; Expected=0},
    [pscustomobject]@{STIGID="WN11-SO-000055"; Title="Max machine account password age = 30";      Section="SecurityOptions"; Severity="Low";    CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="MaximumPasswordAge"; Expected=30},
    [pscustomobject]@{STIGID="WN11-SO-000060"; Title="Require strong session key";                 Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="RequireStrongKey"; Expected=1},
    [pscustomobject]@{STIGID="WN11-SO-000070"; Title="Machine inactivity limit = 900 sec";         Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="InactivityTimeoutSecs"; Expected=900},
    [pscustomobject]@{STIGID="WN11-SO-000085"; Title="Cached logons <= 10";                        Section="SecurityOptions"; Severity="Low";    CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="CachedLogonsCount"; Expected="10"; Type="String"},
    [pscustomobject]@{STIGID="WN11-SO-000095"; Title="Smart card removal = lock workstation";      Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="SCRemoveOption"; Expected="1"; Type="String"},
    [pscustomobject]@{STIGID="WN11-SO-000100"; Title="SMB client always sign";                     Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="RequireSecuritySignature"; Expected=1},
    [pscustomobject]@{STIGID="WN11-SO-000110"; Title="No unencrypted password to SMB servers";     Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="EnablePlainTextPassword"; Expected=0},
    [pscustomobject]@{STIGID="WN11-SO-000120"; Title="SMB server always sign";                     Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="RequireSecuritySignature"; Expected=1},
    [pscustomobject]@{STIGID="WN11-SO-000145"; Title="No anonymous enumeration of SAM accounts";   Section="SecurityOptions"; Severity="High";   CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymousSAM"; Expected=1},
    [pscustomobject]@{STIGID="WN11-SO-000150"; Title="No anonymous enumeration of shares";         Section="SecurityOptions"; Severity="High";   CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymous"; Expected=1},
    [pscustomobject]@{STIGID="WN11-SO-000160"; Title="Everyone perms not applied to anonymous";    Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="EveryoneIncludesAnonymous"; Expected=0},
    [pscustomobject]@{STIGID="WN11-SO-000165"; Title="Restrict anonymous Named Pipes/Shares";      Section="SecurityOptions"; Severity="High";   CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="RestrictNullSessAccess"; Expected=1},
    [pscustomobject]@{STIGID="WN11-SO-000167"; Title="Restrict remote SAM calls to Admins";        Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictRemoteSAM"; Expected="O:BAG:BAD:(A;;RC;;;BA)"; Type="String"},
    [pscustomobject]@{STIGID="WN11-SO-000180"; Title="NTLM no Null session fallback";              Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="allownullsessionfallback"; Expected=0},
    [pscustomobject]@{STIGID="WN11-SO-000185"; Title="PKU2U online identities prevented";          Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u"; Name="AllowOnlineID"; Expected=0},
    [pscustomobject]@{STIGID="WN11-SO-000190"; Title="Kerberos: no DES/RC4 (AES only)";            Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"; Name="SupportedEncryptionTypes"; Expected=2147483640},
    [pscustomobject]@{STIGID="WN11-SO-000195"; Title="Do not store LAN Manager hash";              Section="SecurityOptions"; Severity="High";   CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="NoLMHash"; Expected=1},
    [pscustomobject]@{STIGID="WN11-SO-000205"; Title="LAN Manager auth = NTLMv2 only";             Section="SecurityOptions"; Severity="High";   CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LmCompatibilityLevel"; Expected=5},
    [pscustomobject]@{STIGID="WN11-SO-000210"; Title="LDAP client signing >= Negotiate";           Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"; Name="LDAPClientIntegrity"; Expected=1},
    [pscustomobject]@{STIGID="WN11-SO-000215"; Title="NTLM SSP client min session security";       Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="NTLMMinClientSec"; Expected=537395200},
    [pscustomobject]@{STIGID="WN11-SO-000220"; Title="NTLM SSP server min session security";       Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="NTLMMinServerSec"; Expected=537395200},
    [pscustomobject]@{STIGID="WN11-SO-000240"; Title="Strengthen default permissions of objects";  Section="SecurityOptions"; Severity="Low";    CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"; Name="ProtectionMode"; Expected=1},
    [pscustomobject]@{STIGID="WN11-SO-000245"; Title="UAC: Admin Approval Mode for built-in Admin";Section="SecurityOptions";Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="FilterAdministratorToken"; Expected=1},
    [pscustomobject]@{STIGID="WN11-SO-000250"; Title="UAC: prompt admins on secure desktop";       Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorAdmin"; Expected=2},
    [pscustomobject]@{STIGID="WN11-SO-000255"; Title="UAC: deny elevation for standard users";     Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorUser"; Expected=0},
    [pscustomobject]@{STIGID="WN11-SO-000260"; Title="UAC: detect installs and prompt";            Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableInstallerDetection"; Expected=1},
    [pscustomobject]@{STIGID="WN11-SO-000265"; Title="UAC: only elevate UIAccess in secure paths"; Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableSecureUIAPaths"; Expected=1},
    [pscustomobject]@{STIGID="WN11-SO-000270"; Title="UAC: run all admins in Admin Approval Mode"; Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableLUA"; Expected=1},
    [pscustomobject]@{STIGID="WN11-SO-000275"; Title="UAC: virtualize write failures";             Section="SecurityOptions"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableVirtualization"; Expected=1},

    # ======================= COMPUTER CONFIGURATION (WN11-CC / WN11-EP, registry) =======================
    [pscustomobject]@{STIGID="WN11-CC-000005"; Title="Disable lock-screen camera";                 Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"; Name="NoLockScreenCamera"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000010"; Title="Disable lock-screen slide show";             Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"; Name="NoLockScreenSlideshow"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000020"; Title="IPv6 source routing highest protection";     Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; Name="DisableIpSourceRouting"; Expected=2},
    [pscustomobject]@{STIGID="WN11-CC-000025"; Title="IPv4 source routing highest protection";     Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="DisableIPSourceRouting"; Expected=2},
    [pscustomobject]@{STIGID="WN11-CC-000030"; Title="No ICMP redirect override of OSPF";          Section="ComputerConfig"; Severity="Low";    CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="EnableICMPRedirect"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000035"; Title="Ignore NetBIOS name release (non-WINS)";     Section="ComputerConfig"; Severity="Low";    CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters"; Name="NoNameReleaseOnDemand"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000037"; Title="UAC restrictions to local accts on network"; Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LocalAccountTokenFilterPolicy"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000038"; Title="WDigest Authentication disabled";            Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest"; Name="UseLogonCredential"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000039a"; Title="Remove RunAsUser (bat)";                    Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Classes\batfile\shell\runasuser"; Name="SuppressionPolicy"; Expected=4096},
    [pscustomobject]@{STIGID="WN11-CC-000039b"; Title="Remove RunAsUser (cmd)";                    Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser"; Name="SuppressionPolicy"; Expected=4096},
    [pscustomobject]@{STIGID="WN11-CC-000039c"; Title="Remove RunAsUser (exe)";                    Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Classes\exefile\shell\runasuser"; Name="SuppressionPolicy"; Expected=4096},
    [pscustomobject]@{STIGID="WN11-CC-000039d"; Title="Remove RunAsUser (msc)";                    Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser"; Name="SuppressionPolicy"; Expected=4096},
    [pscustomobject]@{STIGID="WN11-CC-000040"; Title="Insecure SMB guest logons disabled";         Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"; Name="AllowInsecureGuestAuth"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000044"; Title="Internet Connection Sharing disabled";       Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"; Name="NC_ShowSharedAccessUI"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000052"; Title="Prioritize ECC curves (P384,P256)";          Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"; Name="EccCurves"; Expected=@("NistP384","NistP256"); Type="MultiString"},
    [pscustomobject]@{STIGID="WN11-CC-000055"; Title="Minimize simultaneous connections = 3";      Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"; Name="fMinimizeConnections"; Expected=3},
    [pscustomobject]@{STIGID="WN11-CC-000065"; Title="Wi-Fi Sense auto-connect disabled";          Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"; Name="AutoConnectAllowedOEM"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000066"; Title="Include command line in proc-create events"; Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"; Name="ProcessCreationIncludeCmdLine_Enabled"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000068"; Title="Allow delegation of non-exportable creds";   Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"; Name="AllowProtectedCreds"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000070"; Title="Virtualization Based Security enabled";      Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name="EnableVirtualizationBasedSecurity"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000070b"; Title="VBS platform security: Secure Boot";        Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name="RequirePlatformSecurityFeatures"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000075"; Title="Credential Guard enabled (UEFI lock)";       Section="ComputerConfig"; Severity="High";   CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name="LsaCfgFlags"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000080"; Title="VBS protection of code integrity";           Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name="HypervisorEnforcedCodeIntegrity"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000085"; Title="Early Launch Antimalware boot policy";       Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"; Name="DriverLoadPolicy"; Expected=3},
    [pscustomobject]@{STIGID="WN11-CC-000090"; Title="Reprocess GPOs even if unchanged";           Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"; Name="NoGPOListChanges"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000100"; Title="No print driver download over HTTP";         Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Name="DisableWebPnPDownload"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000105"; Title="No web publishing/online ordering download"; Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoWebServices"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000110"; Title="Printing over HTTP prevented";               Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"; Name="DisableHTTPPrinting"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000120"; Title="No network selection UI on logon screen";    Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="DontDisplayNetworkSelectionUI"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000145"; Title="Require password on resume (battery)";       Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"; Name="DCSettingIndex"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000150"; Title="Require password on resume (plugged in)";    Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"; Name="ACSettingIndex"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000155"; Title="Solicited Remote Assistance disabled";       Section="ComputerConfig"; Severity="High";   CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fAllowToGetHelp"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000165"; Title="Restrict unauthenticated RPC clients";       Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"; Name="RestrictRemoteClients"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000170"; Title="Microsoft accounts optional for apps";       Section="ComputerConfig"; Severity="Low";    CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="MSAOptional"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000175"; Title="App Compat Inventory Collector off";         Section="ComputerConfig"; Severity="Low";    CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name="DisableInventory"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000180"; Title="Autoplay off for non-volume devices";        Section="ComputerConfig"; Severity="High";   CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="NoAutoplayfornonVolume"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000185"; Title="Default AutoRun = no autorun commands";      Section="ComputerConfig"; Severity="High";   CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoAutorun"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000190"; Title="Autoplay disabled for all drives";           Section="ComputerConfig"; Severity="High";   CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer"; Name="NoDriveTypeAutoRun"; Expected=255},
    [pscustomobject]@{STIGID="WN11-CC-000195"; Title="Enhanced anti-spoofing (facial)";            Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"; Name="EnhancedAntiSpoofing"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000197"; Title="Microsoft consumer experiences off";         Section="ComputerConfig"; Severity="Low";    CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name="DisableWindowsConsumerFeatures"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000200"; Title="Don't enumerate admins on elevation";        Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"; Name="EnumerateAdministrators"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000205"; Title="Telemetry not Full (Basic)";                 Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000206"; Title="Windows Update no internet peering";         Section="ComputerConfig"; Severity="Low";    CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"; Name="DODownloadMode"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000210"; Title="Defender SmartScreen for Explorer on";       Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnableSmartScreen"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000210b"; Title="SmartScreen level = Block";                 Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="ShellSmartScreenLevel"; Expected="Block"; Type="String"},
    [pscustomobject]@{STIGID="WN11-CC-000215"; Title="Explorer Data Execution Prevention on";      Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="NoDataExecutionPrevention"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000220"; Title="Explorer heap termination on corruption";    Section="ComputerConfig"; Severity="Low";    CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="NoHeapTerminationOnCorruption"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000225"; Title="Explorer shell protocol protected mode";     Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="PreXPSP2ShellProtocolBehavior"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000252"; Title="Game Recording and Broadcasting off";        Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"; Name="AllowGameDVR"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000255"; Title="Windows Hello hardware security device";     Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork"; Name="RequireSecurityDevice"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000260"; Title="Hello PIN min length = 6";                   Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity"; Name="MinimumPINLength"; Expected=6},
    [pscustomobject]@{STIGID="WN11-CC-000270"; Title="No saved passwords in RDP client";           Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="DisablePasswordSaving"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000275"; Title="No local drive redirection over RDP";        Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fDisableCdm"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000280"; Title="RDP always prompt for password";             Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fPromptForPassword"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000285"; Title="RDP require secure RPC";                     Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fEncryptRPCTraffic"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000290"; Title="RDP client encryption = High";               Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="MinEncryptionLevel"; Expected=3},
    [pscustomobject]@{STIGID="WN11-CC-000295"; Title="No RSS feed attachment download";            Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"; Name="DisableEnclosureDownload"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000300"; Title="No Basic auth for RSS over HTTP";            Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"; Name="AllowBasicAuthInClear"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000305"; Title="No indexing of encrypted files";             Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowIndexingEncryptedStoresOrItems"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000310"; Title="No user control over installs";              Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="EnableUserControl"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000315"; Title="No always-install-elevated (machine)";       Section="ComputerConfig"; Severity="High";   CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="AlwaysInstallElevated"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000320"; Title="Notify on web-based software install";       Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="SafeForScripting"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000325"; Title="No auto sign-in after restart";              Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="DisableAutomaticRestartSignOn"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000326"; Title="PowerShell script block logging on";         Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name="EnableScriptBlockLogging"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000327"; Title="PowerShell transcription on";                Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name="EnableTranscripting"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000330"; Title="WinRM client no Basic auth";                 Section="ComputerConfig"; Severity="High";   CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowBasic"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000335"; Title="WinRM client no unencrypted traffic";        Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowUnencryptedTraffic"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000345"; Title="WinRM service no Basic auth";                Section="ComputerConfig"; Severity="High";   CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="AllowBasic"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000350"; Title="WinRM service no unencrypted traffic";       Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="AllowUnencryptedTraffic"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000355"; Title="WinRM service no RunAs credential store";    Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; Name="DisableRunAs"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000360"; Title="WinRM client no Digest auth";                Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowDigest"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000365"; Title="No app voice activation above lock";         Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsActivateWithVoiceAboveLock"; Expected=2},
    [pscustomobject]@{STIGID="WN11-CC-000370"; Title="Domain convenience PIN logon disabled";      Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\Software\Policies\Microsoft\Windows\System"; Name="AllowDomainPINLogon"; Expected=0},
    [pscustomobject]@{STIGID="WN11-CC-000385"; Title="Windows Ink Workspace no access above lock"; Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace"; Name="AllowWindowsInkWorkspace"; Expected=1},
    [pscustomobject]@{STIGID="WN11-EP-000310"; Title="Kernel DMA Protection enumeration policy";   Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection"; Name="DeviceEnumerationPolicy"; Expected=0},
    [pscustomobject]@{STIGID="WN11-00-000150"; Title="SEHOP enabled";                              Section="ComputerConfig"; Severity="High";   CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name="DisableExceptionChainValidation"; Expected=0},
    [pscustomobject]@{STIGID="WN11-00-000165"; Title="SMBv1 disabled on SMB server";               Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="SMB1"; Expected=0},
    [pscustomobject]@{STIGID="WN11-00-000170"; Title="SMBv1 client driver disabled";               Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"; Name="Start"; Expected=4},
    [pscustomobject]@{STIGID="WN11-00-000126"; Title="Block consumer MSA user authentication";     Section="ComputerConfig"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"; Name="DisableUserAuth"; Expected=1},

    # ======================= SYSTEM (features / services / apps) =======================
    [pscustomobject]@{STIGID="WN11-00-000155"; Title="Windows PowerShell 2.0 feature disabled";   Section="System"; Severity="Medium"; CheckType="Feature"; FeatureName="MicrosoftWindowsPowerShellV2Root"},
    [pscustomobject]@{STIGID="WN11-00-000160"; Title="SMB 1.0/CIFS feature disabled";             Section="System"; Severity="Medium"; CheckType="Feature"; FeatureName="SMB1Protocol"},
    [pscustomobject]@{STIGID="WN11-00-000175"; Title="Secondary Logon service disabled";          Section="System"; Severity="Medium"; CheckType="Service"; ServiceName="seclogon"},
    [pscustomobject]@{STIGID="WN11-00-000125"; Title="Copilot app removed";                       Section="System"; Severity="Medium"; CheckType="Appx";    AppxName="*Copilot*"},

    # ======================= DOMAIN-ONLY (opt-in: -Section Domain) =======================
    [pscustomobject]@{STIGID="WN11-CC-000050a"; Title="Hardened UNC Path - NETLOGON";              Section="Domain"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"; Name="\\*\NETLOGON"; Expected="RequireMutualAuthentication=1, RequireIntegrity=1"; Type="String"},
    [pscustomobject]@{STIGID="WN11-CC-000050b"; Title="Hardened UNC Path - SYSVOL";                Section="Domain"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"; Name="\\*\SYSVOL"; Expected="RequireMutualAuthentication=1, RequireIntegrity=1"; Type="String"},
    [pscustomobject]@{STIGID="WN11-CC-000060"; Title="Block non-domain when on domain network";    Section="Domain"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"; Name="fBlockNonDomain"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000115"; Title="Device auth using certificate";              Section="Domain"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"; Name="DevicePKInitEnabled"; Expected=1},
    [pscustomobject]@{STIGID="WN11-CC-000130"; Title="Do not enumerate local users (domain)";      Section="Domain"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnumerateLocalUsers"; Expected=0},
    [pscustomobject]@{STIGID="WN11-UR-000075"; Title="Deny log on as batch = Ent/Domain Admins";   Section="Domain"; Severity="Medium"; CheckType="UserRight"; RightName="SeDenyBatchLogonRight";   Allowed=@()},
    [pscustomobject]@{STIGID="WN11-UR-000080"; Title="Deny log on as service = Ent/Domain Admins"; Section="Domain"; Severity="Medium"; CheckType="UserRight"; RightName="SeDenyServiceLogonRight"; Allowed=@()},

    # ======================= DoD-SPECIFIC (opt-in: -Section DoD) =======================
    [pscustomobject]@{STIGID="WN11-SO-000230"; Title="FIPS-compliant algorithms only";            Section="DoD"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy"; Name="Enabled"; Expected=1},
    [pscustomobject]@{STIGID="WN11-SO-000075"; Title="Legal notice text (DoD banner)";            Section="DoD"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LegalNoticeText"; Expected="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only."; Type="String"},
    [pscustomobject]@{STIGID="WN11-SO-000080"; Title="Legal notice caption";                      Section="DoD"; Severity="Low";    CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LegalNoticeCaption"; Expected="US Department of Defense Warning Statement"; Type="String"},

    # ======================= RESTRICTIVE (opt-in: -Section Restrictive) =======================
    # These break common laptop workflows (webcam, Bluetooth peripherals, account names). Apply deliberately.
    [pscustomobject]@{STIGID="WN11-CC-000007"; Title="Deny all webcam access";                     Section="Restrictive"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"; Name="Value"; Expected="Deny"; Type="String"},
    [pscustomobject]@{STIGID="WN11-00-000210"; Title="Bluetooth radio disabled";                   Section="Restrictive"; Severity="Medium"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Connectivity"; Name="AllowBluetooth"; Expected=0},
    [pscustomobject]@{STIGID="WN11-SO-000020"; Title="Rename built-in Administrator account";      Section="Restrictive"; Severity="Medium"; CheckType="AccountPolicy"; Policy="NewAdministratorName"; Expected="xAdmin"},
    [pscustomobject]@{STIGID="WN11-SO-000025"; Title="Rename built-in Guest account";              Section="Restrictive"; Severity="Medium"; CheckType="AccountPolicy"; Policy="NewGuestName"; Expected="xVisitor"}
)

# =============================================================================
# SCOPE FILTER (by StigId, else Section / Severity / RulesFile)
# =============================================================================
if ($StigId) {
    $scoped  = $rules | Where-Object { $_.STIGID -in $StigId }
    $missing = $StigId | Where-Object { $_ -notin $rules.STIGID }
    if ($missing) {
        Write-Warning "No rule found for STIG ID(s): $($missing -join ', ')"
    }
} else {
    if ($Section -contains 'All') {
        $scoped = $rules
    } else {
        $scoped = $rules | Where-Object { $_.Section -in $Section }
    }
    $scoped = $scoped | Where-Object { $_.Severity -in $Severity }

    if (-not $IgnoreRulesFile) {
        $iniPath = if ($RulesFile) { $RulesFile } else { Join-Path $PSScriptRoot 'Windows11-STIG-Computer-V2R7.ini' }
        $enabled = Get-EnabledStigIdsFromIni -Path $iniPath
        if ($null -ne $enabled) {
            $scoped = $scoped | Where-Object { $_.STIGID -in $enabled }
            if (-not $PassThru) { Write-Host "Rules file   : $iniPath" -ForegroundColor DarkGray }
        } elseif ($RulesFile -and -not $PassThru) {
            Write-Warning "RulesFile '$RulesFile' not found - ignoring."
        }
    }
}

if (-not $scoped) {
    if (-not $PassThru) { Write-Host "No rules match the selected -Section / -Severity / -StigId / RulesFile. Nothing to do." -ForegroundColor Yellow }
    return
}

if ($ListRules) {
    if ($PassThru) { return $scoped }
    $scoped | Sort-Object Section, Severity, STIGID |
        Format-Table STIGID, Section, Severity, Title -AutoSize
    Write-Host "`n$($scoped.Count) rule(s) in scope." -ForegroundColor Cyan
    return
}

if (-not $PassThru) {
    Write-Host "Windows 11 STIG V2R7 - $($scoped.Count) rule(s) in scope." -ForegroundColor White
    Write-Host "Sections : $((($scoped.Section | Sort-Object -Unique)) -join ', ')" -ForegroundColor DarkGray
    Write-Host "Severity : $($Severity -join ', ')   |   Mode: $(if($Remediate){'REMEDIATE'}else{'CHECK ONLY'})`n" -ForegroundColor DarkGray
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================
$report = @()
$rebootRequired = $false

foreach ($rule in $scoped) {
    $status     = "Non-Compliant"
    $remediated = $false
    $current    = $null
    $type       = if ($rule.PSObject.Properties.Name -contains 'Type') { $rule.Type } else { 'DWord' }

    switch ($rule.CheckType) {

        "AccountPolicy" {
            $export = Run-SeceditExport
            $line = ($export -split "`r`n") | Where-Object { $_ -match "^\s*$($rule.Policy)\s*=" }
            $current = if ($line) { (($line -split '=', 2)[1].Trim()) } else { $null }
            if ("$current" -eq "$($rule.Expected)") { $status = "Compliant" }
            elseif ($Remediate) {
                $tmp = [System.IO.Path]::GetTempFileName()
                if ($rule.Policy -in @('NewAdministratorName','NewGuestName')) {
@"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
$($rule.Policy) = "$($rule.Expected)"
"@ | Out-File $tmp -Encoding ASCII
                } else {
@"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
$($rule.Policy) = $($rule.Expected)
"@ | Out-File $tmp -Encoding ASCII
                }
                secedit /configure /db "$env:windir\security\database\secedit.sdb" /cfg $tmp /areas SECURITYPOLICY /quiet | Out-Null
                Remove-Item $tmp -Force -ErrorAction SilentlyContinue
                $remediated = $true; $rebootRequired = $true
            }
        }

        "UserRight" {
            $current = Get-UserRight -RightName $rule.RightName
            $a = ($current | Sort-Object) -join ','
            $b = ($rule.Allowed | Sort-Object) -join ','
            if ($a -eq $b) { $status = "Compliant" }
            elseif ($Remediate) { Set-UserRight -RightName $rule.RightName -AllowedSIDs $rule.Allowed; $remediated = $true }
            $current = if ($a) { $a } else { "(none)" }
        }

        "Registry" {
            $current = Get-RegValue -Path $rule.Path -Name $rule.Name
            if ($type -eq 'MultiString') {
                $ok = (@($current) -join ',') -eq (@($rule.Expected) -join ',')
            } else {
                $ok = ("$current" -eq "$($rule.Expected)")
            }
            if ($ok) { $status = "Compliant" }
            elseif ($Remediate) { Set-RegValue -Path $rule.Path -Name $rule.Name -Value $rule.Expected -Type $type; $remediated = $true }
        }

        "AuditPolicy" {
            $current = Get-AuditSetting -Guid $rule.Guid
            if ("$current" -eq "$($rule.Expected)") { $status = "Compliant" }
            elseif ($Remediate) { Set-AuditSetting -Guid $rule.Guid -Expected $rule.Expected; $remediated = $true }
        }

        "Feature" {
            $f = Get-WindowsOptionalFeature -Online -FeatureName $rule.FeatureName -ErrorAction SilentlyContinue
            $current = if ($f) { $f.State } else { "NotPresent" }
            if ($current -in @('Disabled','DisabledWithPayloadRemoved','NotPresent')) { $status = "Compliant" }
            elseif ($Remediate) {
                Disable-WindowsOptionalFeature -Online -FeatureName $rule.FeatureName -NoRestart -ErrorAction SilentlyContinue | Out-Null
                $remediated = $true; $rebootRequired = $true
            }
        }

        "Service" {
            $svc = Get-Service -Name $rule.ServiceName -ErrorAction SilentlyContinue
            $current = if ($svc) { $svc.StartType } else { "NotPresent" }
            if ($current -in @('Disabled','NotPresent')) { $status = "Compliant" }
            elseif ($Remediate) {
                Set-Service -Name $rule.ServiceName -StartupType Disabled -ErrorAction SilentlyContinue
                Stop-Service -Name $rule.ServiceName -Force -ErrorAction SilentlyContinue
                $remediated = $true
            }
        }

        "Appx" {
            $pkgs = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.Name -like $rule.AppxName }
            $current = if ($pkgs) { ($pkgs.Name -join ';') } else { "(absent)" }
            if (-not $pkgs) { $status = "Compliant" }
            elseif ($Remediate) {
                $pkgs | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
                $remediated = $true
            }
        }
    }

    $report += [pscustomobject]@{
        STIGID     = $rule.STIGID
        Section    = $rule.Section
        Sev        = $rule.Severity
        Title      = $rule.Title
        Status     = $status
        Remediated = if ($Remediate -and $remediated) { "Yes" } else { "No" }
        Current    = if ($null -eq $current -or "$current" -eq "") { "Not Set" } else { "$current" }
    }
}

# =============================================================================
# OUTPUT
# =============================================================================
if ($PassThru) {
    # Hand the structured results back to a caller (orchestrator) and stay quiet.
    return $report
}

$report | Sort-Object Section, Sev, STIGID |
    Format-Table STIGID, Section, Sev, Status, Remediated, Title -AutoSize

$compliant = ($report | Where-Object Status -eq 'Compliant').Count
$total     = $report.Count
Write-Host ("`nSummary: {0}/{1} compliant" -f $compliant, $total) -ForegroundColor White

if ($Remediate) {
    Write-Host "Remediation complete for the in-scope Windows 11 STIG V2R7 rules." -ForegroundColor Green
    if ($rebootRequired) {
        Write-Host "A reboot is required for some changes (account/audit policy, features) to take effect." -ForegroundColor Yellow
    }
} else {
    Write-Host "Run with -Remediate to fix the Non-Compliant items above." -ForegroundColor Cyan
}
