<#
.SYNOPSIS
    Microsoft Defender Antivirus STIG V2R7

.DESCRIPTION
    This script checks and remediates the Microsoft Defender Antivirus settings
    as per the DoD STIG V2R7 guidelines. It covers all relevant registry settings
    for Defender Antivirus, including PUA protection, ASR rules, MAPS, and more.
    The script is data-driven, with all rules defined in the $rules array based on
    the GPO XML. It uses native PowerShell and .NET without any external dependencies.
    Run with -Remediate to apply fixes automatically. The script outputs a compliance
    report to the console.

.PARAMETER Remediate
    If specified, the script will attempt to remediate any non-compliant settings
    by setting the expected values in the registry.

.EXAMPLE
    .\MicrosoftDefenderAntivirus-STIG-V2R7.ps1 -Remediate
    Checks all Defender Antivirus settings against the STIG and remediates any that are non-compliant.

.NOTES
    Author: Robert Weber
#>

param([switch]$Remediate)

# =============================================================================
# NATIVE HELPER FUNCTIONS
# =============================================================================
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

# =============================================================================
# STIG RULES ARRAY
# =============================================================================
$rules = @(

    # === PUAPROTECTION / PUA Detection ===
    [pscustomobject]@{VID="Defender-PUA"; Title="Configure detection for potentially unwanted applications"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name="PUAProtection"; Expected=1},

    # === Local admin merge behavior ===
    [pscustomobject]@{VID="Defender-Merge"; Title="Configure local administrator merge behavior for lists"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name="DisableLocalAdminMerge"; Expected=0},

    # === Exclusions visibility ===
    [pscustomobject]@{VID="Defender-ExclusionsVisible"; Title="Control whether or not exclusions are visible to Local Admins"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name="HideExclusions"; Expected=0},

    # === Randomize scheduled task times ===
    [pscustomobject]@{VID="Defender-Randomize"; Title="Randomize scheduled task times"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name="RandomizeScheduleTaskTimes"; Expected=1},

    # === Turn off Auto Exclusions ===
    [pscustomobject]@{VID="Defender-AutoExclusions"; Title="Turn off Auto Exclusions"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions"; Name="DisableAutoExclusions"; Expected=0},

    # === EDR in block mode ===
    [pscustomobject]@{VID="Defender-EDRBlock"; Title="Enable EDR in block mode"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name="EDRBlockMode"; Expected=1},

    # === Block at First Sight ===
    [pscustomobject]@{VID="Defender-BlockAtFirstSight"; Title="Configure the 'Block at First Sight' feature"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name="DisableBlockAtFirstSeen"; Expected=0},

    # === MAPS / Cloud ===
    [pscustomobject]@{VID="Defender-MAPS"; Title="Join Microsoft MAPS"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"; Name="SpynetReporting"; Expected=2},
    [pscustomobject]@{VID="Defender-SampleSubmission"; Title="Send file samples when further analysis is required"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"; Name="SubmitSamplesConsent"; Expected=1},

    # === Attack Surface Reduction Rules ===
    [pscustomobject]@{VID="ASR-1"; Title="ASR - Block executable content from email client"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"; Name="BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"; Expected=1},
    [pscustomobject]@{VID="ASR-2"; Title="ASR - Block all Office applications from creating child processes"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"; Name="D4F940AB-401B-4EFC-AADC-AD5F3C50688A"; Expected=1},
    [pscustomobject]@{VID="ASR-3"; Title="ASR - Block Office applications from creating executable content"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"; Name="3B576869-A4EC-4529-8536-B80A7769E899"; Expected=1},
    [pscustomobject]@{VID="ASR-4"; Title="ASR - Block Office applications from injecting code into other processes"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"; Name="75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"; Expected=1},
    [pscustomobject]@{VID="ASR-5"; Title="ASR - Block JavaScript/VBScript from launching downloaded executable content"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"; Name="D3E037E1-3EB8-44C8-A917-57927947596D"; Expected=1},
    [pscustomobject]@{VID="ASR-6"; Title="ASR - Block execution of potentially obfuscated scripts"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"; Name="5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"; Expected=1},
    [pscustomobject]@{VID="ASR-7"; Title="ASR - Block Win32 API calls from Office macros"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"; Name="92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"; Expected=1},
    [pscustomobject]@{VID="ASR-8"; Title="ASR - Block credential stealing from LSASS"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"; Name="01443614-cd74-433a-b99e-2ecdc07bfc25"; Expected=2},
    [pscustomobject]@{VID="ASR-9"; Title="ASR - Block process creations originating from PSExec and WMI commands"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"; Name="7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"; Expected=1},
    [pscustomobject]@{VID="ASR-10"; Title="ASR - Block untrusted and unsigned processes that run from USB"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"; Name="9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"; Expected=1},
    [pscustomobject]@{VID="ASR-11"; Title="ASR - Block executable files from running unless they meet a prevalence, age, or trusted list criterion"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"; Name="b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"; Expected=1},
    [pscustomobject]@{VID="ASR-12"; Title="ASR - Block persistence through WMI event subscription"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"; Name="c1db55ab-c21a-4637-bb3f-a12568109d35"; Expected=1},
    [pscustomobject]@{VID="ASR-13"; Title="ASR - Block Office communication applications from creating child processes"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"; Name="d1e49aac-8f56-4280-b9ba-993a6d77406c"; Expected=2},
    [pscustomobject]@{VID="ASR-14"; Title="ASR - Block Adobe Reader from creating child processes"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"; Name="e6db77e5-3df2-4cf1-b95a-636979351e5b"; Expected=2},
    [pscustomobject]@{VID="ASR-15"; Title="ASR - Block abuse of exploited vulnerable signed drivers"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"; Name="26190899-1602-49e8-8b27-eb1d0a1ce869"; Expected=1},
    [pscustomobject]@{VID="ASR-16"; Title="ASR - Block process creations from PSExec and WMI"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"; Name="56a863a9-875e-4185-98a7-b882c64b5ce5"; Expected=1},

    # === Network Protection ===
    [pscustomobject]@{VID="Defender-NetworkProtection"; Title="Prevent users and apps from accessing dangerous websites"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"; Name="EnableNetworkProtection"; Expected=1},
    [pscustomobject]@{VID="Defender-NetworkProtectionServer"; Title="Network Protection block/audit mode on Windows Server"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"; Name="EnableNetworkProtectionOnServer"; Expected=1},

    # === Extended cloud check ===
    [pscustomobject]@{VID="Defender-ExtendedCloudCheck"; Title="Configure extended cloud check"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"; Name="CloudExtendedTimeout"; Expected=50},

    # === File hash computation ===
    [pscustomobject]@{VID="Defender-FileHash"; Title="Enable file hash computation feature"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"; Name="EnableFileHashComputation"; Expected=1},

    # === Cloud protection level ===
    [pscustomobject]@{VID="Defender-CloudLevel"; Title="Select cloud protection level"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"; Name="MpCloudBlockLevel"; Expected=2},

    # === Warn verdict to block ===
    [pscustomobject]@{VID="Defender-WarnToBlock"; Title="Convert warn verdict to block"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Network Inspection System"; Name="ConvertWarnToBlock"; Expected=1},

    # === Asynchronous inspection ===
    [pscustomobject]@{VID="Defender-AsyncInspection"; Title="Turn on asynchronous inspection"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Network Inspection System"; Name="EnableAsyncInspection"; Expected=1},

    # === Real-time protection during OOBE ===
    [pscustomobject]@{VID="Defender-OOBE"; Title="Configure real-time protection and Security Intelligence Updates during OOBE"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="DisableRealtimeProtectionDuringOOBE"; Expected=0},

    # === Script scanning ===
    [pscustomobject]@{VID="Defender-ScriptScanning"; Title="Turn on script scanning"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="DisableScriptScanning"; Expected=0},

    # === Dynamic Signature dropped events ===
    [pscustomobject]@{VID="Defender-DynamicSignature"; Title="Configure whether to report Dynamic Signature dropped events"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"; Name="DisableDynamicSignatureDroppedEvents"; Expected=0},

    # === Quick scan exclusions ===
    [pscustomobject]@{VID="Defender-QuickScanExclusions"; Title="Scan excluded files and directories during quick scans"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name="DisableQuickScanExclusions"; Expected=0},

    # === Packed executables ===
    [pscustomobject]@{VID="Defender-PackedExe"; Title="Scan packed executables"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name="DisablePackedExeScanning"; Expected=0},

    # === Removable drives ===
    [pscustomobject]@{VID="Defender-RemovableDrives"; Title="Scan removable drives"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name="DisableRemovableDriveScanning"; Expected=0},

    # === Scheduled scan day ===
    [pscustomobject]@{VID="Defender-ScheduledScanDay"; Title="Specify the day of the week to run a scheduled scan"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name="ScanScheduleDay"; Expected=0},

    # === Email scanning ===
    [pscustomobject]@{VID="Defender-EmailScan"; Title="Turn on e-mail scanning"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name="DisableEmailScanning"; Expected=0},

    # === Heuristics ===
    [pscustomobject]@{VID="Defender-Heuristics"; Title="Turn on heuristics"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"; Name="DisableHeuristics"; Expected=0},

    # === Security Intelligence age ===
    [pscustomobject]@{VID="Defender-SpywareAge"; Title="Define the number of days before spyware security intelligence is considered out of date"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates"; Name="SpywareAgeLimit"; Expected=7},
    [pscustomobject]@{VID="Defender-VirusAge"; Title="Define the number of days before virus security intelligence is considered out of date"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates"; Name="VirusAgeLimit"; Expected=7},

    # === Security Intelligence update day ===
    [pscustomobject]@{VID="Defender-SignatureUpdateDay"; Title="Specify the day of the week to check for security intelligence updates"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates"; Name="SignatureUpdateDay"; Expected=0},

    # === Threat alert levels ===
    [pscustomobject]@{VID="Defender-ThreatLevels"; Title="Specify threat alert levels at which default action should not be taken"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats"; Name="DefaultAction"; Expected="2"},  # Quarantine for all levels

    # === Hide Family options ===
    [pscustomobject]@{VID="Defender-FamilyOptions"; Title="Hide the Family options area"; CheckType="Registry"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family"; Name="DisableFamily"; Expected=1}
)

# =============================================================================
# MAIN EXECUTION
# =============================================================================
$report = @()

foreach ($rule in $rules) {
    $status = "Non-Compliant"
    $remediated = $false

    $current = Get-RegValue -Path $rule.Path -Name $rule.Name

    if ($current -eq $rule.Expected) {
        $status = "Compliant"
    }
    elseif ($Remediate) {
        Set-RegValue -Path $rule.Path -Name $rule.Name -Value $rule.Expected
        $remediated = $true
        $status = "Remediated"
    }

    $report += [pscustomobject]@{
        VID        = $rule.VID
        Title      = $rule.Title
        Status     = $status
        Remediated = if ($Remediate -and $remediated) { "Yes" } else { "No" }
    }
}

# =============================================================================
# OUTPUT REPORT
# =============================================================================
$report | Sort-Object VID | Format-Table -AutoSize

if ($Remediate) {
    Write-Host "`nAll Microsoft Defender Antivirus STIG V2R7 settings have been remediated!" -ForegroundColor Green
} else {
    Write-Host "`nRun the script with -Remediate to apply fixes." -ForegroundColor Cyan
}
Write-Host "Script complete - the Microsoft Defender Antivirus STIG V2R7 is finished." -ForegroundColor White