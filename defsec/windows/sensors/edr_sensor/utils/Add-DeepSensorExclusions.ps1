<#
.SYNOPSIS
    Registers Windows Defender exclusions for the Deep Sensor EDR project.

.DESCRIPTION
    DeepSensor_Launcher.ps1 and OsSensor.cs implement legitimate active-defense
    primitives (native thread suspension via OpenThread/SuspendThread, memory
    forensics via MiniDumpWriteDump/ReadProcessMemory/VirtualProtectEx). This is
    the same category of Win32 API surface any real EDR/endpoint agent uses, and
    Defender's AMSI static content scan can classify the script itself as
    malicious content purely from that combination of API references -- this is
    a known false positive for security tooling, not a sign the script is unsafe.

    This script does NOT bypass or disable AMSI, real-time protection, or any
    Defender scanning engine. It adds standard PATH exclusions for the sensor's
    own source and data directories, which is the normal, expected deployment
    step for any legitimate security agent (every commercial EDR/AV product
    ships itself pre-excluded from its own or sibling engines for this exact
    reason). Run this ONCE, elevated, before launching the sensor for the first
    time on a given host.

.NOTES
    Must be run as Administrator. Safe to re-run (Add-MpPreference is idempotent
    for already-present exclusion paths).

    Author: Robert Weber
#>
#Requires -RunAsAdministrator

$ProjectDir = Split-Path $PSScriptRoot -Parent
$DataDir    = "C:\ProgramData\DeepSensor"

$paths = @($ProjectDir, $DataDir) | Where-Object { $_ -and (Test-Path $_) }

if ($paths.Count -eq 0) {
    Write-Host "[!] Neither the project directory nor $DataDir exist yet -- nothing to exclude." -ForegroundColor Yellow
    exit 1
}

foreach ($p in $paths) {
    try {
        Add-MpPreference -ExclusionPath $p -ErrorAction Stop
        Write-Host "[+] Excluded: $p" -ForegroundColor Green
    } catch {
        Write-Host "[!] Failed to exclude $p : $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n[*] Current Defender path exclusions:" -ForegroundColor Cyan
(Get-MpPreference).ExclusionPath | ForEach-Object { Write-Host "    $_" }
