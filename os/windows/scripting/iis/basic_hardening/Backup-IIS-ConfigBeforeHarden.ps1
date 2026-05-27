<#
.SYNOPSIS
    IIS Configuration Backup Script (Pre-Hardening Snapshot)
    Creates a complete backup before applying hardening changes.

.DESCRIPTION
    Exports IIS applicationHost.config, site configs, SCHANNEL registry keys,
    custom headers, and authentication settings for later rollback if needed.

.PARAMETER None
    This script has no parameters.

.NOTES
    - Run as Administrator
    - Creates timestamped folder with all backups + detailed log
    - Critical safety step before running Harden-IIS.ps1
    - Used by Rollback-IIS-Hardening.ps1 for restore
    - Author: Robert Weber

.EXAMPLE
    .\Backup-IIS-ConfigBeforeHarden.ps1
    Creates a full pre-hardening backup snapshot
#>

$ErrorActionPreference = "Stop"
$WarningPreference = "Continue"

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupRoot = "IIS_BACKUP_BEFORE_$timestamp"
$backupPath = Join-Path $PSScriptRoot $backupRoot

$logFile = Join-Path $backupPath "backup_detailed.log"

function Write-Log {
    param(
        [Parameter(Mandatory)] [string]$Message,
        [string]$Level = "INFO",
        [switch]$Critical
    )
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $line = "$time [$Level] $Message"
    $line | Out-File -FilePath $logFile -Append -Encoding utf8

    $color = switch ($Level) {
        "INFO"    { "White" }
        "SUCCESS" { "Green" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        default   { "White" }
    }
    Write-Host $line -ForegroundColor $color

    if ($Critical) { throw $Message }
}

# ─── PRE-FLIGHT CHECKS ──────────────────────────────────────────────────────────
try {
    Write-Log "Starting pre-flight checks..." "INFO"

    # Elevation (redundant but explicit)
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Script must run elevated (Administrator)"
    }

    # WebAdministration module
    if (-not (Get-Module -ListAvailable WebAdministration)) {
        throw "WebAdministration module is not available on this system"
    }

    # IIS service running?
    $iisService = Get-Service W3SVC -ErrorAction Stop
    if ($iisService.Status -ne "Running") {
        Write-Log "IIS service (W3SVC) is not running. Backup may be incomplete." "WARN"
    }

    # Disk space check (at least 500 MB free on current drive)
    $drive = (Get-Item $PSScriptRoot).PSDrive
    $freeGB = [math]::Round(($drive.Free / 1GB), 2)
    if ($freeGB -lt 0.5) {
        throw "Insufficient disk space. Only $freeGB GB free on drive $($drive.Name):"
    }

    # Create backup directory
    New-Item -ItemType Directory -Path $backupPath -Force -ErrorAction Stop | Out-Null
    Write-Log "Backup directory created: $backupPath" "SUCCESS"

} catch {
    Write-Log "PRE-FLIGHT CHECK FAILED: $($_.Exception.Message)" "ERROR" -Critical
}

# ─── MAIN BACKUP OPERATIONS ─────────────────────────────────────────────────────
try {
    Import-Module WebAdministration -ErrorAction Stop
    Write-Log "WebAdministration module loaded successfully" "SUCCESS"

    # Global IIS config export
    try {
        & "$env:windir\system32\inetsrv\appcmd.exe" list config /xml > "$backupPath\applicationHost_config_export.xml" 2>&1
        if ($LASTEXITCODE -ne 0) { throw "appcmd global export failed (exit code: $LASTEXITCODE)" }
        Write-Log "Global IIS configuration exported" "SUCCESS"
    } catch {
        Write-Log "Global config export failed: $($_.Exception.Message)" "ERROR"
        # Continue - partial backup still valuable
    }

    # Per-site exports
    $sites = Get-Website -ErrorAction Stop
    Write-Log "Found $($sites.Count) websites" "INFO"

    foreach ($site in $sites) {
        $safeName = $site.Name -replace '[^a-zA-Z0-9_-]','_'
        $outFile = "$backupPath\site_$safeName.xml"

        try {
            & "$env:windir\system32\inetsrv\appcmd.exe" list config "$($site.Name)" /xml > $outFile 2>&1
            if ($LASTEXITCODE -ne 0) { throw "appcmd failed for site $($site.Name)" }
            Write-Log "Exported config for site: $($site.Name)" "SUCCESS"
        } catch {
            Write-Log "Failed to export site $($site.Name): $($_.Exception.Message)" "ERROR"
        }
    }

    # SCHANNEL registry backup
    $regPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CipherSuites"
    )

    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            try {
                $safe = $path -replace '[:\\]','_'
                reg export $path "$backupPath\schannel_$safe.reg" /y | Out-Null
                Write-Log "Exported registry: $path" "SUCCESS"
            } catch {
                Write-Log "Registry export failed for $path : $($_.Exception.Message)" "ERROR"
            }
        }
    }

    # Headers backup (global + sites)
    try {
        $globalHeaders = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -ErrorAction Stop
        $globalHeaders.Collection | Export-Csv "$backupPath\global_headers.csv" -NoTypeInformation -ErrorAction Stop
        Write-Log "Global custom headers backed up" "SUCCESS"
    } catch {
        Write-Log "Global headers backup failed: $($_.Exception.Message)" "ERROR"
    }

    foreach ($site in $sites) {
        $safeName = $site.Name -replace '[^a-zA-Z0-9_-]','_'
        try {
            $headers = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -ErrorAction Stop
            $headers.Collection | Export-Csv "$backupPath\headers_$safeName.csv" -NoTypeInformation -ErrorAction Stop
            Write-Log "Headers backed up for: $($site.Name)" "SUCCESS"
        } catch {
            Write-Log "Headers backup failed for $($site.Name): $($_.Exception.Message)" "ERROR"
        }
    }

    # Manifest
    $manifest = [ordered]@{
        BackupDate   = $timestamp
        ComputerName = $env:COMPUTERNAME
        IISVersion   = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue).SetupString ?? "Unknown"
        SitesCount   = $sites.Count
        BackupPath   = $backupPath.FullName
        Note         = "Use Rollback-IIS-Hardening.ps1 -BackupPath '$backupPath'"
    }
    $manifest | ConvertTo-Json -Depth 10 | Out-File "$backupPath\manifest.json" -Encoding utf8
    Write-Log "Backup manifest created" "SUCCESS"

    Write-Host "`nBackup completed successfully!" -ForegroundColor Green
    Write-Host "Location: $backupPath" -ForegroundColor Cyan
    Write-Host "Log: $logFile" -ForegroundColor Cyan
}
catch {
    Write-Log "CRITICAL BACKUP FAILURE: $($_.Exception.Message)" "ERROR"
    Write-Log $_.ScriptStackTrace "ERROR"
    Write-Host "`nPartial backup may exist in: $backupPath" -ForegroundColor Yellow
    Write-Host "Review log file for details." -ForegroundColor Yellow
}