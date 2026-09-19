<#
.SYNOPSIS
    IIS Hardening Rollback Script
    Restores IIS configuration from a pre-hardening backup.

.DESCRIPTION
    Reverts IIS settings, registry keys, custom headers, and authentication
    configurations to their state captured by Backup-IIS-ConfigBeforeHarden.ps1.

.PARAMETER BackupPath
    Required. Full path to the backup folder created by Backup-IIS-ConfigBeforeHarden.ps1.

.NOTES
    - Run as Administrator
    - Use only after hardening issues are detected
    - Some changes (e.g. registry) may still require reboot
    - Always test applications after rollback
    - Author: Robert Weber

.EXAMPLE
    .\Rollback-IIS-Hardening.ps1 -BackupPath ".\IIS_BACKUP_BEFORE_20260118-143022"
    Restores IIS from the specified backup folder
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$BackupPath
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $BackupPath -PathType Container)) {
    Write-Error "Backup path not found: $BackupPath"
    exit 1
}

$logFile = Join-Path $BackupPath "rollback.log"

function Write-Log {
    param(
        [Parameter(Mandatory)] [string]$Message,
        [ConsoleColor]$Color = "White",
        [switch]$Error
    )
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$time  $Message" | Out-File -FilePath $logFile -Append -Encoding utf8
    if ($Error) { Write-Host $Message -ForegroundColor Red }
    else { Write-Host $Message -ForegroundColor $Color }
}

Write-Log "Rollback process started" Cyan

$successCount = 0
$failCount = 0

try {
    # 1. Restore global IIS configuration
    $globalXml = Join-Path $BackupPath "applicationHost_config_export.xml"
    if (Test-Path $globalXml) {
        Write-Log "Restoring global IIS configuration..."
        try {
            & "$env:windir\system32\inetsrv\appcmd.exe" set config -in $globalXml
            Write-Log "Global configuration restored" Green
            $successCount++
        }
        catch {
            Write-Log "Global restore failed: $($_.Exception.Message)" -Error
            $failCount++
        }
    }

    # 2. Restore site configurations
    Get-ChildItem -Path $BackupPath -Filter "site_*.xml" | ForEach-Object {
        $siteXml = $_.FullName
        $siteName = $_.BaseName -replace '^site_','' -replace '_',' '
        Write-Log "Attempting to restore site: $siteName"

        try {
            & "$env:windir\system32\inetsrv\appcmd.exe" set config "$siteName" -in $siteXml
            Write-Log "  Site $siteName restored" Green
            $successCount++
        }
        catch {
            Write-Log "  Failed to restore site $siteName : $($_.Exception.Message)" -Error
            $failCount++
        }
    }

    # 3. Restore registry (SCHANNEL)
    Get-ChildItem -Path $BackupPath -Filter "schannel_*.reg" | ForEach-Object {
        Write-Log "Importing registry file: $($_.Name)"
        try {
            reg import $_.FullName > $null 2>&1
            Write-Log "  Imported: $($_.Name)" Green
            $successCount++
        }
        catch {
            Write-Log "  Registry import failed: $($_.Exception.Message)" -Error
            $failCount++
        }
    }

    # 4. Restore custom headers
    Write-Log "Restoring custom headers..."

    # Global headers
    $globalCsv = Join-Path $BackupPath "global_custom_headers.csv"
    if (Test-Path $globalCsv) {
        try {
            Clear-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' `
                -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -ErrorAction Stop

            $headers = Import-Csv $globalCsv -ErrorAction Stop
            foreach ($h in $headers) {
                Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' `
                    -Filter "system.webServer/httpProtocol/customHeaders" -Name "." `
                    -Value @{name=$h.name; value=$h.value} -ErrorAction Stop
            }
            Write-Log "Global custom headers restored" Green
            $successCount++
        }
        catch {
            Write-Log "Global headers restore failed: $($_.Exception.Message)" -Error
            $failCount++
        }
    }

    # Site headers
    Get-ChildItem -Path $BackupPath -Filter "headers_site_*.csv" | ForEach-Object {
        $siteName = $_.BaseName -replace '^headers_site_','' -replace '_',' '
        $csvPath = $_.FullName

        if (Get-Website -Name $siteName -ErrorAction SilentlyContinue) {
            try {
                Clear-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $siteName `
                    -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -ErrorAction Stop

                $headers = Import-Csv $csvPath -ErrorAction Stop
                foreach ($h in $headers) {
                    Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $siteName `
                        -Filter "system.webServer/httpProtocol/customHeaders" -Name "." `
                        -Value @{name=$h.name; value=$h.value} -ErrorAction Stop
                }
                Write-Log "Headers restored for site: $siteName" Green
                $successCount++
            }
            catch {
                Write-Log "Headers restore failed for $siteName: $($_.Exception.Message)" -Error
                $failCount++
            }
        }
    }

    Write-Log "Rollback summary: $successCount successful | $failCount failed" Cyan
}
catch {
    Write-Log "CRITICAL ROLLBACK ERROR: $($_.Exception.Message)" Red
    Write-Log $_.ScriptStackTrace Yellow
}
finally {
    Write-Log "Rollback process finished" Cyan
    Write-Host "`nRollback completed. Check log: $logFile" -ForegroundColor Cyan
    Write-Host "Recommended: run iisreset and test applications thoroughly" -ForegroundColor Yellow
}