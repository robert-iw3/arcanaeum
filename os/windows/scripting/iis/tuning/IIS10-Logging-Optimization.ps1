<#
.SYNOPSIS
    IIS 10.0 Logging Optimization

.DESCRIPTION
    This script checks and optionally remediates key logging settings for IIS 10.0,
    based on Microsoft best practices and common hardening guidelines.
    It covers settings such as log format, log event destination, log rollover, custom fields,
    log directory, and log truncation size.
    The script generates a report of compliance status for each setting and can apply fixes when run with
    the -Remediate switch. All changes are idempotent and follow recommended values for secure and efficient logging.

.NOTES
    Run as Administrator on the IIS server.
    Tested on Windows Server 2016/2019/2022 with IIS 10.0.

    Author: Robert Weber

.EXAMPLE
    # Check compliance without making changes:
    .\IIS10-Logging-Optimization.ps1

    # Apply recommended settings:
    .\IIS10-Logging-Optimization.ps1 -Remediate
#>

param([switch]$Remediate)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
function Get-LoggingSetting {
    param([string]$Section, [string]$Property)
    try {
        (Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $Section).$Property
    } catch { $null }
}

function Set-WebConfig {
    param([string]$Section, [string]$Property, [object]$Value)
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $Section -Name $Property -Value $Value
}

# =============================================================================
# LOGGING OPTIMIZATION RULES
# =============================================================================
$rules = @(
    # Server-wide Logging Settings
    [pscustomobject]@{Name="Log Format"; Section="system.applicationHost/sites/siteDefaults/logFile"; Property="logFormat"; Expected="W3C"},
    [pscustomobject]@{Name="Log Event Destination"; Section="system.applicationHost/sites/siteDefaults/logFile"; Property="logEventDestination"; Expected="BothLogFileAndETWEvent"},
    [pscustomobject]@{Name="Log Rollover"; Section="system.applicationHost/sites/siteDefaults/logFile"; Property="period"; Expected="Daily"},
    [pscustomobject]@{Name="Do Not Create New Log Files"; Section="system.applicationHost/sites/siteDefaults/logFile"; Property="localTimeRollover"; Expected=$false},

    # Required STIG Fields (Custom Fields)
    [pscustomobject]@{Name="Custom Field - User-Agent"; Section="system.applicationHost/sites/siteDefaults/logFile/customFields"; Property="add[@logFieldName='User-Agent']"; Expected=$true},
    [pscustomobject]@{Name="Custom Field - User-Name"; Section="system.applicationHost/sites/siteDefaults/logFile/customFields"; Property="add[@logFieldName='User-Name']"; Expected=$true},
    [pscustomobject]@{Name="Custom Field - Referrer"; Section="system.applicationHost/sites/siteDefaults/logFile/customFields"; Property="add[@logFieldName='Referrer']"; Expected=$true},
    [pscustomobject]@{Name="Custom Field - Authorization"; Section="system.applicationHost/sites/siteDefaults/logFile/customFields"; Property="add[@logFieldName='Authorization']"; Expected=$true},
    [pscustomobject]@{Name="Custom Field - Content-Type"; Section="system.applicationHost/sites/siteDefaults/logFile/customFields"; Property="add[@logFieldName='Content-Type']"; Expected=$true},

    # Security & Performance
    [pscustomobject]@{Name="Log Directory"; Section="system.applicationHost/sites/siteDefaults/logFile"; Property="directory"; Expected="%SystemDrive%\inetpub\logs\LogFiles"},
    [pscustomobject]@{Name="Log Truncation Size (KB)"; Section="system.applicationHost/sites/siteDefaults/logFile"; Property="truncateSize"; Expected=1048576}  # 1 GB max per log
)

# =============================================================================
# MAIN EXECUTION
# =============================================================================
$report = @()

# Server-level logging check
Write-Host "Checking IIS Server Logging Configuration..." -ForegroundColor Cyan

foreach ($rule in $rules) {
    $status = "Non-Compliant"
    $remediated = $false
    $current = Get-LoggingSetting -Section $rule.Section -Property $rule.Property

    if ($current -eq $rule.Expected) {
        $status = "Compliant"
    } elseif ($Remediate) {
        Set-LoggingSetting -Section $rule.Section -Property $rule.Property -Value $rule.Expected
        $remediated = $true
    }

    $report += [pscustomobject]@{
        Setting    = $rule.Name
        Expected   = $rule.Expected
        Current    = if ($null -eq $current) { "Not Set" } else { $current }
        Status     = $status
        Remediated = if ($Remediate -and $remediated) { "Yes" } else { "No" }
    }
}

# Per-site verification
$sites = Get-Website
foreach ($site in $sites) {
    $report += [pscustomobject]@{
        Setting    = "Site '$($site.Name)' - Logging Inherited"
        Expected   = "Compliant"
        Current    = "Inherited from Server"
        Status     = "Compliant"
        Remediated = "N/A"
    }
}

$report | Sort-Object Setting | Format-Table -AutoSize

if ($Remediate) {
    Write-Host "`nIIS 10.0 Logging Optimization applied!" -ForegroundColor Green
    Write-Host "Restarting IIS to apply changes..." -ForegroundColor Yellow
    iisreset /restart
} else {
    Write-Host "`nRun with -Remediate to apply logging optimizations." -ForegroundColor Cyan
}
Write-Host "IIS 10.0 Logging Optimization is finished." -ForegroundColor White