<#
.SYNOPSIS
    IIS 10.0 Extra Credit Optimizations & Tuning

.DESCRIPTION
    This script checks and optionally remediates additional optimization and tuning settings for IIS 10.
    It covers settings such as compression, output caching, security headers, keep-alive settings,
    request filtering limits, and failed request tracing.
    The script generates a report of compliance status for each setting and can apply fixes when run with the -Remediate switch.
    All changes are idempotent and follow recommended values for secure and efficient IIS operation.

.NOTES
    Run as Administrator on the IIS server.
    Tested on Windows Server 2016/2019/2022 with IIS 10.0.

    Author: Robert Weber

.EXAMPLE
    # Check compliance without making changes:
    .\IIS10-ExtraCredit-Tuning.ps1

    # Apply recommended settings:
    .\IIS10-ExtraCredit-Tuning.ps1 -Remediate
#>

param([switch]$Remediate)

# Import built-in IIS module (always present on IIS 10.0 servers)
Import-Module WebAdministration -ErrorAction SilentlyContinue

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
function Get-WebConfig {
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
# OPTIMIZATION RULES
# =============================================================================
$rules = @(
    # === Compression ===
    [pscustomobject]@{Name="Static Compression Enabled"; Section="system.webServer/httpCompression"; Property="staticCompression"; Expected=$true},
    [pscustomobject]@{Name="Dynamic Compression Enabled"; Section="system.webServer/httpCompression"; Property="dynamicCompression"; Expected=$true},
    [pscustomobject]@{Name="Static Compression Level"; Section="system.webServer/httpCompression"; Property="staticCompressionLevel"; Expected=7},   # 7 = balanced
    [pscustomobject]@{Name="Dynamic Compression Level"; Section="system.webServer/httpCompression"; Property="dynamicCompressionLevel"; Expected=4},

    # === Output Caching ===
    [pscustomobject]@{Name="Output Caching Enabled"; Section="system.webServer/caching"; Property="enabled"; Expected=$true},
    [pscustomobject]@{Name="Kernel Caching Enabled"; Section="system.webServer/caching"; Property="enableKernelCache"; Expected=$true},

    # === Security Headers (STIG-aligned) ===
    [pscustomobject]@{Name="X-Frame-Options"; Section="system.webServer/httpProtocol/customHeaders"; Property="add[@name='X-Frame-Options']"; Expected="SAMEORIGIN"},
    [pscustomobject]@{Name="X-Content-Type-Options"; Section="system.webServer/httpProtocol/customHeaders"; Property="add[@name='X-Content-Type-Options']"; Expected="nosniff"},
    [pscustomobject]@{Name="X-XSS-Protection"; Section="system.webServer/httpProtocol/customHeaders"; Property="add[@name='X-XSS-Protection']"; Expected="1; mode=block"},
    [pscustomobject]@{Name="Referrer-Policy"; Section="system.webServer/httpProtocol/customHeaders"; Property="add[@name='Referrer-Policy']"; Expected="strict-origin-when-cross-origin"},

    # === HTTP Keep-Alive & Limits ===
    [pscustomobject]@{Name="Keep-Alive Enabled"; Section="system.webServer/httpProtocol"; Property="allowKeepAlive"; Expected=$true},
    [pscustomobject]@{Name="Max Keep-Alive Requests"; Section="system.webServer/httpProtocol"; Property="maxKeepAliveRequests"; Expected=0},   # 0 = unlimited
    [pscustomobject]@{Name="Keep-Alive Timeout (seconds)"; Section="system.webServer/httpProtocol"; Property="keepAliveTimeout"; Expected=120},

    # === Request Filtering ===
    [pscustomobject]@{Name="Request Filtering - Max Query String"; Section="system.webServer/security/requestFiltering"; Property="requestLimits.maxQueryString"; Expected=2048},
    [pscustomobject]@{Name="Request Filtering - Max URL"; Section="system.webServer/security/requestFiltering"; Property="requestLimits.maxUrl"; Expected=4096},

    # === Failed Request Tracing (lightweight) ===
    [pscustomobject]@{Name="Failed Request Tracing Enabled"; Section="system.webServer/tracing"; Property="enabled"; Expected=$false}   # Only enable if actively troubleshooting
)

# =============================================================================
# MAIN EXECUTION
# =============================================================================
$report = @()

Write-Host "=== IIS 10.0 Remaining Optimizations & Tuning ===" -ForegroundColor Cyan

foreach ($rule in $rules) {
    $status = "Non-Compliant"
    $remediated = $false
    $current = Get-WebConfig -Section $rule.Section -Property $rule.Property

    if ($current -eq $rule.Expected) {
        $status = "Compliant"
    } elseif ($Remediate) {
        Set-WebConfig -Section $rule.Section -Property $rule.Property -Value $rule.Expected
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

$report | Sort-Object Setting | Format-Table -AutoSize

if ($Remediate) {
    Write-Host "`nIIS 10.0 Extra Credit Optimizations & Tuning applied!" -ForegroundColor Green
    Write-Host "Restarting IIS to apply changes..." -ForegroundColor Yellow
    iisreset /restart
} else {
    Write-Host "`nRun with -Remediate to apply these optimizations." -ForegroundColor Cyan
}
Write-Host "IIS 10.0 Extra Credit Optimizations & Tuning is finished." -ForegroundColor White