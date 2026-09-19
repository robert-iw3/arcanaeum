<#
.SYNOPSIS
    IIS 10.0 Advanced Troubleshooting & Diagnostic

.DESCRIPTION
    This script performs a comprehensive set of diagnostic checks for IIS 10.0, covering services,
    application pools, websites, performance counters, logging, network connectivity, SSL bindings, and more.
    It generates a detailed report of the health status of various IIS components and can optionally attempt to
    auto-fix common issues when run with the -Fix switch. This is intended for advanced troubleshooting scenarios
    where a deeper analysis of IIS health is required.

.NOTES
    Run as Administrator on the IIS server.
    Tested on Windows Server 2016/2019/2022 with IIS 10.0.

    Author: Robert Weber

.EXAMPLE
    # Run diagnostics without making changes:
    .\IIS10-Troubleshooting-Diagnostic.ps1

    # Run diagnostics and attempt to auto-fix common issues:
    .\IIS10-Troubleshooting-Diagnostic.ps1 -Fix
#>

param([switch]$Fix)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
function Test-IISService { param([string]$Name); $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue; [pscustomobject]@{Service=$Name; Status=$svc.Status; Running=$svc.Status -eq 'Running'} }

function Get-PerfCounter {
    param([string]$Path)
    try { (Get-Counter -Counter $Path -ErrorAction Stop).CounterSamples[0].CookedValue } catch { "N/A" }
}

function Get-LatestIISLogErrors {
    $logPath = (Get-WebConfiguration -Filter "system.applicationHost/sites/siteDefaults/logFile").directory
    $logPath = $logPath -replace '%SystemDrive%', $env:SystemDrive
    $latestLog = Get-ChildItem "$logPath\*.log" -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $latestLog) { return "No logs found" }
    $errors = Get-Content $latestLog.FullName -Tail 200 | Where-Object { $_ -match ' (4\d{2}|5\d{2}) ' } | Select-Object -First 10
    if ($errors) { $errors -join "`n" } else { "No recent 4xx/5xx errors" }
}

function Get-W3wpAdvanced {
    Get-Process w3wp -ErrorAction SilentlyContinue | Select-Object Id, CPU, WorkingSet64, Threads, Handles,
        @{Name='MemoryMB';Expression={[math]::Round($_.WorkingSet64/1MB,2)}}
}

# =============================================================================
# DIAGNOSTIC CHECKS
# =============================================================================
$diagnostics = @(
    # === BASIC ===
    [pscustomobject]@{Category="Services"; Check="W3SVC / WAS / IISADMIN"; Script={ (Test-IISService "W3SVC").Running -and (Test-IISService "WAS").Running -and (Test-IISService "IISADMIN").Running }; Expected=$true; Fix={ Start-Service W3SVC,WAS,IISADMIN -Force }; Tip="Core IIS services"},
    [pscustomobject]@{Category="AppPools"; Check="All App Pools Started"; Script={ (Get-WebAppPoolState | Where-Object Value -ne "Started").Count -eq 0 }; Expected=$true; Fix={ Get-WebAppPoolState | Restart-WebAppPool }; Tip="Stopped pools cause 503"},
    [pscustomobject]@{Category="Sites"; Check="All Websites Started"; Script={ (Get-Website | Where-Object State -ne "Started").Count -eq 0 }; Expected=$true; Fix={ Get-Website | Start-Website }; Tip="Unreachable sites"},

    # === PERFORMANCE COUNTERS ===
    [pscustomobject]@{Category="Performance"; Check="ASP.NET Requests Queued"; Script={ (Get-PerfCounter "\ASP.NET\Requests Queued") -lt 5 }; Expected=$true; Tip="High queue = backend bottleneck"},
    [pscustomobject]@{Category="Performance"; Check="HTTP Service Current Connections"; Script={ (Get-PerfCounter "\HTTP Service\Current Connections") -lt 1000 }; Expected=$true; Tip="Extremely high connections"},
    [pscustomobject]@{Category="Performance"; Check="w3wp Memory Leak (>2.5 GB)"; Script={ (Get-W3wpAdvanced | Measure-Object -Property MemoryMB -Maximum).Maximum -lt 2500 }; Expected=$true; Tip="Memory leak detected"},

    # === LOG & TRACING ===
    [pscustomobject]@{Category="Logging"; Check="Recent 4xx/5xx in IIS Logs"; Script={ (Get-LatestIISLogErrors) -notmatch '4\d{2}|5\d{2}' }; Expected=$true; Tip="Review logs for root cause"},
    [pscustomobject]@{Category="Tracing"; Check="Failed Request Tracing Enabled"; Script={ (Get-WebConfiguration -Filter "system.webServer/tracing").enabled -eq $false }; Expected=$true; Tip="FRT should be off unless debugging"},

    # === HTTP.sys & CONFIG ===
    [pscustomobject]@{Category="Advanced"; Check="HTTP.sys Service State"; Script={ (netsh http show servicestate | Out-String) -notmatch 'error|critical' }; Expected=$true; Tip="HTTP.sys corruption"},
    [pscustomobject]@{Category="Advanced"; Check="applicationHost.config Health"; Script={ Test-Path "$env:windir\System32\inetsrv\config\applicationHost.config" }; Expected=$true; Tip="Config file missing/corrupt"},

    # === NETWORK CONNECTIVITY DIAGNOSTICS ===
    [pscustomobject]@{Category="Network"; Check="Network Adapters Up"; Script={ (Get-NetAdapter | Where-Object Status -ne "Up").Count -eq 0 }; Expected=$true; Tip="Network interface down"},
    [pscustomobject]@{Category="Network"; Check="Loopback IPv4/IPv6"; Script={
        (Test-NetConnection -ComputerName 127.0.0.1 -Port 80 -WarningAction SilentlyContinue).TcpTestSucceeded -and
        (Test-NetConnection -ComputerName ::1 -Port 80 -WarningAction SilentlyContinue).TcpTestSucceeded
    }; Expected=$true; Tip="Loopback failure"},
    [pscustomobject]@{Category="Network"; Check="IIS Ports Listening (80/443)"; Script={
        $ports = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in 80,443 }
        $ports.Count -ge 2
    }; Expected=$true; Tip="Port 80 or 443 not listening"},
    [pscustomobject]@{Category="Network"; Check="HTTP.sys URL Reservations"; Script={ (netsh http show urlacl | Out-String) -notmatch 'error|critical|not found' }; Expected=$true; Tip="Missing URLACL reservations"},
    [pscustomobject]@{Category="Network"; Check="IIS Firewall Rules Enabled"; Script={
        $rules = Get-NetFirewallRule -DisplayName "*HTTP*" -ErrorAction SilentlyContinue | Where-Object Enabled -eq $true
        $rules.Count -ge 2
    }; Expected=$true; Fix={ netsh advfirewall firewall add rule name="IIS HTTP" dir=in action=allow protocol=TCP localport=80,443 }; Tip="Firewall blocking IIS"},
    [pscustomobject]@{Category="Network"; Check="DNS Resolution for Bindings"; Script={
        $sites = Get-Website
        $fail = 0
        foreach ($site in $sites) { $site.Bindings | ForEach-Object { try { [System.Net.Dns]::GetHostAddresses($_.bindingInformation.Split(':')[0]) } catch { $fail++ } } }
        $fail -eq 0
    }; Expected=$true; Tip="DNS resolution failure for host headers"},
    [pscustomobject]@{Category="Network"; Check="Binding Port Conflicts"; Script={ (Get-NetTCPConnection -State Listen | Group-Object LocalPort | Where-Object Count -gt 1).Count -eq 0 }; Expected=$true; Tip="Port conflict detected"},

    # === SSL & CERTIFICATES ===
    [pscustomobject]@{Category="SSL"; Check="SSL Bindings & Cert Expiry"; Script={
        $badCerts = Get-Website | ForEach-Object { Get-WebBinding -Name $_.Name | Where-Object protocol -eq "https" } | ForEach-Object {
            $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object Thumbprint -eq $_.certificateHash
            if ($cert.NotAfter -lt (Get-Date).AddDays(14)) { $true }
        }
        $badCerts.Count -eq 0
    }; Expected=$true; Tip="Certificates expiring soon"},

    # === PROCESS & RESOURCE ===
    [pscustomobject]@{Category="Advanced"; Check="Orphaned w3wp Processes"; Script={ (Get-W3wpAdvanced).Count -le (Get-WebAppPoolState).Count }; Expected=$true; Tip="Orphaned workers consuming resources"}
)

# =============================================================================
# MAIN EXECUTION
# =============================================================================
$report = @()
$issuesFound = 0

Write-Host "`n=== IIS 10.0 ADVANCED TROUBLESHOOTING DIAGNOSTIC ===" -ForegroundColor Cyan
Write-Host "Running full basic + advanced diagnostics...`n" -ForegroundColor White

foreach ($diag in $diagnostics) {
    $result = & $diag.Script
    $status = if ($result -eq $diag.Expected) { "Healthy" } else { "Issue" }
    if ($status -eq "Issue") { $issuesFound++ }

    $report += [pscustomobject]@{
        Category       = $diag.Category
        Check          = $diag.Check
        Status         = $status
        Current        = $result
        Expected       = $diag.Expected
        Recommendation = if ($status -eq "Issue" -and $Fix -and $diag.Fix) {
            & $diag.Fix | Out-Null; "Auto-Fixed"
        } elseif ($status -eq "Issue") {
            $diag.Tip
        } else { "None" }
    }
}

$report | Sort-Object Category, Check | Format-Table -AutoSize

Write-Host "`n=== ADVANCED DIAGNOSTIC SUMMARY ===" -ForegroundColor Cyan
if ($issuesFound -eq 0) {
    Write-Host "IIS is HEALTHY - No issues detected!" -ForegroundColor Green
} else {
    Write-Host "$issuesFound issue(s) found - review recommendations above" -ForegroundColor Red
}

if ($Fix) {
    Write-Host "`nAuto-fix completed. Restarting IIS..." -ForegroundColor Yellow
    iisreset /restart
} else {
    Write-Host "`nRun with -Fix to automatically remediate common issues." -ForegroundColor Cyan
}

Write-Host "IIS 10.0 Advanced Troubleshooting & Diagnostic is finished." -ForegroundColor White