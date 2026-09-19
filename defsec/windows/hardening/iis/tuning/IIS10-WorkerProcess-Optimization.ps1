<#
.SYNOPSIS
    IIS 10.0 Worker Process Optimization

.DESCRIPTION
    This script checks and optionally remediates key settings for IIS 10.0 Worker Processes,
    based on Microsoft best practices and common hardening guidelines.
    It covers settings such as identity configuration, pinging settings, CPU limits, memory limits, and rapid fail protection.
    The script generates a report of compliance status for each setting and can apply fixes when run with the -Remediate switch.
    All changes are idempotent and follow recommended values for secure and stable IIS operation.

.NOTES
    Run as Administrator on the IIS server.
    Tested on Windows Server 2016/2019/2022 with IIS 10.0.

.EXAMPLE
    # Check compliance without making changes:
    .\IIS10-WorkerProcess-Optimization.ps1

    # Apply recommended settings:
    .\IIS10-WorkerProcess-Optimization.ps1 -Remediate
#>

param([switch]$Remediate)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
function Get-AppPoolSetting {
    param([string]$PoolName, [string]$Property)
    try {
        (Get-ItemProperty -Path "IIS:\AppPools\$PoolName" -Name $Property -ErrorAction Stop).Value
    } catch { $null }
}

function Set-AppPoolSetting {
    param([string]$PoolName, [string]$Property, [object]$Value)
    Set-ItemProperty -Path "IIS:\AppPools\$PoolName" -Name $Property -Value $Value -Force
}

# =============================================================================
# WORKER PROCESS OPTIMIZATION RULES
# =============================================================================
$rules = @(
    # === Security & Identity ===
    [pscustomobject]@{Name="Identity Type"; Property="ProcessModel.IdentityType"; Expected=4},           # 4 = ApplicationPoolIdentity
    [pscustomobject]@{Name="Load User Profile"; Property="ProcessModel.LoadUserProfile"; Expected=$true},

    # === Stability & Availability ===
    [pscustomobject]@{Name="Pinging Enabled"; Property="ProcessModel.PingingEnabled"; Expected=$true},
    [pscustomobject]@{Name="Ping Interval (seconds)"; Property="ProcessModel.PingInterval"; Expected=30},
    [pscustomobject]@{Name="Ping Response Time (seconds)"; Property="ProcessModel.PingResponseTime"; Expected=90},
    [pscustomobject]@{Name="Shutdown Time Limit (minutes)"; Property="ProcessModel.ShutdownTimeLimit"; Expected="00:01:30"},
    [pscustomobject]@{Name="Startup Time Limit (minutes)"; Property="ProcessModel.StartupTimeLimit"; Expected="00:01:30"},

    # === Performance & Resource Limits ===
    [pscustomobject]@{Name="CPU Limit (%)"; Property="Cpu.Limit"; Expected=0},                          # 0 = unlimited (or set per workload)
    [pscustomobject]@{Name="CPU Limit Action"; Property="Cpu.Action"; Expected="KillW3wp"},
    [pscustomobject]@{Name="Private Memory Limit (KB)"; Property="Recycling.PeriodicRestart.PrivateMemory"; Expected=0}, # 0 = unlimited
    [pscustomobject]@{Name="Virtual Memory Limit (KB)"; Property="Recycling.PeriodicRestart.Memory"; Expected=0},

    # === Rapid Fail Protection ===
    [pscustomobject]@{Name="Rapid Fail Protection Enabled"; Property="RapidFailProtection"; Expected=$true},
    [pscustomobject]@{Name="Rapid Fail Max Failures"; Property="RapidFailProtection.MaxFailures"; Expected=5},
    [pscustomobject]@{Name="Rapid Fail Interval"; Property="RapidFailProtection.Interval"; Expected="00:05:00"}
)

# =============================================================================
# MAIN EXECUTION
# =============================================================================
$report = @()
$appPools = Get-ChildItem IIS:\AppPools | Select-Object -ExpandProperty Name

foreach ($pool in $appPools) {
    Write-Host "Processing Application Pool: $pool" -ForegroundColor Cyan

    foreach ($rule in $rules) {
        $status = "Non-Compliant"
        $remediated = $false
        $current = Get-AppPoolSetting -PoolName $pool -Property $rule.Property

        if ($current -eq $rule.Expected) {
            $status = "Compliant"
        } elseif ($Remediate) {
            Set-AppPoolSetting -PoolName $pool -Property $rule.Property -Value $rule.Expected
            $remediated = $true
        }

        $report += [pscustomobject]@{
            AppPool    = $pool
            Setting    = $rule.Name
            Expected   = $rule.Expected
            Current    = if ($null -eq $current) { "Not Set" } else { $current }
            Status     = $status
            Remediated = if ($Remediate -and $remediated) { "Yes" } else { "No" }
        }
    }
}

$report | Sort-Object AppPool, Setting | Format-Table -AutoSize

if ($Remediate) {
    Write-Host "`nIIS 10.0 Worker Process Optimization applied to all Application Pools!" -ForegroundColor Green
    Write-Host "Restarting all Application Pools to apply changes..." -ForegroundColor Yellow
    Restart-WebAppPool -Name "*" -ErrorAction SilentlyContinue
} else {
    Write-Host "`nRun with -Remediate to apply optimizations." -ForegroundColor Cyan
}
Write-Host "IIS 10.0 Worker Process Optimization is finished." -ForegroundColor White