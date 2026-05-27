<#
.SYNOPSIS
    IIS 10.0 Application Pool Tuning


.DESCRIPTION
    This script checks and optionally remediates key performance and stability settings for IIS 10.0 Application Pools,
    based on Microsoft best practices and common hardening guidelines.
    It covers settings such as queue length, idle timeout, recycling intervals, memory limits, CPU limits, rapid fail protection,
    identity configuration, and pinging settings.
    The script generates a report of compliance status for each setting and can apply fixes when run with the -Remediate switch.
    All changes are idempotent and follow recommended values for secure and stable IIS operation.

.NOTES
    Run as Administrator on the IIS server.
    Tested on Windows Server 2016/2019/2022 with IIS 10.0.

    Author: Robert Weber

.EXAMPLE
    # Check compliance without making changes:
    .\IIS10-AppPool-Tuning.ps1

    # Apply recommended settings:
    .\IIS10-AppPool-Tuning.ps1 -Remediate
#>

param([switch]$Remediate)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
function Get-AppPoolSetting {
    param([string]$PoolName, [string]$Property)
    try {
        $value = (Get-ItemProperty -Path "IIS:\AppPools\$PoolName" -Name $Property -ErrorAction Stop).Value
        if ($value -is [Microsoft.IIs.PowerShell.Framework.ConfigurationElement]) { $value } else { $value }
    } catch { $null }
}

function Set-AppPoolSetting {
    param([string]$PoolName, [string]$Property, [object]$Value)
    Set-ItemProperty -Path "IIS:\AppPools\$PoolName" -Name $Property -Value $Value -Force
}

# =============================================================================
# TUNING RULES ARRAY
# =============================================================================
$rules = @(
    # Performance & Stability
    [pscustomobject]@{Name="Queue Length"; Property="QueueLength"; Expected=1000},
    [pscustomobject]@{Name="Idle Timeout (minutes)"; Property="IdleTimeout"; Expected="00:20:00"},
    [pscustomobject]@{Name="Regular Time Interval (minutes)"; Property="Recycling.PeriodicRestart.TimeInterval"; Expected=1740}, # 29 hours - prevents midnight recycle
    [pscustomobject]@{Name="Private Memory Limit (KB)"; Property="Recycling.PeriodicRestart.PrivateMemory"; Expected=0}, # 0 = unlimited
    [pscustomobject]@{Name="CPU Limit (%)"; Property="Cpu.Limit"; Expected=0},
    [pscustomobject]@{Name="CPU Limit Action"; Property="Cpu.Action"; Expected="KillW3wp"},
    [pscustomobject]@{Name="Rapid Fail Protection - Enabled"; Property="RapidFailProtection"; Expected=$true},
    [pscustomobject]@{Name="Rapid Fail Protection - Max Failures"; Property="RapidFailProtection.MaxFailures"; Expected=5},
    [pscustomobject]@{Name="Rapid Fail Protection - Interval"; Property="RapidFailProtection.Interval"; Expected="00:05:00"},

    # Security & Best Practices
    [pscustomobject]@{Name="Load User Profile"; Property="ProcessModel.LoadUserProfile"; Expected=$true},
    [pscustomobject]@{Name="Identity - ApplicationPoolIdentity"; Property="ProcessModel.IdentityType"; Expected=4},
    [pscustomobject]@{Name="Pinging Enabled"; Property="ProcessModel.PingingEnabled"; Expected=$true},
    [pscustomobject]@{Name="Ping Interval (seconds)"; Property="ProcessModel.PingInterval"; Expected=30},
    [pscustomobject]@{Name="Shutdown Time Limit (minutes)"; Property="ProcessModel.ShutdownTimeLimit"; Expected="00:01:30"},
    [pscustomobject]@{Name="Startup Time Limit (minutes)"; Property="ProcessModel.StartupTimeLimit"; Expected="00:01:30"}
)

# =============================================================================
# MAIN EXECUTION
# =============================================================================
$report = @()
$appPools = Get-ChildItem IIS:\AppPools | Select-Object -ExpandProperty Name

foreach ($pool in $appPools) {
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
            Current    = $current
            Status     = $status
            Remediated = if ($Remediate -and $remediated) { "Yes" } else { "No" }
        }
    }
}

$report | Sort-Object AppPool, Setting | Format-Table -AutoSize

if ($Remediate) {
    Write-Host "`nIIS 10.0 Application Pool Tuning complete!" -ForegroundColor Green
    Write-Host "Restarting all Application Pools to apply changes..." -ForegroundColor Yellow
    Restart-WebAppPool -Name "*" -ErrorAction SilentlyContinue
} else {
    Write-Host "`nRun with -Remediate to apply tuning." -ForegroundColor Cyan
}
Write-Host "IIS 10.0 Application Pool Tuning is finished." -ForegroundColor White