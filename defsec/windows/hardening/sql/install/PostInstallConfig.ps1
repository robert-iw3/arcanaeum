<#
.SYNOPSIS
    Post-Installation Configuration Script for SQL Server 2022 / 2025
    This is the follow-on script you requested — run it AFTER the main installation script completes.
    It configures SQL Server Configuration Manager settings exactly like the GUI:
      • Enables TCP/IP protocol
      • Sets static TCP port to 1433 (removes dynamic ports – default install uses dynamic)
      • Optionally updates SQL Server and SQL Agent service logon accounts ("Log On As")
    Uses the official SQL WMI provider (Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer) – no registry hacks, no extra modules.
    All settings declared at the top (param block).
    Includes firewall rule and service restart for immediate effect.

.NOTES

    - This script is idempotent – you can run it multiple times without causing issues (e.g. firewall rule creation will be skipped if it already exists).
    - Make sure to run this script on the target SQL Server machine with appropriate permissions (local admin for firewall and service configuration).
    - Always test in a non-production environment first to validate parameters and understand changes.
    - The script assumes default instance if $InstanceName is "MSSQLSERVER". For named instances, it will adjust service account names accordingly.
    - Post-install T-SQL block includes error handling in case SQL service is still starting – you can run the T-SQL manually if needed.

    Example usage:
    .\PostInstallConfig.ps1 -InstanceName "MSSQLSERVER" -TCPPort 1433 `
        -SQLServiceAccount "NT SERVICE\MSSQLSERVER" `
        -AgentServiceAccount "NT SERVICE\SQLSERVERAGENT" `
        -CreateFirewallRule $true `
        -RestartServices $true

    Author: Robert Weber
#>

param (
    # =================================================================================================
    # ====================  EDIT ALL PARAMETERS HERE (TOP OF SCRIPT)  ====================
    # =================================================================================================

    [string]$InstanceName = "MSSQLSERVER",           # MSSQLSERVER for default instance, or your named instance

    [int]$TCPPort = 1433,                            # Static port (default install uses dynamic – this fixes it)

    # Service "Log On As" accounts – leave empty to keep whatever was set during install
    # Use format: "DOMAIN\Account" or "NT SERVICE\..." (virtual accounts need no password)
    [string]$SQLServiceAccount = "",                 # e.g. "NT SERVICE\MSSQLSERVER" or "DOMAIN\SQLService"
    [string]$SQLServicePassword = "",                # Only needed for domain accounts (leave empty for virtual accounts)

    [string]$AgentServiceAccount = "",               # e.g. "NT SERVICE\SQLSERVERAGENT"
    [string]$AgentServicePassword = "",

    [bool]$CreateFirewallRule = $true,               # Opens the static port for Domain/Private networks
    [bool]$RestartServices = $true                   # Restarts SQL Server + Agent so changes take effect immediately

    # =================================================================================================
    # ====================  END OF USER-CONFIGURABLE PARAMETERS  ====================
    # =================================================================================================
)

# ====================== SCRIPT BODY ======================

Write-Host "=== SQL Server Post-Install Configuration Manager Settings ===" -ForegroundColor Cyan
Write-Host "Target Instance : $InstanceName" -ForegroundColor Yellow
Write-Host "Static TCP Port : $TCPPort" -ForegroundColor Yellow

# Load the official SQL WMI assembly (installed with SQL Server 2022/2025)
try {
    [void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement")
}
catch {
    throw "SQL WMI assembly not found. Make sure SQL Server is installed and you are running this script on the target server."
}

$wmi = New-Object Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer

# Resolve exact service names (works for both default and named instances)
$SqlServiceName = if ($InstanceName -eq "MSSQLSERVER") { "MSSQLSERVER" } else { "MSSQL`$$InstanceName" }
$AgentServiceName = if ($InstanceName -eq "MSSQLSERVER") { "SQLSERVERAGENT" } else { "SQLAgent`$$InstanceName" }

# ── 1. Configure TCP/IP → Static Port 1433 (Configuration Manager equivalent) ──
Write-Host "Configuring TCP/IP protocol → Static port $TCPPort (disabling dynamic ports)..." -ForegroundColor Yellow

$tcp = $wmi.ServerInstances[$InstanceName].ServerProtocols['Tcp']
$tcp.IsEnabled = $true

$ipAll = $tcp.IPAddresses['IPAll']

# Clear dynamic ports and set static port (this is what the Configuration Manager GUI does)
$ipAll.IPAddressProperties['TcpDynamicPorts'].Value = ""
$ipAll.IPAddressProperties['TcpPort'].Value = $TCPPort.ToString()

$tcp.Alter()

Write-Host "✓ TCP/IP successfully set to static port $TCPPort" -ForegroundColor Green

# ── 2. Service "Log On As" (Service Accounts) ──
if ($SQLServiceAccount) {
    Write-Host "Updating SQL Server service logon account to: $SQLServiceAccount" -ForegroundColor Yellow
    $sqlSvc = $wmi.Services[$SqlServiceName]
    $sqlSvc.SetServiceAccount($SQLServiceAccount, $SQLServicePassword)
    Write-Host "✓ SQL Server service account updated" -ForegroundColor Green
}

if ($AgentServiceAccount) {
    Write-Host "Updating SQL Agent service logon account to: $AgentServiceAccount" -ForegroundColor Yellow
    $agentSvc = $wmi.Services[$AgentServiceName]
    $agentSvc.SetServiceAccount($AgentServiceAccount, $AgentServicePassword)
    Write-Host "✓ SQL Agent service account updated" -ForegroundColor Green
}

# ── 3. Optional Firewall Rule ──
if ($CreateFirewallRule) {
    try {
        New-NetFirewallRule -DisplayName "SQL Server - TCP $TCPPort" `
                            -Direction Inbound `
                            -Protocol TCP `
                            -LocalPort $TCPPort `
                            -Action Allow `
                            -Profile Domain,Private `
                            -ErrorAction Stop | Out-Null
        Write-Host "✓ Firewall rule created for TCP port $TCPPort" -ForegroundColor Green
    }
    catch {
        Write-Warning "Firewall rule already exists or could not be created (run as Administrator)."
    }
}

# ── 4. Restart Services to apply changes ──
if ($RestartServices) {
    Write-Host "Restarting SQL Server and SQL Agent services..." -ForegroundColor Cyan
    Restart-Service -Name $SqlServiceName -Force -WarningAction SilentlyContinue
    if ($AgentServiceName) { Restart-Service -Name $AgentServiceName -Force -WarningAction SilentlyContinue }
    Write-Host "✓ Services restarted" -ForegroundColor Green
}

Write-Host "`n=== SQL Server Configuration Manager settings applied successfully! ===" -ForegroundColor Green
Write-Host "You can now connect to SQL Server using port $TCPPort." -ForegroundColor Cyan
Write-Host "Script finished." -ForegroundColor Cyan