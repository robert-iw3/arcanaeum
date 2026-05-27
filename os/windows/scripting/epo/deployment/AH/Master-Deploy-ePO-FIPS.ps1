<#
.SYNOPSIS
    Master Orchestrator - Trellix ePO 5.10.0 FIPS + Multi-AH Deployment

.DESCRIPTION
    This master deployment script automates the installation of Trellix ePO 5.10
    in a split-server configuration with FIPS compliance, along with multiple Agent Handlers.
    It performs the following steps:
    1. Deploys SQL Server backend on a remote SQL server using the Install-SQLBackend script.
    2. Deploys ePO server in FIPS mode using the Install-EPO-FIPS-SplitServer script.
    3. Deploys and optimizes multiple Agent Handlers on specified hosts.
    After running this script, you will need to complete the installation through the ePO setup wizard, providing the SQL server details.

.PARAMETER SQLServerFQDN
    The fully qualified domain name of the remote SQL server hosting the ePO database.
.PARAMETER SQLInstanceName
    The name of the SQL instance (default is MSSQLSERVER for default instance).
.PARAMETER EpoDatabaseName
    The name of the ePO database to create/use on the SQL server.
.PARAMETER EPOServerFQDN
    The fully qualified domain name of the ePO server to install.
.PARAMETER EPOInstallerPath
    The directory where the ePO setup.exe is located.
.PARAMETER AgentHandlers
    An array of hostnames for the Agent Handlers to deploy.
.PARAMETER SQLAuthMode
    Authentication mode to use for SQL connection (Windows or SQL).
.PARAMETER EnableFIPS
    Whether to enable Windows FIPS mode (recommended for full compliance).
.PARAMETER CreateFirewallRules
    Whether to create Windows Firewall rules for ePO communication (ports 80, 443, 8443, 1433).

.EXAMPLE
    .\Master-Deploy-ePO-FIPS.ps1 -SQLServerFQDN "sql01.contoso.local" -SQLInstanceName "MSSQLSERVER" \
    -EpoDatabaseName "ePO" -EPOServerFQDN "epo.contoso.local" -EPOInstallerPath "C:\Temp\ePO_5.10.0" \
    -AgentHandlers @("ah01.contoso.local", "ah02.contoso.local") -SQLAuthMode "Windows" \
    -EnableFIPS $true -CreateFirewallRules $true

.NOTES
    Author: Robert Weber
    Run as administrator or with sufficient permissions.
    Test in non-production first.
    Ensure PowerShell remoting is enabled and properly configured on target servers.
    Paths for agent (e.g., McAfee\Agent) may vary; Trellix often retains McAfee paths.
    For large-scale deployment, consider using ePO deployment tasks for AHs after initial setup.
    Avoid running on systems with insufficient space or during high-load periods.
#>

param (
    # ====================== EDIT THESE ONLY ======================
    [string]$SQLServerFQDN      = "sql01.contoso.local",
    [string]$SQLInstanceName    = "MSSQLSERVER",
    [string]$EpoDatabaseName    = "ePO",

    [string]$EPOServerFQDN      = "epo.contoso.local",
    [string]$EPOInstallerPath   = "C:\Temp\ePO_5.10.0",

    # Agent Handlers (add as many as needed)
    [array]$AgentHandlers = @(
        "ah01.contoso.local",
        "ah02.contoso.local"
    ),

    [string]$SQLAuthMode        = "Windows",
    [bool]$EnableFIPS           = $true,
    [bool]$CreateFirewallRules  = $true
    # ============================================================
)

$ErrorActionPreference = "Stop"
$LogFile = "$env:SYSTEMDRIVE\ePO-Deploy\Master-Log.log"
New-Item -Path "$env:SYSTEMDRIVE\ePO-Deploy" -ItemType Directory -Force | Out-Null

function Write-Log { param([string]$Msg) "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - $Msg" | Tee-Object -FilePath $LogFile -Append }

Write-Log "=== MASTER DEPLOYMENT START - ePO 5.10.0 FIPS + Multi-AH ==="

# 1. SQL Backend (remote execution)
Write-Log "Deploying SQL Backend on $SQLServerFQDN..."
Invoke-Command -ComputerName $SQLServerFQDN -ScriptBlock {
    param($params)
    & "C:\Temp\Install-SQLBackend-For-EPO.ps1" @params
} -ArgumentList @{
    SQLInstallDirectory = "C:\SQL2022Setup"
    SQLInstanceName     = $SQLInstanceName
    SQLDataDir          = "E:\SQLData"
    SQLLogDir           = "F:\SQLLogs"
    SQLTempDBDir        = "G:\SQLTempDB"
    SQLTempDBLogDir     = "G:\SQLTempDB"
    SQLBackupDir        = "H:\SQLBackups"
    TempDBFileCount     = 8
    TempDBFileSizeMB    = 8192
    TempDBFileGrowthMB  = 1024
    EnableMemoryOptimizedTempDB = $true
    EnableTempDBRCSI    = $true
}

# 2. ePO Server (FIPS)
Write-Log "Deploying ePO on $EPOServerFQDN..."
Invoke-Command -ComputerName $EPOServerFQDN -ScriptBlock {
    param($params)
    & "C:\Temp\Install-EPO-FIPS-SplitServer.ps1" @params
} -ArgumentList @{
    EPOInstallerPath   = $EPOInstallerPath
    SQLServerFQDN      = $SQLServerFQDN
    SQLInstanceName    = $SQLInstanceName
    EpoDatabaseName    = $EpoDatabaseName
    SQLAuthMode        = $SQLAuthMode
    EnableWindowsFIPS  = $EnableFIPS
    CreateFirewallRules= $CreateFirewallRules
}

# 3. Deploy & Optimize Multiple Agent Handlers
foreach ($ah in $AgentHandlers) {
    Write-Log "Deploying Agent Handler on $ah..."
    Invoke-Command -ComputerName $ah -ScriptBlock {
        param($ePOInstallerPath)
        # Install AH silently (same installer as ePO)
        $SetupExe = Join-Path $ePOInstallerPath "setup.exe"
        Start-Process -FilePath $SetupExe -ArgumentList "INSTALLAH=1 ENABLEFIPSMODE=1" -Wait -NoNewWindow

        # Optimization
        Restart-Service -Name "Trellix Agent Handler" -Force
        Restart-Service -Name "Trellix Event Parser" -Force

        # FIPS verification
        $ini = Get-Content "C:\Program Files (x86)\Trellix\ePolicy Orchestrator\DB\server.ini"
        if ($ini -match "FipsMode=1") { Write-Output "AH FIPS ENABLED ✓" }
    } -ArgumentList $EPOInstallerPath
}

Write-Log "=== MASTER DEPLOYMENT COMPLETE ==="
Write-Host "Full ePO + Multi-AH deployment finished!" -ForegroundColor Green
Write-Host "Next: Log into ePO console → Configuration → Agent Handlers → Add the new AHs to a Load Balancer Group." -ForegroundColor Yellow