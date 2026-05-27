<#
.SYNOPSIS
    Fully automated SQL Server 2022 backend for Trellix ePO 5.10.0 (split-server)

.DESCRIPTION
    This script performs a silent installation of SQL Server 2022 with performance optimizations tailored for
    Trellix ePO 5.10.0. It configures storage best practices, TempDB optimizations, and security hardening.
    After installation, it applies recommended SQL settings and creates a firewall rule for SQL Server.

.PARAMETER SQLInstallDirectory
    The directory where SQL Server setup.exe is located.
.PARAMETER SQLInstanceName
    The name of the SQL instance to install (default is MSSQLSERVER for default instance).
.PARAMETER SQLDataDir
    Directory for SQL user databases.
.PARAMETER SQLLogDir
    Directory for SQL transaction logs.
.PARAMETER SQLTempDBDir
    Directory for TempDB data files (should be on fastest storage).
.PARAMETER SQLTempDBLogDir
    Directory for TempDB log files (should be on fastest storage).
.PARAMETER SQLBackupDir
    Directory for SQL backups.
.PARAMETER TempDBFileCount
    Number of TempDB data files (recommended 1 per CPU core, up to 8 for most workloads).
.PARAMETER TempDBFileSizeMB
    Initial size of TempDB data files in MB.
.PARAMETER TempDBFileGrowthMB
    Growth increment for TempDB data files in MB.
.PARAMETER EnableMemoryOptimizedTempDB
    Whether to enable Memory-Optimized TempDB Metadata (best for temp object performance).
.PARAMETER EnableTempDBRCSI
    Whether to enable Read Committed Snapshot Isolation for TempDB (reduces contention).
.PARAMETER CreateFirewallRule
    Whether to create a Windows Firewall rule for SQL Server (port 1433).

.EXAMPLE
    .\Install-SQLBackend-For-EPO.ps1 -SQLInstallDirectory "C:\SQL2022Setup" -SQLInstanceName "MSSQLSERVER" \
    -SQLDataDir "E:\SQLData" -SQLLogDir "F:\SQLLogs" -SQLTempDBDir "G:\SQLTempDB" -SQLTempDBLogDir "G:\SQLTempDB" \
    -SQLBackupDir "H:\SQLBackups" -TempDBFileCount 8 -TempDBFileSizeMB 8192 -TempDBFileGrowthMB 1024 \
    -EnableMemoryOptimizedTempDB $true -EnableTempDBRCSI $true -CreateFirewallRule $true

.NOTES
    Author: Robert Weber
#>

param (
    # ====================== EDIT THESE ONLY ======================
    [string]$SQLInstallDirectory = "C:\SQL2022Setup",
    [string]$SQLInstanceName     = "MSSQLSERVER",

    # Storage (use fastest disks for TempDB)
    [string]$SQLDataDir          = "E:\SQLData",
    [string]$SQLLogDir           = "F:\SQLLogs",
    [string]$SQLTempDBDir        = "G:\SQLTempDB",
    [string]$SQLTempDBLogDir     = "G:\SQLTempDB",
    [string]$SQLBackupDir        = "H:\SQLBackups",

    # TempDB - Trellix recommended
    [int]$TempDBFileCount        = 8,
    [int]$TempDBFileSizeMB       = 8192,
    [int]$TempDBFileGrowthMB     = 1024,

    [bool]$EnableMemoryOptimizedTempDB = $true,
    [bool]$EnableTempDBRCSI      = $true,
    [bool]$CreateFirewallRule    = $true
    # ============================================================
)

$ErrorActionPreference = "Stop"
$LogFile = "$env:SYSTEMDRIVE\ePO-Install\SQL-Install.log"
New-Item -Path "$env:SYSTEMDRIVE\ePO-Install" -ItemType Directory -Force | Out-Null

function Write-Log { param([string]$Msg) "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - $Msg" | Tee-Object -FilePath $LogFile -Append }

Write-Log "=== Starting SQL Server 2022 Installation for Trellix ePO 5.10.0 ==="

# Pre-checks
if (-not (Test-Path "$SQLInstallDirectory\setup.exe")) { throw "setup.exe not found!" }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrators")) { throw "Run as Administrator" }

# Silent install arguments
$argList = @(
    "/Q", "/IACCEPTSQLSERVERLICENSETERMS", "/ACTION=Install", "/FEATURES=SQLENGINE",
    "/INSTANCENAME=$SQLInstanceName", "/SQLCOLLATION=SQL_Latin1_General_CP1_CI_AS",
    "/INSTALLSQLDATADIR=`"$SQLInstallDirectory`"", "/SQLUSERDBDIR=`"$SQLDataDir`"",
    "/SQLUSERDBLOGDIR=`"$SQLLogDir`"", "/SQLTEMPDBDIR=`"$SQLTempDBDir`"",
    "/SQLTEMPDBLOGDIR=`"$SQLTempDBLogDir`"", "/SQLBACKUPDIR=`"$SQLBackupDir`"",
    "/SQLTEMPDBFILECOUNT=$TempDBFileCount", "/SQLTEMPDBFILESIZE=$TempDBFileSizeMB",
    "/SQLTEMPDBFILEGROWTH=$TempDBFileGrowthMB", "/SQLTEMPDBLOGFILESIZE=4096",
    "/SQLTEMPDBLOGFILEGROWTH=512", "/SQLSVCINSTANTFILEINIT=1", "/TCPENABLED=1"
)

$InstanceSuffix = if ($SQLInstanceName -eq "MSSQLSERVER") { "" } else { "`$$SQLInstanceName" }
$argList += "/SQLSVCACCOUNT=`"NT SERVICE\MSSQL$InstanceSuffix`""
$argList += "/AGTSVCACCOUNT=`"NT SERVICE\SQLAGENT$InstanceSuffix`""
$argList += "/SQLSYSADMINACCOUNTS=`"BUILTIN\Administrators`""

Write-Log "Launching silent SQL installation..."
$process = Start-Process -FilePath "$SQLInstallDirectory\setup.exe" -ArgumentList $argList -Wait -PassThru

if ($process.ExitCode -notin 0,3010) { throw "SQL install failed (ExitCode $($process.ExitCode))" }

Write-Log "SQL Server installed successfully. Applying Trellix optimizations..."

# Post-install SQL configuration
$ServerInstance = if ($SQLInstanceName -eq "MSSQLSERVER") { "localhost" } else { "localhost\$SQLInstanceName" }

$postSQL = @"
SET NOCOUNT ON;
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'max server memory (MB)',0; RECONFIGURE;
EXEC sp_configure 'backup compression default',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',0; RECONFIGURE;
ALTER DATABASE tempdb SET MIXED_PAGE_ALLOCATION OFF;
ALTER DATABASE tempdb MODIFY FILEGROUP [PRIMARY] AUTOGROW_ALL_FILES;
$(if ($EnableMemoryOptimizedTempDB) { "ALTER SERVER CONFIGURATION SET MEMORY_OPTIMIZED TEMPDB_METADATA = ON;" })
$(if ($EnableTempDBRCSI) { "ALTER DATABASE tempdb SET READ_COMMITTED_SNAPSHOT ON WITH NO_WAIT;" })
PRINT 'SQL Backend fully optimized for ePO 5.10.0';
GO
"@

Invoke-Sqlcmd -ServerInstance $ServerInstance -Query $postSQL -Database master

# Set recovery model (Trellix requirement)
Invoke-Sqlcmd -ServerInstance $ServerInstance -Query "ALTER DATABASE tempdb SET RECOVERY FULL WITH NO_WAIT;" -Database master
Write-Log "Recovery model set to FULL"

# Firewall
if ($CreateFirewallRule) {
    New-NetFirewallRule -DisplayName "SQL Server 1433 (ePO)" -Direction Inbound -Protocol TCP -LocalPort 1433 -Action Allow | Out-Null
    Write-Log "Firewall rule created for SQL port 1433"
}

Restart-Service -Name (if ($SQLInstanceName -eq "MSSQLSERVER") { "MSSQLSERVER" } else { "MSSQL`$$SQLInstanceName" }) -Force

Write-Log "=== SQL Backend Installation COMPLETE & Optimized for ePO 5.10.0 ==="
Write-Host "SQL installation finished! Log: $LogFile" -ForegroundColor Green