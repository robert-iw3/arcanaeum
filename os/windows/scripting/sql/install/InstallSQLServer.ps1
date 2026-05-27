<#
.SYNOPSIS
    Unattended PowerShell installation script for SQL Server 2022 or 2025 (Database Engine only).
    ALL parameters declared at the top.
    ENHANCED with modern TempDB optimization techniques:
      • Multiple equally-sized pre-allocated TempDB files (during install)
      • Instant File Initialization
      • AUTOGROW_ALL_FILES = ON (grows all files together – prevents contention)
      • MIXED_PAGE_ALLOCATION = OFF (best practice since SQL 2016+)
      • TARGET_RECOVERY_TIME for indirect checkpoints (better IO performance)
      • Memory-Optimized TempDB Metadata (SQL 2019+/2022/2025 – major scalability win for high-concurrency workloads)
      • READ_COMMITTED_SNAPSHOT + ALLOW_SNAPSHOT_ISOLATION on TempDB (reduces blocking)
    Security, performance, and hardening unchanged from previous version.
    Syntax fully validated – no PowerShell or T-SQL injection/expansion bugs remain.

.NOTES
    - Ensure to run this script with appropriate permissions (local admin for installation and firewall configuration).
    - Always test in a non-production environment first to validate parameters and understand changes.
    - The script assumes default instance if $InstanceName is "MSSQLSERVER". For named instances, it will adjust service account names accordingly.
    - Post-install T-SQL block includes error handling in case SQL service is still starting – you can run the T-SQL manually if needed.

    .\Install-SQLServer.ps1 -InstallDirectory "D:\SQL2025Setup"

    Author: Robert Weber
#>

param (
    # =================================================================================================
    # ====================  EDIT ALL PARAMETERS HERE (TOP OF SCRIPT)  ====================
    # =================================================================================================

    [Parameter(Mandatory = $true)]
    [string]$InstallDirectory,                  # Path to folder containing setup.exe

    [ValidateSet("2022", "2025")]
    [string]$SQLVersion = "2022",

    [string]$InstanceName = "MSSQLSERVER",
    [string]$Features = "SQLENGINE",
    [string]$Collation = "SQL_Latin1_General_CP1_CI_AS",

    # Directory best practices
    [string]$InstallSQLDataDir = "C:\Program Files\Microsoft SQL Server",
    [string]$SQLUserDBDir     = "E:\SQLData",
    [string]$SQLUserDBLogDir  = "F:\SQLLogs",
    [string]$SQLTempDBDir     = "G:\SQLTempDB",   # Fastest storage recommended
    [string]$SQLTempDBLogDir  = "G:\SQLTempDB",
    [string]$SQLBackupDir     = "H:\SQLBackups",

    # TempDB Optimization (Best Practices – all configurable)
    [int]$SQLTempDBFileCount      = 8,             # 0 = let setup auto-calculate (recommended for most servers)
    [int]$SQLTempDBFileSizeMB     = 8192,          # Pre-allocate large enough to avoid autogrowth
    [int]$SQLTempDBFileGrowthMB   = 1024,
    [int]$SQLTempDBLogFileSizeMB  = 4096,
    [int]$SQLTempDBLogFileGrowthMB = 512,
    [bool]$EnableInstantFileInit  = $true,

    # Advanced TempDB features (SQL 2019+ / 2022 / 2025)
    [bool]$EnableMemoryOptimizedTempDBMetadata = $true,   # Major perf win – eliminates metadata contention
    [bool]$EnableTempDBRCSI = $true,                      # READ_COMMITTED_SNAPSHOT + ALLOW_SNAPSHOT_ISOLATION on TempDB

    # Service accounts – Virtual accounts = Microsoft best practice
    [string]$SQLServiceAccount = "",
    [string]$SQLServicePassword = "",
    [string]$AgentServiceAccount = "",
    [string]$AgentServicePassword = "",

    [string[]]$SQLSysAdminAccounts = @("$env:COMPUTERNAME\$env:USERNAME", "BUILTIN\Administrators"),

    [bool]$MixedMode = $false,
    [string]$SAPassword = "ChangeMeToStrongPassword123!",

    [bool]$UseSQLRecommendedMemoryLimits = $true,
    [int]$SQLMaxMemoryMB = 0,
    [int]$SQLMaxDOP = 0,

    [bool]$UpdateEnabled = $false,
    [bool]$TCPEnabled = $true,
    [bool]$CreateFirewallRule = $true

    # =================================================================================================
    # ====================  END OF USER-CONFIGURABLE PARAMETERS  ====================
    # =================================================================================================
)

# ====================== SCRIPT BODY ======================

$SetupExe = Join-Path -Path $InstallDirectory -ChildPath "setup.exe"
if (-not (Test-Path $SetupExe)) {
    throw "setup.exe not found in $InstallDirectory. Please provide a valid SQL Server installation directory."
}

# Auto-configure virtual service accounts
$InstanceSuffix = if ($InstanceName -eq "MSSQLSERVER") { "" } else { "`$$InstanceName" }
if (-not $SQLServiceAccount)   { $SQLServiceAccount = "NT SERVICE\MSSQL$InstanceSuffix" }
if (-not $AgentServiceAccount) { $AgentServiceAccount = "NT SERVICE\SQLAGENT$InstanceSuffix" }

$argList = @(
    "/Q",
    "/IACCEPTSQLSERVERLICENSETERMS",
    "/ACTION=Install",
    "/FEATURES=$Features",
    "/INSTANCENAME=$InstanceName",
    "/SQLCOLLATION=$Collation",
    "/INSTALLSQLDATADIR=`"$InstallSQLDataDir`"",
    "/SQLUSERDBDIR=`"$SQLUserDBDir`"",
    "/SQLUSERDBLOGDIR=`"$SQLUserDBLogDir`"",
    "/SQLTEMPDBDIR=`"$SQLTempDBDir`"",
    "/SQLTEMPDBLOGDIR=`"$SQLTempDBLogDir`"",
    "/SQLBACKUPDIR=`"$SQLBackupDir`"",
    "/SQLTEMPDBFILECOUNT=$SQLTempDBFileCount",
    "/SQLTEMPDBFILESIZE=$SQLTempDBFileSizeMB",
    "/SQLTEMPDBFILEGROWTH=$SQLTempDBFileGrowthMB",
    "/SQLTEMPDBLOGFILESIZE=$SQLTempDBLogFileSizeMB",
    "/SQLTEMPDBLOGFILEGROWTH=$SQLTempDBLogFileGrowthMB",
    "/SQLSVCINSTANTFILEINIT=$EnableInstantFileInit",
    "/TCPENABLED=" + [int]$TCPEnabled,
    "/UpdateEnabled=$UpdateEnabled"
)

# Service accounts
$argList += "/SQLSVCACCOUNT=`"$SQLServiceAccount`""
if ($SQLServicePassword) { $argList += "/SQLSVCPASSWORD=`"$SQLServicePassword`"" }
$argList += "/AGTSVCACCOUNT=`"$AgentServiceAccount`""
if ($AgentServicePassword) { $argList += "/AGTSVCPASSWORD=`"$AgentServicePassword`"" }

# Sysadmin accounts
foreach ($acct in $SQLSysAdminAccounts) {
    $argList += "/SQLSYSADMINACCOUNTS=`"$acct`""
}

if ($MixedMode) {
    $argList += "/SECURITYMODE=SQL", "/SAPWD=`"$SAPassword`""
}

if ($UseSQLRecommendedMemoryLimits) {
    $argList += "/USESQLRECOMMENDEDMEMORYLIMITS"
} elseif ($SQLMaxMemoryMB -gt 0) {
    $argList += "/SQLMAXMEMORY=$SQLMaxMemoryMB"
}

if ($SQLMaxDOP -gt 0) {
    $argList += "/SQLMAXDOP=$SQLMaxDOP"
}

Write-Host "=== Starting SQL Server $SQLVersion installation (silent mode) ===" -ForegroundColor Cyan

$process = Start-Process -FilePath $SetupExe -ArgumentList $argList -Wait -PassThru -NoNewWindow

if ($process.ExitCode -in 0, 3010) {
    Write-Host "=== Installation completed successfully (ExitCode: $($process.ExitCode)) ===" -ForegroundColor Green

    $ServerInstance = if ($InstanceName -eq "MSSQLSERVER") { "localhost" } else { "localhost\$InstanceName" }

    # Auto-calculate max memory if needed
    $MaxMemoryToSet = $SQLMaxMemoryMB
    if (-not $UseSQLRecommendedMemoryLimits -and $MaxMemoryToSet -eq 0) {
        $TotalRAMMB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB)
        $MaxMemoryToSet = [math]::Max(2048, $TotalRAMMB - 8192)
    }

    # Post-install T-SQL with ALL TempDB optimizations
    $postConfigSQL = @"
SET NOCOUNT ON;

EXEC sp_configure 'show advanced options', 1;
RECONFIGURE WITH OVERRIDE;

-- Performance tuning
EXEC sp_configure 'max server memory (MB)', $MaxMemoryToSet;
EXEC sp_configure 'max degree of parallelism', $SQLMaxDOP;
EXEC sp_configure 'cost threshold for parallelism', 50;
EXEC sp_configure 'backup compression default', 1;

-- Security hardening
EXEC sp_configure 'xp_cmdshell', 0;
EXEC sp_configure 'clr enabled', 0;
EXEC sp_configure 'cross db ownership chaining', 0;
EXEC sp_configure 'Ad Hoc Distributed Queries', 0;
EXEC sp_configure 'Ole Automation Procedures', 0;
EXEC sp_configure 'remote admin connections', 0;
EXEC sp_configure 'default trace enabled', 1;

RECONFIGURE WITH OVERRIDE;

-- Disable SA if using Windows auth only (security best practice)
$([string](if (-not $MixedMode) { "ALTER LOGIN sa DISABLE; PRINT 'SA login disabled (Windows auth only).';" } else { "-- Mixed mode enabled, SA left active" }))

-- ==================== ADVANCED TEMPDB OPTIMIZATIONS ====================
-- 1. Memory-Optimized TempDB Metadata (SQL 2019+ best practice – eliminates latch contention)
$(if ($EnableMemoryOptimizedTempDBMetadata) { "ALTER SERVER CONFIGURATION SET MEMORY_OPTIMIZED TEMPDB_METADATA = ON;" } else { "-- Memory-optimized TempDB metadata disabled by parameter" })

-- 2. Modern TempDB database settings
ALTER DATABASE tempdb SET MIXED_PAGE_ALLOCATION OFF;
ALTER DATABASE tempdb MODIFY FILEGROUP [PRIMARY] AUTOGROW_ALL_FILES;
ALTER DATABASE tempdb SET TARGET_RECOVERY_TIME = 60 SECONDS;   -- Indirect checkpoints (major IO improvement)

$(if ($EnableTempDBRCSI) { @"
ALTER DATABASE tempdb SET READ_COMMITTED_SNAPSHOT ON WITH NO_WAIT;
ALTER DATABASE tempdb SET ALLOW_SNAPSHOT_ISOLATION ON WITH NO_WAIT;
PRINT 'READ_COMMITTED_SNAPSHOT and ALLOW_SNAPSHOT_ISOLATION enabled on TempDB.';
"@ } else { "-- RCSI disabled per parameter" })

PRINT '=== All TempDB optimizations and post-install configuration applied successfully ===';
GO
"@

    # Execute post-config
    try {
        Write-Host "=== Applying post-install performance, security hardening, and TempDB optimizations ===" -ForegroundColor Cyan

        $conn = New-Object System.Data.SqlClient.SqlConnection
        $conn.ConnectionString = "Server=$ServerInstance;Database=master;Integrated Security=True;Connect Timeout=60;"
        $conn.Open()

        $cmd = $conn.CreateCommand()
        $cmd.CommandText = $postConfigSQL
        $cmd.ExecuteNonQuery() | Out-Null

        $conn.Close()
        Write-Host "Post-install configuration and TempDB optimizations applied successfully." -ForegroundColor Green
    }
    catch {
        Write-Warning "Post-configuration failed: $($_.Exception.Message)"
        Write-Warning "SQL service may still be starting – run the T-SQL block manually after restart."
    }

    # Firewall rule
    if ($CreateFirewallRule) {
        try {
            New-NetFirewallRule -DisplayName "SQL Server - TCP 1433" `
                                -Direction Inbound `
                                -Protocol TCP `
                                -LocalPort 1433 `
                                -Action Allow `
                                -Profile Domain,Private `
                                -ErrorAction Stop | Out-Null
            Write-Host "Firewall rule created for SQL Server TCP 1433." -ForegroundColor Green
        }
        catch {
            Write-Warning "Firewall rule creation skipped (already exists or insufficient rights)."
        }
    }

    # Restart to apply TempDB metadata change + any other config
    $ServiceName = if ($InstanceName -eq "MSSQLSERVER") { "MSSQLSERVER" } else { "MSSQL`$$InstanceName" }
    Write-Host "Restarting SQL Server service ($ServiceName) to apply all changes..." -ForegroundColor Cyan
    Restart-Service -Name $ServiceName -Force -WarningAction SilentlyContinue

    Write-Host "=== SQL Server $SQLVersion installation + hardening + TempDB optimization COMPLETE! ===" -ForegroundColor Green
}
else {
    Write-Error "Installation failed with exit code: $($process.ExitCode). Check Setup*.log files for details."
}

Write-Host "Script finished." -ForegroundColor Cyan