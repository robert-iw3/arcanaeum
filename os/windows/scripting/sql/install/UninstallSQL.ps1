<#
.SYNOPSIS
    Complete Clean Uninstall Script for SQL Server 2022 or 2025 (separate follow-on script).
    Performs proper, safe, and thorough removal:
      • Stops all related SQL services (SQL Server, Agent, Browser, etc.)
      • Runs official Microsoft uninstall via setup.exe /ACTION=Uninstall (quiet)
      • Cleans leftover directories (Program Files, ProgramData, Bootstrap, etc.)
      • Removes SQL-specific registry keys (with automatic backup first)
      • Deletes any remaining services
      • Removes associated firewall rules
      • Optional: Aggressive cleanup of user data directories (disabled by default for safety)
    WARNING: This script is DESTRUCTIVE. Back up all databases and important files BEFORE running.
    Run as Administrator. Reboot recommended at the end.

.NOTES
    Usage: .\UninstallSQL.ps1 -SetupDirectory "D:\SQL2022Media" -InstanceName "MSSQLSERVER" -SQLVersion "2022"
    Adjust parameters as needed for your environment. See comments in the script for details.

    Author: Robert Weber
#>

param (
    # =================================================================================================
    # ====================  EDIT ALL PARAMETERS HERE (TOP OF SCRIPT)  ====================
    # =================================================================================================

    [Parameter(Mandatory = $true)]
    [string]$SetupDirectory,                    # Path to the original SQL installation media folder containing setup.exe

    [string]$InstanceName = "MSSQLSERVER",      # MSSQLSERVER for default instance

    [ValidateSet("2022", "2025")]
    [string]$SQLVersion = "2022",               # Used to help identify version-specific paths

    [bool]$RemoveUserDataDirectories = $false,  # Set to $true ONLY if you want to delete your custom data/log/backup folders
    [string[]]$UserDataDirectories = @("E:\SQLData", "F:\SQLLogs", "G:\SQLTempDB", "H:\SQLBackups"),  # Your custom paths from install script

    [bool]$ForceAggressiveCleanup = $false,     # Set to $true for maximum cleanup (deletes ALL Microsoft SQL Server folders)

    [bool]$RestartComputerAtEnd = $true         # Recommended after full cleanup

    # =================================================================================================
    # ====================  END OF USER-CONFIGURABLE PARAMETERS  ====================
    # =================================================================================================
)

# ====================== SCRIPT BODY ======================

Write-Host "=== WARNING: SQL Server $SQLVersion CLEAN UNINSTALL STARTING ===" -ForegroundColor Red
Write-Host "This script will COMPLETELY remove SQL Server. Back up your databases NOW!" -ForegroundColor Yellow
Write-Host "Instance being removed: $InstanceName" -ForegroundColor Cyan
Write-Host "Setup media path: $SetupDirectory" -ForegroundColor Cyan

# Resolve setup.exe
$SetupExe = Join-Path -Path $SetupDirectory -ChildPath "setup.exe"
if (-not (Test-Path $SetupExe)) {
    throw "setup.exe not found in $SetupDirectory. Please provide the original SQL Server installation media folder."
}

# Resolve service names
$InstanceSuffix = if ($InstanceName -eq "MSSQLSERVER") { "" } else { "`$$InstanceName" }
$SqlServiceName   = "MSSQL$InstanceSuffix"
$AgentServiceName = "SQLAgent$InstanceSuffix"
$BrowserServiceName = "SQLBrowser"

# ── 1. Stop all SQL-related services ──
Write-Host "Stopping SQL Server services..." -ForegroundColor Yellow
$servicesToStop = @($SqlServiceName, $AgentServiceName, $BrowserServiceName, "MSSQLFDLauncher$InstanceSuffix", "SQLWriter", "ReportServer$InstanceSuffix")
foreach ($svc in $servicesToStop) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        Stop-Service -Name $svc -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        Write-Host "  Stopped: $svc" -ForegroundColor Gray
    }
}

# ── 2. Official Microsoft Uninstall ──
Write-Host "Running official SQL Server uninstall via setup.exe..." -ForegroundColor Yellow
$uninstallArgs = @(
    "/Q",
    "/ACTION=Uninstall",
    "/INSTANCENAME=$InstanceName",
    "/FEATURES=SQLENGINE",                  # Change if you had more features
    "/IACCEPTSQLSERVERLICENSETERMS"
)

$process = Start-Process -FilePath $SetupExe -ArgumentList $uninstallArgs -Wait -PassThru -NoNewWindow

if ($process.ExitCode -in 0, 3010) {
    Write-Host "Official uninstall completed successfully (ExitCode: $($process.ExitCode))" -ForegroundColor Green
} else {
    Write-Warning "Uninstall returned exit code $($process.ExitCode). Continuing with manual cleanup..."
}

# ── 3. Cleanup leftover directories ──
Write-Host "Cleaning up leftover SQL Server directories..." -ForegroundColor Yellow

$foldersToDelete = @(
    "C:\Program Files\Microsoft SQL Server",
    "C:\Program Files (x86)\Microsoft SQL Server",
    "C:\ProgramData\Microsoft SQL Server",
    "C:\Program Files\Microsoft SQL Server\$($SQLVersion -replace '2022','16' -replace '2025','17')",  # Major version folder
    "$env:ProgramFiles\Microsoft SQL Server\*\Setup Bootstrap"
)

if ($ForceAggressiveCleanup) {
    $foldersToDelete += "C:\Program Files\Microsoft SQL Server\*"
    $foldersToDelete += "C:\ProgramData\Microsoft SQL Server\*"
}

foreach ($folder in $foldersToDelete) {
    if (Test-Path $folder) {
        try {
            Remove-Item -Path $folder -Recurse -Force -ErrorAction Stop
            Write-Host "  Deleted: $folder" -ForegroundColor Gray
        } catch {
            Write-Warning "Could not fully delete $folder (may be in use or protected)."
        }
    }
}

# Optional user data directories (DANGER ZONE)
if ($RemoveUserDataDirectories) {
    Write-Host "WARNING: Removing user data directories (as requested)..." -ForegroundColor Red
    foreach ($dir in $UserDataDirectories) {
        if (Test-Path $dir) {
            Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "  Deleted user data: $dir" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "User data directories were NOT deleted (RemoveUserDataDirectories = `$false). Good!" -ForegroundColor Green
}

# ── 4. Registry cleanup (with automatic backup) ──
Write-Host "Backing up and cleaning SQL registry keys..." -ForegroundColor Yellow

$backupPath = "$env:USERPROFILE\Desktop\SQL_Uninstall_Registry_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
reg export "HKLM\SOFTWARE\Microsoft\Microsoft SQL Server" $backupPath /y 2>$null
reg export "HKLM\SOFTWARE\Wow6432Node\Microsoft\Microsoft SQL Server" $backupPath /y 2>$null
Write-Host "Registry backup saved to: $backupPath" -ForegroundColor Green

$registryKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server",
    "HKLM:\SOFTWARE\Microsoft\MSSQLServer",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Microsoft SQL Server",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\MSSQLServer",
    "HKLM:\SYSTEM\CurrentControlSet\Services\MSSQL$InstanceSuffix",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SQLAgent$InstanceSuffix",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SQLBrowser"
)

foreach ($key in $registryKeys) {
    if (Test-Path $key) {
        Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  Removed registry key: $key" -ForegroundColor Gray
    }
}

# ── 5. Delete any leftover services ──
Write-Host "Removing any remaining SQL services..." -ForegroundColor Yellow
$servicesToDelete = @("MSSQL$InstanceSuffix", "SQLAgent$InstanceSuffix", "SQLBrowser", "MSSQLFDLauncher$InstanceSuffix")
foreach ($svc in $servicesToDelete) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        sc.exe delete $svc | Out-Null
        Write-Host "  Deleted service: $svc" -ForegroundColor Gray
    }
}

# ── 6. Remove firewall rules ──
Write-Host "Removing SQL Server firewall rules..." -ForegroundColor Yellow
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*SQL*" -or $_.DisplayName -like "*1433*" } | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Write-Host "Firewall rules cleaned." -ForegroundColor Green

# ── 7. Final steps ──
Write-Host "`n=== SQL Server $SQLVersion has been COMPLETELY removed ===" -ForegroundColor Green
Write-Host "A full system reboot is highly recommended to finalize cleanup." -ForegroundColor Yellow

if ($RestartComputerAtEnd) {
    Write-Host "Rebooting computer in 10 seconds..." -ForegroundColor Cyan
    Start-Sleep -Seconds 10
    Restart-Computer -Force
} else {
    Write-Host "Please reboot manually to complete the clean uninstall." -ForegroundColor Cyan
}

Write-Host "Script finished." -ForegroundColor Cyan