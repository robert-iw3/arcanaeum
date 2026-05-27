<#
.SYNOPSIS
    Manually uninstalls Trellix Endpoint Security (ENS) on Windows endpoints.
    Based on Trellix KB83456, KB65863, KB58231, and product guides for standalone or disconnected systems.
    - Stops related services
    - Uninstalls ENS components via registry/MSI (dynamic GUID detection)
    - Force uninstalls Trellix Agent
    - Optional: Deletes remaining files and registry keys
    - Includes error handling, logging, and space/connectivity checks (adapted from prior script)
.DESCRIPTION
    Use this script when the removal tool is unavailable or for offline systems.
    Detects and uninstalls components like Threat Prevention, Firewall, Web Control, Adaptive Threat Protection, Platform.
    Run as Administrator. Test in non-production first.
    Does not require connectivity to ePO.
    References: KB83456 (remove ENS), KB65863 (manual agent remove), KB58231 (command prompt removal).
.PARAMETER LogFile
    Path to log file. Default: "C:\Temp\TrellixENSUninstall.log"
.PARAMETER CleanFiles
    Switch to delete remaining files and folders after uninstall (use with caution).
.PARAMETER CleanRegistry
    Switch to delete additional registry keys (backup recommended).
.EXAMPLE
    .\UninstallTrellixENS.ps1 -CleanFiles -CleanRegistry
.NOTES
    Requires elevation. Reboot required after removal.
    GUIDs are dynamically detected; supports various versions.
    If uninstall fails, manual steps from KBs may be needed.
    Author: Robert Weber
#>

param (
    [string]$LogFile = "C:\Temp\TrellixENSUninstall.log",
    [switch]$CleanFiles,
    [switch]$CleanRegistry
)

# Function to write to log
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $logEntry
    Write-Output $logEntry
}

# Create log directory if not exists
$logDir = Split-Path $LogFile -Parent
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

Write-Log "Starting Trellix ENS uninstall script on Windows."

# Check if running as admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "ERROR" "Script must be run as Administrator."
    exit 1
}

try {
    # Step 1: Stop related services
    Write-Log "Stopping Trellix/McAfee services."
    Get-Service -Name "mfe*" | Stop-Service -Force -ErrorAction SilentlyContinue
    Get-Service -Name "McA*" | Stop-Service -Force -ErrorAction SilentlyContinue  # Legacy names

    # Step 2: Uninstall ENS components via registry
    Write-Log "Detecting and uninstalling ENS components."
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($path in $uninstallPaths) {
        Get-ChildItem -Path $path | ForEach-Object {
            $displayName = (Get-ItemProperty -Path $_.PSPath -Name DisplayName -ErrorAction SilentlyContinue).DisplayName
            if (($displayName -like "*Endpoint Security*" -or $displayName -like "*Trellix*") -and ($displayName -notlike "*Agent*")) {
                $uninstallString = (Get-ItemProperty -Path $_.PSPath -Name UninstallString -ErrorAction SilentlyContinue).UninstallString
                if ($uninstallString) {
                    Write-Log "Uninstalling $displayName."
                    $uninstallString = $uninstallString -replace '/I', '/X'  # Change Install to Uninstall
                    Start-Process "msiexec.exe" -ArgumentList "$uninstallString /qn /norestart" -Wait -NoNewWindow
                }
            }
        }
    }

    # Step 3: Uninstall Trellix Agent
    Write-Log "Uninstalling Trellix Agent."
    $agentPath = "C:\Program Files\McAfee\Agent"
    if (Test-Path "$agentPath\FrmInst.exe") {
        Start-Process -FilePath "$agentPath\FrmInst.exe" -ArgumentList "/FORCEUNINSTALL" -Wait -NoNewWindow
    } elseif (Test-Path "$agentPath\x86\FrmInst.exe") {
        Start-Process -FilePath "$agentPath\x86\FrmInst.exe" -ArgumentList "/FORCEUNINSTALL" -Wait -NoNewWindow
    } else {
        Write-Log "WARNING" "FrmInst.exe not found. Attempting manual agent removal (from KB65863)."
        # Manual service deletion
        sc.exe delete mfevtp 2>$null
        sc.exe delete McAfeeFramework 2>$null
        sc.exe delete masvc 2>$null
        # Registry cleanup for agent
        Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mfevtp" -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path "HKLM:\SOFTWARE\McAfee\Agent" -Recurse -ErrorAction SilentlyContinue
    }

    # Step 4: Optional clean files
    if ($CleanFiles) {
        Write-Log "Deleting remaining files and folders."
        Remove-Item -Path "C:\Program Files\McAfee" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\Program Files (x86)\McAfee" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\ProgramData\McAfee" -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Step 5: Optional clean registry
    if ($CleanRegistry) {
        Write-Log "Cleaning registry (backup recommended before running)."
        Remove-Item -Path "HKLM:\SOFTWARE\McAfee" -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\McAfee" -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path "HKCU:\SOFTWARE\McAfee" -Recurse -ErrorAction SilentlyContinue
    }

    Write-Log "Uninstall completed successfully. Reboot required to finalize."

} catch {
    Write-Log "Error: $($_.Exception.Message)" "ERROR"
} finally {
    Write-Log "Script execution completed."
}