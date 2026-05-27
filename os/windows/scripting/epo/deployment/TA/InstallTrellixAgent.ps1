<#
.SYNOPSIS
    Installs Trellix Agent using FramePkg from a network share or internal website.
    Applies best practices for deployment based on Trellix documentation (docs.trellix.com/bundle/trellix-agent-5.8.x-installation-guide).
    - Pulls FramePkg.exe from UNC path or HTTP URL
    - Checks connectivity to source
    - Verifies sufficient disk space with buffer
    - Downloads and installs silently
    - Checks connectivity to ePO server
    - Forces agent check-in
    - Extracts and logs relevant agent log entries for check-in confirmation
    - Includes error handling and logging throughout

.DESCRIPTION
    Run this script on endpoints to deploy or update Trellix Agent.
    Supports UNC paths (e.g., \\server\share\FramePkg.exe) or internal HTTP URLs (e.g., http://internal.site/FramePkg.exe).
    Assumes default installation paths; adjust if customized.
    For HTTP sources, uses HEAD request to check existence and size, with status code validation.
    Logs all steps and errors to a specified file.
    Cleans up temporary files after execution.
    Error handling: Catches exceptions per step, logs, and throws for script termination.

.PARAMETER SourcePath
    UNC path or URL to FramePkg.exe (e.g., "\\server\share\FramePkg.exe" or "http://internal.site/FramePkg.exe")

.PARAMETER ePOServer
    ePO Server hostname or IP

.PARAMETER ePOPort
    ePO Server port (default: 443 for HTTPS)

.PARAMETER LogFile
    Path to log file for output and errors. Default: "C:\Temp\TrellixAgentInstall.log"

.PARAMETER BufferSpaceMB
    Additional buffer space in MB for installation (default: 200)

.EXAMPLE
    .\InstallTrellixAgent.ps1 -SourcePath "\\server\share\FramePkg.exe" -ePOServer "epo.server.com" -PurgeDays 90

.NOTES
    Run as administrator or with sufficient permissions.
    Test in non-production first.
    Paths for agent (e.g., McAfee\Agent) may vary; Trellix often retains McAfee paths.
    For large-scale deployment, consider using ePO deployment tasks.
    Avoid running on systems with insufficient space or during high-load periods.
    Author: Robert Weber
#>

param (
    [string]$SourcePath = "\\server\share\FramePkg.exe",  # UNC path or URL to FramePkg.exe
    [string]$ePOServer = "epo.server.com",                # ePO Server hostname or IP
    [int]$ePOPort = 443,                                  # ePO Server port (default 443 for HTTPS)
    [string]$LogFile = "C:\Temp\TrellixAgentInstall.log", # Log file path
    [long]$BufferSpaceMB = 200                            # Additional buffer space in MB
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

Write-Log "Starting Trellix Agent installation script."

try {
    # Step 1: Check connectivity to source
    Write-Log "Checking connectivity to source: $SourcePath"
    $isUNC = $SourcePath -like '\\*'
    $connected = $false
    if ($isUNC) {
        $connected = Test-Path $SourcePath
    } else {
        try {
            $headResponse = Invoke-WebRequest -Uri $SourcePath -Method Head -UseBasicParsing
            if ($headResponse.StatusCode -ne 200) {
                throw "Source not found or inaccessible (Status: $($headResponse.StatusCode))"
            }
            $connected = $true
        } catch {
            $connected = $false
        }
    }
    if (-not $connected) {
        throw "Unable to connect to source: $SourcePath"
    }
    Write-Log "Connectivity to source confirmed."

    # Step 2: Get package size
    Write-Log "Determining package size."
    $packageSizeBytes = 0
    if ($isUNC) {
        $fileInfo = Get-Item $SourcePath
        $packageSizeBytes = $fileInfo.Length
    } else {
        $packageSizeBytes = [long]$headResponse.Headers['Content-Length']
    }
    $packageSizeMB = [math]::Round($packageSizeBytes / 1MB, 2)
    $requiredSpaceMB = $packageSizeMB * 2 + $BufferSpaceMB  # Assume 2x for extraction + buffer
    Write-Log "Package size: $packageSizeMB MB. Required space: $requiredSpaceMB MB."

    # Step 3: Check available disk space on C:
    Write-Log "Checking available disk space on C: drive."
    $disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
    $freeSpaceMB = [math]::Round($disk.FreeSpace / 1MB, 2)
    Write-Log "Free space on C:: $freeSpaceMB MB."
    if ($freeSpaceMB -lt $requiredSpaceMB) {
        throw "Insufficient disk space. Required: $requiredSpaceMB MB, Available: $freeSpaceMB MB."
    }
    Write-Log "Sufficient disk space available."

    # Step 4: Download the package
    $tempDir = "$env:TEMP\TrellixAgent"
    if (-not (Test-Path $tempDir)) {
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
    }
    $localPath = "$tempDir\FramePkg.exe"
    Write-Log "Downloading package to $localPath."
    if ($isUNC) {
        Copy-Item -Path $SourcePath -Destination $localPath -Force
    } else {
        Invoke-WebRequest -Uri $SourcePath -OutFile $localPath -UseBasicParsing
    }
    if (-not (Test-Path $localPath)) {
        throw "Failed to download package."
    }
    Write-Log "Package downloaded successfully."

    # Step 5: Install the package
    Write-Log "Installing Trellix Agent."
    $installArgs = "/install=agent /silent"
    $process = Start-Process -FilePath $localPath -ArgumentList $installArgs -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Installation failed with exit code $($process.ExitCode)."
    }
    Write-Log "Installation completed successfully."

    # Step 6: Check connectivity to ePO server
    Write-Log "Checking connectivity to ePO server: $ePOServer on port $ePOPort."
    $connTest = Test-NetConnection -ComputerName $ePOServer -Port $ePOPort
    if (-not $connTest.TcpTestSucceeded) {
        throw "Unable to connect to ePO server: $ePOServer on port $ePOPort."
    }
    Write-Log "Connectivity to ePO server confirmed."

    # Step 7: Force agent check-in
    $agentPath = "C:\Program Files\McAfee\Agent"  # Adjust if Trellix uses different path; often remains McAfee
    $cmdAgent = "$agentPath\cmdagent.exe"
    if (-not (Test-Path $cmdAgent)) {
        throw "CmdAgent.exe not found at $cmdAgent."
    }
    Write-Log "Forcing agent property collection and send."
    Start-Process -FilePath $cmdAgent -ArgumentList "/c" -Wait
    Write-Log "Property collection executed."

    # Step 8: Grab and consolidate logs
    $logDir = "C:\ProgramData\McAfee\Agent\logs"  # Common log path
    $mainLog = "$logDir\masvc.log"  # One of the main service logs
    if (-not (Test-Path $mainLog)) {
        throw "Agent log not found at $mainLog."
    }
    Write-Log "Extracting relevant log entries for ePO check-in."
    $recentLogs = Get-Content $mainLog -Tail 100  # Last 100 lines
    $relevantLogs = $recentLogs | Where-Object { $_ -match "ePO|ePolicy|connected|check.?in|success|properties sent" }

    if ($relevantLogs.Count -eq 0) {
        Write-Log "No relevant check-in entries found in logs." "WARNING"
    } else {
        Write-Log "Relevant log entries:"
        foreach ($entry in $relevantLogs) {
            Write-Log $entry
        }
        # Check for success indicators
        if ($relevantLogs -match "success|connected") {
            Write-Log "Agent appears to have successfully checked in to ePO."
        } else {
            Write-Log "Check-in may have issues; review logs." "WARNING"
        }
    }

} catch {
    Write-Log "Error: $($_.Exception.Message)" "ERROR"
    throw
} finally {
    # Cleanup
    if (Test-Path $localPath) {
        Remove-Item $localPath -Force
        Write-Log "Cleaned up temporary files."
    }
    Write-Log "Script execution completed."
}