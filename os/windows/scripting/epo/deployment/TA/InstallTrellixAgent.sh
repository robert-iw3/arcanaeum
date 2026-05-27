#!/bin/bash
#
# .SYNOPSIS
#    Installs Trellix Agent on Linux using installation package from a network share or internal website.
#    Based on Trellix documentation (docs.trellix.com, KB articles, installation guides).
#    - Pulls MAxxxLNX.zip from path or HTTP URL
#    - Checks connectivity to source
#    - Verifies sufficient disk space with buffer
#    - Downloads, unzips, and installs using install.sh -i
#    - Checks connectivity to ePO server
#    - Forces agent check-in with cmdagent -c
#    - Extracts and logs relevant agent log entries for check-in confirmation
#    - Includes error handling and logging throughout
# .DESCRIPTION
#    Run this script on Linux endpoints to deploy Trellix Agent.
#    Supports local paths (e.g., /mnt/share/MAxxxLNX.zip) or HTTP URLs (e.g., http://internal.site/MAxxxLNX.zip).
#    Assumes default installation paths (/opt/McAfee/agent, /var/McAfee/agent/logs).
#    For HTTP sources, uses HEAD request to check existence and size, with status code validation.
#    Logs all steps and errors to a specified file.
#    Cleans up temporary files after execution.
#    Error handling: Exits on critical errors, logs warnings.
# .PARAMETER SourcePath
#    Path or URL to MAxxxLNX.zip (e.g., "/mnt/share/MAxxxLNX.zip" or "http://internal.site/MAxxxLNX.zip")
# .PARAMETER ePOServer
#    ePO Server hostname or IP
# .PARAMETER ePOPort
#    ePO Server port (default: 443 for HTTPS)
# .PARAMETER LogFile
#    Path to log file for output and errors. Default: "/tmp/TrellixAgentInstall.log"
# .PARAMETER BufferSpaceMB
#    Additional buffer space in MB for installation (default: 200)
# .EXAMPLE
#    ./InstallTrellixAgent.sh -SourcePath "http://internal.site/MAxxxLNX.zip" -ePOServer "epo.server.com"
# .NOTES
#    Run as root.
#    Test in non-production first.
#    Paths may vary; Trellix often retains McAfee paths.
#    For large-scale deployment, consider using ePO deployment tasks.
#    Author: Robert Weber
#

# Parameters
SourcePath="${1:-/mnt/share/MAxxxLNX.zip}"  # Default example
ePOServer="${2:-epo.server.com}"
ePOPort="${3:-443}"
LogFile="${4:-/tmp/TrellixAgentInstall.log}"
BufferSpaceMB="${5:-200}"

# Function to log messages
log() {
    local level="$1"
    local message="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" | tee -a "$LogFile"
}

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    log "ERROR" "Script must be run as root."
    exit 1
fi

log "INFO" "Starting Trellix Agent installation script on Linux."

# Step 1: Check connectivity to source
log "INFO" "Checking connectivity to source: $SourcePath"
isHTTP=$(echo "$SourcePath" | grep -i '^http')
connected=0
if [ -n "$isHTTP" ]; then
    headResponse=$(curl -I "$SourcePath" 2>/dev/null)
    statusCode=$(echo "$headResponse" | grep -oP 'HTTP/\d\.\d \K\d+' | head -1)
    if [ "$statusCode" != "200" ]; then
        log "ERROR" "Source not found or inaccessible (Status: $statusCode)"
        exit 1
    fi
    connected=1
else
    if [ -f "$SourcePath" ]; then
        connected=1
    fi
fi
if [ $connected -eq 0 ]; then
    log "ERROR" "Unable to connect to source: $SourcePath"
    exit 1
fi
log "INFO" "Connectivity to source confirmed."

# Step 2: Get package size
log "INFO" "Determining package size."
packageSizeBytes=0
if [ -n "$isHTTP" ]; then
    packageSizeBytes=$(echo "$headResponse" | grep -i 'Content-Length' | awk '{print $2}' | tr -d '\r')
else
    packageSizeBytes=$(stat -c %s "$SourcePath")
fi
packageSizeMB=$(echo "scale=2; $packageSizeBytes / 1048576" | bc)
requiredSpaceMB=$(echo "scale=2; $packageSizeMB * 2 + $BufferSpaceMB" | bc)  # 2x for unzip + buffer
log "INFO" "Package size: $packageSizeMB MB. Required space: $requiredSpaceMB MB."

# Step 3: Check available disk space on /
log "INFO" "Checking available disk space on /."
freeSpaceBytes=$(df -B1 / | tail -1 | awk '{print $4}')
freeSpaceMB=$(echo "scale=2; $freeSpaceBytes / 1048576" | bc)
log "INFO" "Free space on /: $freeSpaceMB MB."
if (( $(echo "$freeSpaceMB < $requiredSpaceMB" | bc -l) )); then
    log "ERROR" "Insufficient disk space. Required: $requiredSpaceMB MB, Available: $freeSpaceMB MB."
    exit 1
fi
log "INFO" "Sufficient disk space available."

# Step 4: Download the package
tempDir="/tmp/TrellixAgent"
mkdir -p "$tempDir"
localPath="$tempDir/MAxxxLNX.zip"
log "INFO" "Downloading package to $localPath."
if [ -n "$isHTTP" ]; then
    wget -q "$SourcePath" -O "$localPath" || { log "ERROR" "Failed to download package."; exit 1; }
else
    cp "$SourcePath" "$localPath" || { log "ERROR" "Failed to copy package."; exit 1; }
fi
if [ ! -f "$localPath" ]; then
    log "ERROR" "Failed to obtain package."
    exit 1
fi
log "INFO" "Package obtained successfully."

# Step 5: Unzip and install
log "INFO" "Unzipping and installing Trellix Agent."
unzip -q "$localPath" -d "$tempDir" || { log "ERROR" "Failed to unzip package."; exit 1; }
installScript="$tempDir/install.sh"
if [ ! -f "$installScript" ]; then
    log "ERROR" "install.sh not found in package."
    exit 1
fi
chmod +x "$installScript"
"$installScript" -i > /dev/null 2>&1
if [ $? -ne 0 ]; then
    log "ERROR" "Installation failed."
    exit 1
fi
log "INFO" "Installation completed successfully."

# Step 6: Check connectivity to ePO server
log "INFO" "Checking connectivity to ePO server: $ePOServer on port $ePOPort."
nc -zv "$ePOServer" "$ePOPort" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    log "ERROR" "Unable to connect to ePO server: $ePOServer on port $ePOPort."
    exit 1
fi
log "INFO" "Connectivity to ePO server confirmed."

# Step 7: Force agent check-in
agentBin="/opt/McAfee/agent/bin/cmdagent"
if [ ! -f "$agentBin" ]; then
    log "ERROR" "cmdagent not found at $agentBin."
    exit 1
fi
log "INFO" "Forcing agent property collection and send."
"$agentBin" -c > /dev/null 2>&1
log "INFO" "Property collection executed."

# Step 8: Grab and consolidate logs
logDir="/var/McAfee/agent/logs"
mainLog=$(ls "$logDir/masvc"*.log | head -1)  # Assume masvc_<hostname>.log
if [ ! -f "$mainLog" ]; then
    log "ERROR" "Agent log not found in $logDir."
    exit 1
fi
log "INFO" "Extracting relevant log entries for ePO check-in."
recentLogs=$(tail -n 100 "$mainLog")
relevantLogs=$(echo "$recentLogs" | grep -i "ePO|ePolicy|connected|check.?in|success|properties sent")
if [ -z "$relevantLogs" ]; then
    log "WARNING" "No relevant check-in entries found in logs."
else
    log "INFO" "Relevant log entries:"
    echo "$relevantLogs" | while read -r entry; do
        log "INFO" "$entry"
    done
    if echo "$relevantLogs" | grep -iq "success|connected"; then
        log "INFO" "Agent appears to have successfully checked in to ePO."
    else
        log "WARNING" "Check-in may have issues; review logs."
    fi
fi

# Cleanup
rm -rf "$tempDir"
log "INFO" "Cleaned up temporary files."
log "INFO" "Script execution completed."