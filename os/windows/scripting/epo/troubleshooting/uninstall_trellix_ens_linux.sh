#!/bin/bash
#
# .SYNOPSIS
#    Manually uninstalls Trellix Endpoint Security (ENS) on Linux endpoints.
#    Based on Trellix KB95343 and related documentation for standalone or disconnected systems.
#    - Stops ENS services
#    - Removes ENS packages (Threat Prevention, Firewall) using rpm
#    - Deletes remaining files and directories
#    - Uninstalls Trellix Agent
#    - Includes error handling and logging
# .DESCRIPTION
#    Use this script when standard uninstallers fail or for offline systems without ePO.
#    Assumes default installation paths (/opt/McAfee/ens, /opt/McAfee/agent).
#    Run as root. Test in non-production first.
#    References: KB95343 (manual removal for ENSL Firewall and Threat Prevention),
#    KB75550 (manual agent removal for Linux), and product guides.
# .PARAMETER LogFile
#    Path to log file. Default: /tmp/trellix_ens_uninstall.log
# .EXAMPLE
#    ./uninstall_trellix_ens_linux.sh
# .NOTES
#    May require reboot after removal.
#    If packages not found, script continues to file deletion.
#    Author: Robert Weber
#

LogFile="/tmp/trellix_ens_uninstall.log"

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

log "INFO" "Starting Trellix ENS uninstall on Linux."

# Step 1: Stop ENS services
log "INFO" "Stopping ENS services."
systemctl stop mfeatp 2>/dev/null || service mfeatp stop 2>/dev/null
systemctl stop mfeesp 2>/dev/null || service mfeesp stop 2>/dev/null
systemctl stop mfeesp-ps 2>/dev/null || service mfeesp-ps stop 2>/dev/null
# Firewall if present
systemctl stop mfefire 2>/dev/null || service mfefire stop 2>/dev/null

# Kill any remaining processes
pkill -f mfe 2>/dev/null

# Step 2: Remove ENS packages
log "INFO" "Removing ENS packages."
rpm -e --nodeps ENSLTP 2>> "$LogFile" || log "WARNING" "ENSLTP package not found or removal failed."
rpm -e --nodeps ENSLFW 2>> "$LogFile" || log "WARNING" "ENSLFW package not found or removal failed."
rpm -e --nodeps MFEcma 2>> "$LogFile" || log "WARNING" "MFEcma package not found or removal failed."
rpm -e --nodeps MFErt 2>> "$LogFile" || log "WARNING" "MFErt package not found or removal failed."

# Step 3: Delete ENS files and directories
log "INFO" "Deleting ENS files and directories."
rm -rf /opt/McAfee/ens 2>> "$LogFile"
rm -rf /var/McAfee/ens 2>> "$LogFile"
rm -rf /etc/init.d/mfeatp 2>> "$LogFile"
rm -rf /etc/init.d/mfefire 2>> "$LogFile"
rm -rf /var/log/McAfee 2>> "$LogFile"  # Shared, careful if other products

# Step 4: Uninstall Trellix Agent
log "INFO" "Uninstalling Trellix Agent."
if [ -f /opt/McAfee/agent/scripts/uninstall.sh ]; then
    /opt/McAfee/agent/scripts/uninstall.sh 2>> "$LogFile"
else
    log "WARNING" "Agent uninstall script not found. Performing manual removal."
    # Manual agent removal (from KB75550)
    systemctl stop cma 2>/dev/null || service cma stop 2>/dev/null
    rpm -e --nodeps MFEcma 2>> "$LogFile" || true
    rpm -e --nodeps MFErt 2>> "$LogFile" || true
    rm -rf /opt/McAfee/agent 2>> "$LogFile"
    rm -rf /etc/McAfee 2>> "$LogFile"
    rm -rf /var/McAfee 2>> "$LogFile"
    rm -rf /var/log/McAfee 2>> "$LogFile"
fi

# Step 5: Clean up any remaining links or configs
log "INFO" "Cleaning up remaining configurations."
rm -f /etc/ld.so.conf.d/mfert.conf 2>> "$LogFile"
ldconfig 2>> "$LogFile"

# Verify removal
if rpm -qa | grep -i mfe >/dev/null; then
    log "WARNING" "Some MFE packages may still be installed. Run 'rpm -qa | grep mfe' to check."
else
    log "INFO" "No remaining MFE packages found."
fi

log "INFO" "Uninstall completed. Reboot recommended."
echo "Log file: $LogFile"