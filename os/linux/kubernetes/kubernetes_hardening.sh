#!/bin/bash

# =================================================================================
# Kubernetes Host Hardening Script
# Harden Kubernetes host machine based on CIS Benchmarks and STIG guidelines.
# NSA/CISA Kubernetes Hardening Guide
# Version: 1.0
# RW
# This script assumes a Linux-based system (Ubuntu/CentOS/RHEL) and root privileges
# =================================================================================

# Script configuration
LOG_FILE="/var/log/k8s_hardening.log"
BACKUP_DIR="/var/backups/k8s_hardening_$(date +%Y%m%d%H%M%S)"
STATE_FILE="/etc/k8s_hardening.state"
TIMESTAMP_START=$(date +'%Y-%m-%d %H:%M:%S')

# Enable robust shell options
set -euo pipefail

# --- Utility Functions ---

# Log messages to console and file
log() {
    local message="$1"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $message" | tee -a "$LOG_FILE"
}

# Log and handle errors gracefully
error_exit() {
    log "ERROR: $1"
    log "Aborting script. Please check the log file for details: $LOG_FILE"
    exit 1
}

# Perform cleanup on exit, whether successful or failed
cleanup() {
    log "Script finished at $(date +'%Y-%m-%d %H:%M:%S')"
    # Any other cleanup logic can go here.
}
trap cleanup EXIT

# Check for root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root."
    fi
}

# Backup a file before modification
backup_file() {
    local file="$1"
    if [ -f "$file" ] && [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR" || error_exit "Failed to create backup directory."
    fi
    if [ -f "$file" ]; then
        cp -a "$file" "$BACKUP_DIR/$(basename "$file")" || error_exit "Failed to backup $file."
        log "Backed up $file to $BACKUP_DIR/"
    fi
}

# Check if a specific step has already run to achieve idempotency
is_already_run() {
    local step_name="$1"
    grep -q "$step_name" "$STATE_FILE" 2>/dev/null
}

# Record a completed step in the state file
record_run() {
    local step_name="$1"
    echo "$step_name" >> "$STATE_FILE"
}

# --- Hardening Functions ---

# Harden kernel parameters based on NSA/CISA guidance
harden_kernel() {
    local step_name="kernel_hardening"
    if is_already_run "$step_name"; then
        log "Skipping kernel parameters; already configured."
        return
    fi

    log "Configuring kernel parameters..."
    backup_file "/etc/sysctl.d/99-kubernetes-hardening.conf"

    cat << EOF > /etc/sysctl.d/99-kubernetes-hardening.conf
# NSA/CISA Hardening Guide

# Secure against IP spoofing and source routing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Prevent packet redirects and ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Enable SYN Cookies and log martians
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1

# Disable IPv6 if not required (optional, set to 1 if not used)
net.ipv6.conf.all.disable_ipv6 = 0

# General security improvements
kernel.randomize_va_space = 2
kernel.core_uses_pid = 1
fs.suid_dumpable = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF

    sysctl --system || error_exit "Failed to apply kernel parameters."
    log "Kernel parameters configured."
    record_run "$step_name"
}

# Secure filesystem permissions
secure_filesystem() {
    local step_name="filesystem_hardening"
    if is_already_run "$step_name"; then
        log "Skipping filesystem hardening; already configured."
        return
    fi

    log "Configuring filesystem permissions..."

    # Ensure /etc/shadow is only readable by root
    if [ "$(stat -c %a /etc/shadow)" != "600" ]; then
        backup_file "/etc/shadow"
        chmod 600 /etc/shadow || error_exit "Failed to secure /etc/shadow."
        chown root:root /etc/shadow
    fi

    # Ensure /etc/passwd is readable by all but writable by root only
    if [ "$(stat -c %a /etc/passwd)" != "644" ]; then
        backup_file "/etc/passwd"
        chmod 644 /etc/passwd || error_exit "Failed to secure /etc/passwd."
        chown root:root /etc/passwd
    fi

    # Secure sticky bit on world-writable directories
    log "Securing world-writable directories with sticky bit..."
    find / -type d -perm -0002 -exec chmod a+t {} \; 2>/dev/null

    # Mount /tmp with hardening options
    if ! mount | grep -q "/tmp.*noexec"; then
        log "Configuring /tmp mount with noexec, nosuid, nodev..."
        backup_file "/etc/fstab"
        echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
        mount -o remount,noexec,nosuid,nodev /tmp || error_exit "Failed to remount /tmp."
    fi

    log "Filesystem permissions configured."
    record_run "$step_name"
}

# Disable unused filesystems via modprobe
disable_filesystems() {
    local step_name="disable_filesystems"
    if is_already_run "$step_name"; then
        log "Skipping disabling filesystems; already configured."
        return
    fi

    log "Disabling unused filesystems..."
    backup_file "/etc/modprobe.d/k8s-filesystems.conf"

    cat << EOF > /etc/modprobe.d/k8s-filesystems.conf
# NSA/CISA Hardening Guide
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
install usb-storage /bin/true # Add based on NSA guide
EOF

    log "Unused filesystems disabled."
    record_run "$step_name"
}

# Harden SSH configuration
harden_ssh() {
    local step_name="ssh_hardening"
    if is_already_run "$step_name"; then
        log "Skipping SSH hardening; already configured."
        return
    fi

    SSH_CONFIG="/etc/ssh/sshd_config"
    if [ -f "$SSH_CONFIG" ]; then
        log "Hardening SSH configuration..."
        backup_file "$SSH_CONFIG"

        # Apply various NSA/CISA recommendations
        sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONFIG"
        sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "$SSH_CONFIG"
        sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSH_CONFIG"
        sed -i 's/^Protocol.*/Protocol 2/' "$SSH_CONFIG"
        sed -i 's/^MaxAuthTries.*/MaxAuthTries 3/' "$SSH_CONFIG"
        sed -i 's/^ClientAliveInterval.*/ClientAliveInterval 300/' "$SSH_CONFIG"
        sed -i 's/^ClientAliveCountMax.*/ClientAliveCountMax 0/' "$SSH_CONFIG"

        # Add strong ciphers and MACs if not present
        if ! grep -q "Ciphers" "$SSH_CONFIG"; then
            echo "Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr" >> "$SSH_CONFIG"
        fi
        if ! grep -q "MACs" "$SSH_CONFIG"; then
            echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com" >> "$SSH_CONFIG"
        fi
        if ! grep -q "UseDNS" "$SSH_CONFIG"; then
            echo "UseDNS no" >> "$SSH_CONFIG" # Prevent DNS-related attacks
        fi
        if ! grep -q "Banner" "$SSH_CONFIG"; then
            echo "Banner /etc/issue.net" >> "$SSH_CONFIG" # Add login banner
        fi

        systemctl reload sshd || error_exit "Failed to reload sshd."
        log "SSH configuration hardened."
        record_run "$step_name"
    else
        log "Warning: SSH configuration file not found at $SSH_CONFIG."
    fi
}

# Disable unnecessary services
disable_services() {
    local step_name="disable_services"
    if is_already_run "$step_name"; then
        log "Skipping disabling services; already configured."
        return
    fi

    log "Disabling unnecessary services..."
    local services=(
        "avahi-daemon" "cups" "dhcpd" "slapd" "nfs" "rpcbind" "named"
        "vsftpd" "httpd" "dovecot" "smb" "squid" "snmpd" "telnet" "rsh"
        "xinetd" "nis" # Additional services
    )

    for service in "${services[@]}"; do
        if systemctl is-enabled --quiet "$service"; then
            systemctl stop "$service" || log "Warning: Failed to stop $service."
            systemctl disable "$service" || log "Warning: Failed to disable $service."
            log "Disabled and stopped $service."
        fi
    done

    log "Unnecessary services disabled."
    record_run "$step_name"
}

# Configure firewall rules based on detected firewall
configure_firewall() {
    local step_name="firewall_configuration"
    if is_already_run "$step_name"; then
        log "Skipping firewall configuration; already configured."
        return
    fi

    log "Configuring firewall..."
    local ports_tcp=(6443 10250 10251 10252 2379-2380)
    local ports_udp=(8285 8472) # Required for some Kubernetes networking like Flannel

    if command -v firewalld >/dev/null 2>&1; then
        log "Detected firewalld. Configuring..."
        systemctl enable firewalld --now
        firewall-cmd --set-default-zone=drop
        for port in "${ports_tcp[@]}"; do
            firewall-cmd --permanent --add-port="${port}/tcp"
        done
        for port in "${ports_udp[@]}"; do
            firewall-cmd --permanent --add-port="${port}/udp"
        done
        firewall-cmd --reload
        log "Firewalld configured."
    elif command -v ufw >/dev/null 2>&1; then
        log "Detected UFW. Configuring..."
        ufw default deny incoming
        ufw default allow outgoing
        for port in "${ports_tcp[@]}"; do
            ufw allow "${port}/tcp"
        done
        for port in "${ports_udp[@]}"; do
            ufw allow "${port}/udp"
        done
        ufw enable
        log "UFW configured."
    else
        log "Warning: No supported firewall (firewalld or ufw) found."
        log "Please configure your firewall manually."
    fi

    record_run "$step_name"
}

# Configure auditd rules
configure_auditd() {
    local step_name="auditd_configuration"
    if is_already_run "$step_name"; then
        log "Skipping auditd configuration; already configured."
        return
    fi

    if command -v auditd >/dev/null 2>&1; then
        log "Configuring auditd rules..."
        backup_file "/etc/audit/rules.d/k8s-hardening.rules"

        cat << EOF > /etc/audit/rules.d/k8s-hardening.rules
# NSA/CISA Hardening Guide
# Record events that modify date and time
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change

# Record events that modify user/group information
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Record events that modify the system's network environment
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

# Monitor privileged commands
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k priv_cmd
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k priv_cmd

# File integrity monitoring
-w /etc/kubernetes/ -p wa -k k8s_config
-w /etc/docker/ -p wa -k docker_config
-w /etc/etcd/ -p wa -k etcd_config
EOF

        augenrules --load || error_exit "Failed to load auditd rules."
        systemctl enable auditd --now
        log "Auditd configured and running."
        record_run "$step_name"
    else
        log "Warning: auditd not installed. Skipping auditd configuration."
    fi
}

# Configure mandatory access controls (MAC)
configure_mac() {
    local step_name="mac_configuration"
    if is_already_run "$step_name"; then
        log "Skipping MAC configuration; already configured."
        return
    fi

    log "Configuring mandatory access controls..."
    if command -v apparmor_parser >/dev/null 2>&1; then
        systemctl enable apparmor --now || error_exit "Failed to enable App
