#!/usr/bin/env bash
# Enhanced AIDE Configuration Script
# This script sets up AIDE with a balanced ruleset, SIEM integration, and secure configurations.
# @RW

set -euo pipefail
IFS=$'\n\t'

# ================== CONFIGURATION ==================
LOG_FILE="/var/log/aide_config.log"
JSON_LOG_FILE="/var/log/aide_config.json"
BACKUP_DIR="/var/backups/aide"
AIDE_CONF="/etc/aide/aide.conf"
AIDE_CONF_DIR="/etc/aide/aide.conf.d"
AIDE_LOG_DIR="/var/log/aide"
SHIPPER_PATH="/usr/local/bin/aide-ship-to-siem.py"
RSYSLOG_CONF="/etc/rsyslog.d/50-default.conf"
VERBOSE=${VERBOSE:-"N"}
SCRIPT_COUNT=1

# Balanced ruleset
read -r -d '' AIDE_RULES << 'EOF'
# Enhanced AIDE Ruleset - Balanced Coverage + Performance
FIPSR   = p+i+n+u+g+s+m+c+acl+xattrs+selinux+sha512
NORMAL  = p+i+n+u+g+s+m+c+acl+xattrs+selinux+sha512
LOG     = p+i+n+u+g+s+m+c+acl+xattrs+selinux
PERMS   = p+u+g+acl+xattrs+selinux

# Volatile exclusions (major performance win)
!/proc
!/sys
!/dev
!/run
!/tmp
!/var/tmp
!/var/run
!/var/lock
!/var/cache
!/var/spool
!/var/log/journal
!/var/lib/docker
!/var/lib/lxcfs
!/var/lib/kubelet
!/var/lib/containerd
!/home/*/.cache

# Critical areas - strong integrity
/bin          FIPSR
/sbin         FIPSR
/usr/bin      FIPSR
/usr/sbin     FIPSR
/usr/local/bin FIPSR
/lib          FIPSR
/lib64        FIPSR
/usr/lib      FIPSR
/usr/lib64    FIPSR
/boot         FIPSR
/etc          NORMAL
/root         PERMS

# Lighter rules for logs and user data
/var/log      LOG
/home         PERMS

# AIDE self-protection
/etc/aide     FIPSR
/var/lib/aide FIPSR

# SIEM-ready reporting (AIDE >= 0.18)
report_format = json
report_url = file:/var/log/aide/aide_report.json
report_url = syslog:authpriv
EOF

# Log function
log() {
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $*" | tee -a "$LOG_FILE"
}

# Setup directories
setup_dirs() {
    mkdir -p "$BACKUP_DIR" "$AIDE_LOG_DIR" "$AIDE_CONF_DIR" "/var/lib/aide"
    chown root:root "$BACKUP_DIR" "$AIDE_LOG_DIR" "$AIDE_CONF_DIR" "/var/lib/aide"
    chmod 750 "$BACKUP_DIR" "$AIDE_LOG_DIR" "$AIDE_CONF_DIR" "/var/lib/aide"
}

# Check dependencies
check_deps() {
    local deps=("aide" "aideinit" "systemctl" "capsh")
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            log "Error: $cmd is required but not installed"
            exit 1
        fi
    done
}

# Check root or CAP_SYS_ADMIN
check_privileges() {
    if ! capsh --print 2>/dev/null | grep -qi "cap_sys_admin"; then
        if [[ $EUID -ne 0 ]]; then
            log "Error: This script requires root or CAP_SYS_ADMIN privileges"
            exit 1
        fi
    fi
}

# Backup file
backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        local backup="$BACKUP_DIR/$(basename "$file").$(date +%s)"
        mkdir -p "$BACKUP_DIR"
        cp "$file" "$backup"
        log "Backed up $file to $backup"
    fi
}

# Install SIEM shipper (same as Python version)
install_shipper() {
    log "[$SCRIPT_COUNT] Installing SIEM shipper"
    cat > "$SHIPPER_PATH" << 'SHIPPER'
#!/usr/bin/env python3
import json, sys, os, socket
from datetime import datetime
import urllib.request
def ship(r="/var/log/aide/aide_report.json"):
    h = socket.gethostname()
    ts = datetime.utcnow().isoformat() + "Z"
    jpath = "/var/log/aide/aide_events.jsonl"
    try:
        with open(r) as f: rep = json.load(f)
        ev = [{"@timestamp": ts, "host.name": h, "event.module": "aide", "aide": rep}]
    except:
        with open(r, errors="ignore") as f: ev = [{"@timestamp": ts, "host.name": h, "event.module": "aide", "message": f.read(20000)}]
    with open(jpath, "a") as f:
        for e in ev: f.write(json.dumps(e)+"\n")
    if os.getenv("AIDE_SIEM_HTTP_URL"):
        try:
            req = urllib.request.Request(os.getenv("AIDE_SIEM_HTTP_URL"), data=json.dumps(ev[0]).encode(), headers={"Content-Type":"application/json", "Authorization":f"Bearer {os.getenv('AIDE_SIEM_TOKEN','')}"})
            urllib.request.urlopen(req, timeout=8)
        except Exception as e: print(f"HTTP ship failed: {e}", file=sys.stderr)
if __name__ == "__main__": ship(sys.argv[1] if len(sys.argv)>1 else None)
SHIPPER
    chmod 755 "$SHIPPER_PATH"
    chown root:root "$SHIPPER_PATH"
    ((SCRIPT_COUNT++))
}

# Configure cron and at
cron() {
    log "[$SCRIPT_COUNT] Configuring /etc/cron and /etc/at"
    rm -f /etc/cron.deny /etc/at.deny 2>/dev/null
    echo 'root' | tee /etc/cron.allow /etc/at.allow >/dev/null
    chown root:root /etc/cron* /etc/at* 2>/dev/null || true
    chmod 600 /etc/cron* /etc/at* 2>/dev/null || true
    systemctl mask --now atd.service >/dev/null 2>&1 || true
    if [[ -f "$RSYSLOG_CONF" ]]; then
        backup_file "$RSYSLOG_CONF"
        sed -i 's/^#cron\./cron\./' "$RSYSLOG_CONF"
    fi
    ((SCRIPT_COUNT++))
}

# Configure comprehensive AIDE rules
aide_rules() {
    log "[$SCRIPT_COUNT] Installing comprehensive AIDE ruleset"
    mkdir -p "$AIDE_CONF_DIR"
    chown root:root "$AIDE_CONF_DIR"
    chmod 750 "$AIDE_CONF_DIR"
    echo "$AIDE_RULES" > "$AIDE_CONF_DIR/10_aide_enhanced.conf"
    chown root:root "$AIDE_CONF_DIR/10_aide_enhanced.conf"
    chmod 644 "$AIDE_CONF_DIR/10_aide_enhanced.conf"

    # Ensure @@include in main config
    if [[ -f "$AIDE_CONF" ]]; then
        backup_file "$AIDE_CONF"
        if ! grep -q "@@include /etc/aide/aide.conf.d/" "$AIDE_CONF"; then
            echo -e "\n@@include /etc/aide/aide.conf.d/*.conf" >> "$AIDE_CONF"
        fi
    else
        log "Error: $AIDE_CONF not found"
        exit 1
    fi
    ((SCRIPT_COUNT++))
}

# Initialize AIDE database
aide_post() {
    log "[$SCRIPT_COUNT] Initializing AIDE database (this may take a while)"
    aideinit --yes
    ((SCRIPT_COUNT++))
}

# Activate database
activate_db() {
    log "[$SCRIPT_COUNT] Activating AIDE database"
    for newdb in /var/lib/aide/aide.db.new*; do
        if [[ -f "$newdb" ]]; then
            target="${newdb/.new/}"
            backup_file "$target" 2>/dev/null || true
            mv "$newdb" "$target"
            chmod 600 "$target"
            log "Activated database: $target"
        fi
    done
    ((SCRIPT_COUNT++))
}

# Setup systemd timer + service with SIEM shipper
aide_timer() {
    log "[$SCRIPT_COUNT] Configuring daily AIDE check with SIEM integration"
    local service_file="/etc/systemd/system/aidecheck.service"
    local timer_file="/etc/systemd/system/aidecheck.timer"

    cat > "$service_file" << EOF
[Unit]
Description=AIDE daily check
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/aide --check
ExecStartPost=$SHIPPER_PATH
Nice=19
IOSchedulingClass=idle
StandardOutput=append:/var/log/aide/aide.log
StandardError=append:/var/log/aide/aide.log
EOF

    cat > "$timer_file" << EOF
[Unit]
Description=Daily AIDE check timer

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=30min

[Install]
WantedBy=timers.target
EOF

    chown root:root "$service_file" "$timer_file"
    chmod 644 "$service_file" "$timer_file"

    systemctl daemon-reload
    systemctl enable --now aidecheck.timer >/dev/null 2>&1
    ((SCRIPT_COUNT++))
}

# ================== MAIN ==================
setup_dirs
check_deps
check_privileges

# Initialize log file
touch "$LOG_FILE" "$JSON_LOG_FILE" 2>/dev/null || true
chown root:root "$LOG_FILE" "$JSON_LOG_FILE"
chmod 640 "$LOG_FILE" "$JSON_LOG_FILE"

log "=== Starting Enhanced AIDE Configuration (Shell Edition) ==="
log "Starting AIDE configuration"

cron
aide_rules
aide_post
activate_db
install_shipper
aide_timer

log "=== AIDE Configuration Complete ==="
log "SIEM events → $AIDE_LOG_DIR/aide_events.jsonl"
log "Timer: /etc/systemd/system/aidecheck.timer"
log "Shipper: $SHIPPER_PATH"
log "Use: export AIDE_SIEM_HTTP_URL=... && export AIDE_SIEM_TOKEN=... for direct shipping"