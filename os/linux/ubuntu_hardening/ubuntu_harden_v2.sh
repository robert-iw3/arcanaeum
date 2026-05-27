#!/bin/bash
# Ubuntu Hardening Script with CIS/STIG Compliance

set -euo pipefail

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
  echo "❌ Run me as root"
  exit 1
fi

# Variables
APT=$(command -v apt) || { echo "❌ APT not found"; exit 1; }
BACKUP_DIR="/root/hardening-backups-$(date +%F_%T)"
LOG_FILE="/var/log/hardening.log"
VERBOSE='N'
LXC=$(grep -q "container=lxc" /proc/1/environ && echo "1" || echo "0")
NTPSERVERPOOL="0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org 2.ubuntu.pool.ntp.org 3.ubuntu.pool.ntp.org pool.ntp.org"
TIMESYNCD="/etc/systemd/timesyncd.conf"
SYSTEMCONF="/etc/systemd/system.conf"
USERCONF="/etc/systemd/user.conf"
SCRIPT_COUNT=1

# Logging function
log() {
  echo "$(date '+%F %T'): $1" | tee -a "$LOG_FILE"
}

# Backup function
backup_file() {
  local file="$1"
  if [ -f "$file" ]; then
    mkdir -p "$BACKUP_DIR"
    cp "$file" "$BACKUP_DIR/$(basename "$file").$(date +%F_%T)"
    log "Backed up $file to $BACKUP_DIR"
  fi
}

function apport {
  log "[$SCRIPT_COUNT] Disabling apport, ubuntu-report, and popularity-contest"
  backup_file /etc/default/apport

  if command -v gsettings >/dev/null 2>&1; then
    gsettings set com.ubuntu.update-notifier show-apport-crashes false || log "Warning: Failed to disable apport crashes in gsettings"
  fi

  if command -v ubuntu-report >/dev/null 2>&1; then
    ubuntu-report -f send no || log "Warning: Failed to disable ubuntu-report"
  fi

  if [ -f /etc/default/apport ]; then
    sed -i 's/enabled=.*/enabled=0/' /etc/default/apport || log "Warning: Failed to modify /etc/default/apport"
    systemctl stop apport.service >/dev/null 2>&1 || true
    systemctl mask apport.service >/dev/null 2>&1 || log "Warning: Failed to mask apport.service"
  fi

  if dpkg -l | grep -q '^ii.*popularity-contest'; then
    $APT purge -y popularity-contest || log "Warning: Failed to purge popularity-contest"
  fi

  systemctl daemon-reload || log "Warning: Failed to reload systemd"
  [ "$VERBOSE" = "Y" ] && systemctl status apport.service --no-pager
  ((SCRIPT_COUNT++))
}

function aptget {
  log "[$SCRIPT_COUNT] Updating package index"
  $APT update || { log "Error: APT update failed"; exit 1; }
  ((SCRIPT_COUNT++))

  log "[$SCRIPT_COUNT] Upgrading installed packages"
  $APT -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y upgrade || { log "Error: APT upgrade failed"; exit 1; }
  ((SCRIPT_COUNT++))
}

function aptget_clean {
  log "[$SCRIPT_COUNT] Removing unused packages"
  $APT -y clean || log "Warning: APT clean failed"
  $APT -y autoremove || log "Warning: APT autoremove failed"

  for deb_clean in $(dpkg -l | grep '^rc' | awk '{print $2}'); do
    $APT purge -y "$deb_clean" || log "Warning: Failed to purge $deb_clean"
  done
  ((SCRIPT_COUNT++))
}

function aptget_configure {
  log "[$SCRIPT_COUNT] Configuring APT"
  local APT_CONF="/etc/apt/apt.conf.d/98-hardening-ubuntu"
  local PERIODIC_CONF="/etc/apt/apt.conf.d/10periodic"
  local UNATTENDED_CONF="/etc/apt/apt.conf.d/50unattended-upgrades"
  backup_file "$APT_CONF" "$PERIODIC_CONF" "$UNATTENDED_CONF"

  cat <<EOF > "$APT_CONF"
Acquire::http::AllowRedirect "false";
APT::Get::AllowUnauthenticated "false";
APT::Install-Recommends "false";
APT::Get::AutomaticRemove "true";
APT::Install-Suggests "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
Acquire::AllowInsecureRepositories "false";
APT::Sandbox::Seccomp "1";
EOF

  cat <<EOF > "$PERIODIC_CONF"
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

  cat <<EOF >> "$UNATTENDED_CONF"
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
EOF

  [ "$VERBOSE" = "Y" ] && cat "$APT_CONF" "$PERIODIC_CONF" "$UNATTENDED_CONF"
  ((SCRIPT_COUNT++))
}

function aptget_noexec {
  if [ "$LXC" = "1" ]; then
    log "[$SCRIPT_COUNT] Skipping /tmp noexec in LXC"
    return
  fi
  log "[$SCRIPT_COUNT] Configuring DPkg noexec for /tmp"
  backup_file /etc/apt/apt.conf.d/99noexec-tmp
  cat <<EOF > /etc/apt/apt.conf.d/99noexec-tmp
DPkg::Pre-Invoke {"mount -o remount,exec,nodev,nosuid /tmp";};
DPkg::Post-Invoke {"mount -o remount,mode=1777,strictatime,noexec,nodev,nosuid /tmp";};
EOF
  ((SCRIPT_COUNT++))
}

function remove_users {
  log "[$SCRIPT_COUNT] Removing unnecessary users"
  for user in games gnats irc list news sync uucp; do
    if id "$user" >/dev/null 2>&1; then
      pkill -u "$user" 2>/dev/null || true
      if userdel -r "$user" >/dev/null 2>&1; then
        log "User $user deleted successfully"
      else
        log "Warning: Failed to delete user $user"
      fi
    else
      [ "$VERBOSE" = "Y" ] && log "User $user does not exist"
    fi
  done
  ((SCRIPT_COUNT++))
}

function timesyncd {
  log "[$SCRIPT_COUNT] Configuring systemd-timesyncd"
  backup_file "$TIMESYNCD"
  cat <<EOF > "$TIMESYNCD"
[Time]
NTP=$NTPSERVERPOOL
FallbackNTP=pool.ntp.org
RootDistanceMaxSec=1
EOF
  systemctl restart systemd-timesyncd || log "Warning: Failed to restart systemd-timesyncd"
  timedatectl set-ntp true || log "Warning: Failed to enable NTP"
  [ "$VERBOSE" = "Y" ] && { systemctl status systemd-timesyncd --no-pager; timedatectl; }
  ((SCRIPT_COUNT++))
}

function systemdconf {
  log "[$SCRIPT_COUNT] Configuring systemd system and user settings"
  backup_file "$SYSTEMCONF" "$USERCONF"
  sed -i 's/^#DumpCore=.*/DumpCore=no/' "$SYSTEMCONF" || log "Warning: Failed to modify $SYSTEMCONF"
  sed -i 's/^#CrashShell=.*/CrashShell=no/' "$SYSTEMCONF" || log "Warning: Failed to modify $SYSTEMCONF"
  sed -i 's/^#DefaultLimitCORE=.*/DefaultLimitCORE=0/' "$SYSTEMCONF" || log "Warning: Failed to modify $SYSTEMCONF"
  sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=1024/' "$SYSTEMCONF" || log "Warning: Failed to modify $SYSTEMCONF"
  sed -i 's/^#DefaultLimitNPROC=.*/DefaultLimitNPROC=1024/' "$SYSTEMCONF" || log "Warning: Failed to modify $SYSTEMCONF"

  sed -i 's/^#DefaultLimitCORE=.*/DefaultLimitCORE=0/' "$USERCONF" || log "Warning: Failed to modify $USERCONF"
  sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=1024/' "$USERCONF" || log "Warning: Failed to modify $USERCONF"
  sed -i 's/^#DefaultLimitNPROC=.*/DefaultLimitNPROC=1024/' "$USERCONF" || log "Warning: Failed to modify $USERCONF"

  systemctl daemon-reload || log "Warning: Failed to reload systemd"
  [ "$VERBOSE" = "Y" ] && cat "$SYSTEMCONF" "$USERCONF"
  ((SCRIPT_COUNT++))
}

function kernel_params {
  log "[$SCRIPT_COUNT] Configuring kernel parameters"
  backup_file /etc/sysctl.d/99-hardening.conf
  cat <<EOF > /etc/sysctl.d/99-hardening.conf
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.ip_forward = 0
fs.suid_dumpable = 0
EOF
  sysctl -p /etc/sysctl.d/99-hardening.conf || log "Warning: Failed to apply kernel parameters"
  ((SCRIPT_COUNT++))
}

function disable_filesystems {
  log "[$SCRIPT_COUNT] Disabling unnecessary filesystems"
  backup_file /etc/modprobe.d/CIS.conf
  cat <<EOF > /etc/modprobe.d/CIS.conf
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
EOF
  ((SCRIPT_COUNT++))
}

function file_permissions {
  log "[$SCRIPT_COUNT] Setting file permissions"
  chmod 644 /etc/passwd /etc/group || log "Warning: Failed to set permissions on /etc/passwd or /etc/group"
  chmod 600 /etc/shadow || log "Warning: Failed to set permissions on /etc/shadow"
  ((SCRIPT_COUNT++))
}

function password_policy {
  log "[$SCRIPT_COUNT] Configuring password policies"
  backup_file /etc/login.defs
  sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs || log "Warning: Failed to set PASS_MAX_DAYS"
  sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs || log "Warning: Failed to set PASS_MIN_DAYS"
  sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs || log "Warning: Failed to set PASS_WARN_AGE"
  ((SCRIPT_COUNT++))
}

function ssh_hardening {
  log "[$SCRIPT_COUNT] Hardening SSH configuration"
  backup_file /etc/ssh/sshd_config
  cat <<EOF >> /etc/ssh/sshd_config
PermitRootLogin no
PasswordAuthentication no
EOF
  systemctl restart sshd || log "Warning: Failed to restart sshd"
  [ "$VERBOSE" = "Y" ] && cat /etc/ssh/sshd_config
  ((SCRIPT_COUNT++))
}

# Main execution
if command -v apt >/dev/null 2>&1; then
  log "Starting Ubuntu hardening"
  mkdir -p "$(dirname "$LOG_FILE")"
  touch "$LOG_FILE"
  apport
  aptget
  aptget_clean
  aptget_configure
  aptget_noexec
  remove_users
  timesyncd
  systemdconf
  kernel_params
  disable_filesystems
  file_permissions
  password_policy
  ssh_hardening
  log "Hardening complete"
else
  log "Error: This is not an Ubuntu/Debian system"
  exit 1
fi