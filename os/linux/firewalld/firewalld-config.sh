#!/bin/bash
<<comment

  RW
  firewalld configuration script with CIS/STIG recommendations
  Replace INT= with your interface (e.g., eth0, wlo1)
  Monitor dropped/denied packets: dmesg | grep -i 'REJECT\|DROP'
  Watch logs: sudo tail -f /var/log/firewalld-dropped.log

comment

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "❌ This script must be run as root"
  exit 1
fi

# Define variables
INT="wlo1"                     # Replace with your network interface
SUBNET="192.168.0.0/16"        # Replace with your subnet
ZONE="wireless"                # Custom zone name
LOG_FILE="/var/log/firewalld-dropped.log"

if command -v dnf &>/dev/null; then
  PKG_MANAGER="dnf"
  INSTALL_CMD="$PKG_MANAGER install -y"
elif command -v apt &>/dev/null; then
  PKG_MANAGER="apt"
  INSTALL_CMD="$PKG_MANAGER install -y"
elif command -v apk &>/dev/null; then
  PKG_MANAGER="apk"
  INSTALL_CMD="$APK add --no-cache"
else
  echo "❌ No supported package manager found (dnf, apt, apk)"
  exit 1
fi

install_firewalld() {
  # Install firewalld and fail2ban (STIG V-230354)
  if ! command -v firewall-cmd &>/dev/null; then
    echo "Installing firewalld and fail2ban..."
    $INSTALL_CMD firewalld firewall-config fail2ban
  else
    echo "firewalld already installed"
  fi
}

disable_iptables() {
  # Disable and mask iptables (CIS RHEL8 3.4.2.1, STIG V-230535)
  if command -v iptables &>/dev/null; then
    echo "Disabling iptables..."
    systemctl disable iptables.service ip6tables.service --quiet
    systemctl mask iptables.service ip6tables.service --quiet
  else
    echo "iptables not installed"
  fi
}

enable_firewalld() {
  # Ensure firewalld is running and enabled (CIS RHEL8 3.4.2.2)
  echo "Starting and enabling firewalld..."
  systemctl unmask firewalld.service
  systemctl enable firewalld.service --quiet
  systemctl start firewalld.service --quiet
  if ! firewall-cmd --state &>/dev/null; then
    echo "❌ Failed to start firewalld"
    exit 1
  fi
}

disable_drifting() {
  # Harden firewalld.conf (CIS RHEL8 3.4.2.3)
  echo "Hardening firewalld configuration..."
  if ! grep -q '^AllowZoneDrifting=' /etc/firewalld/firewalld.conf; then
    echo "AllowZoneDrifting=no" >> /etc/firewalld/firewalld.conf
  else
    sed -i.bak 's/^AllowZoneDrifting=.*/AllowZoneDrifting=no/' /etc/firewalld/firewalld.conf
  fi
}

create_zone() {
  # Create and configure custom zone (CIS RHEL8 3.4.2.4)
  echo "Configuring $ZONE zone..."
  firewall-cmd --permanent --new-zone="$ZONE" || true # Ignore if zone exists
  firewall-cmd --permanent --zone="$ZONE" --set-target=DROP # Default deny policy (CIS RHEL8 3.4.2.5)
  firewall-cmd --permanent --zone="$ZONE" --change-interface="$INT"
  firewall-cmd --permanent --zone="$ZONE" --add-service=dhcpv6-client
}

configure_rate_limiting() {
  # Add services conditionally (CIS RHEL8 3.4.2.6: Minimize open ports)
  if command -v sshd &>/dev/null; then
    echo "Adding SSH service with rate limiting..."
    firewall-cmd --permanent --zone="$ZONE" --add-service=ssh
    # Rate limit SSH to mitigate brute-force attacks (STIG V-230354)
    firewall-cmd --permanent --zone="$ZONE" --add-rich-rule='rule service name="ssh" log prefix="SSH_Bruteforce: " level="warning" limit value="3/m" accept'
  fi

  if command -v cockpit &>/dev/null; then
    echo "Adding Cockpit service with rate limiting..."
    firewall-cmd --permanent --zone="$ZONE" --add-service=cockpit
    # Rate limit Cockpit (STIG V-230354)
    firewall-cmd --permanent --zone="$ZONE" --add-rich-rule='rule service name="cockpit" log prefix="Cockpit_Bruteforce: " level="warning" limit value="3/m" accept'
  fi
}

enable_conn_tracking() {
  # Enable connection tracking for stateful inspection (STIG V-230355)
  echo "Enabling stateful connection tracking..."
  firewall-cmd --permanent --zone="$ZONE" --add-rich-rule='rule family="ipv4" connection state="new,established,related" accept'
  firewall-cmd --permanent --zone="$ZONE" --add-rich-rule='rule family="ipv6" connection state="new,established,related" accept'
}

restrict_icmp() {
  # Restrict ICMP (STIG V-230353)
  echo "Restricting ICMP traffic..."
  firewall-cmd --permanent --zone="$ZONE" --add-icmp-block-inversion
  firewall-cmd --permanent --zone="$ZONE" --add-icmp-block=echo-request
}

drop_invalid_packets() {
  # Drop invalid packets (STIG V-230352)
  echo "Dropping invalid packets..."
  firewall-cmd --permanent --zone="$ZONE" --add-rich-rule='rule family="ipv4" source address="0.0.0.0/0" reject type="icmp-host-prohibited"'
  firewall-cmd --permanent --zone="$ZONE" --add-rich-rule='rule family="ipv6" source address="::/0" reject type="icmp6-adm-prohibited"'
}

restrict_access() {
  # Restrict source addresses to local subnet (CIS RHEL8 3.4.2.7)
  echo "Restricting source addresses to $SUBNET..."
  firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="rule family='ipv4' source address='$SUBNET' accept"
  firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="rule family='ipv4' source address='0.0.0.0/0' drop"
}

log_denied_packets() {
  # Log denied packets (CIS RHEL8 3.4.2.8)
  echo "Configuring logging for denied packets..."
  if ! grep -q '^LogDenied=' /etc/firewalld/firewalld.conf; then
    echo "LogDenied=all" >> /etc/firewalld/firewalld.conf
  else
    sed -i.bak 's/^LogDenied=.*/LogDenied=all/' /etc/firewalld/firewalld.conf
  fi
  firewall-cmd --set-log-denied=all

# Configure rsyslog for dropped/rejected packets (CIS RHEL8 4.2.1.4)
echo "Setting up rsyslog for firewall logs..."
touch "$LOG_FILE"
chmod 640 "$LOG_FILE"
chown root:adm "$LOG_FILE"
tee /etc/rsyslog.d/firewalld-dropped.conf <<EOF
:msg,contains,"_DROP" $LOG_FILE
:msg,contains,"_REJECT" $LOG_FILE
& stop
EOF
systemctl restart rsyslog.service --quiet
}

auditd_monitoring() {
  # Configure auditd to monitor firewall changes (CIS RHEL8 4.1.3)
  if command -v auditctl &>/dev/null; then
    echo "Configuring auditd to monitor firewall changes..."
    auditctl -w /etc/firewalld -p wa -k firewall_changes
  else
    echo "auditd not installed, skipping audit rule configuration"
  fi
}

fail2ban_config() {
# Configure fail2ban for SSH and Cockpit (STIG V-230354)
if command -v fail2ban-client &>/dev/null; then
  echo "Configuring fail2ban for SSH and Cockpit..."
  tee /etc/fail2ban/jail.d/firewalld.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
action = firewallcmd-ipset
logpath = /var/log/secure
maxretry = 3

[cockpit]
enabled = true
port = 9090
action = firewallcmd-ipset
logpath = /var/log/cockpit.log
maxretry = 3
EOF
  systemctl enable fail2ban --quiet
  systemctl start fail2ban --quiet
fi
}

post_conf_adjust() {
  # Disable unused zones to reduce attack surface
  echo "Removing unused zones..."
  for zone in $(firewall-cmd --get-zones | grep -v "$ZONE\|libvirt"); do
    firewall-cmd --permanent --delete-zone="$zone" || true
  done

  # Backup firewalld configuration
  echo "Backing up firewalld configuration..."
  cp -r /etc/firewalld /etc/firewalld.bak-$(date +%F)

  # Disable IPv6 if not needed (STIG V-230536)
  if ! ip addr show | grep -q inet6; then
    echo "Disabling IPv6..."
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p >/dev/null
  fi

  # Set default zone and reload
  echo "Setting $ZONE as default zone and reloading..."
  firewall-cmd --set-default-zone="$ZONE"
  firewall-cmd --reload
  systemctl restart firewalld.service --quiet
}

libvirt_config() {
# Libvirt configuration (if applicable)
fix_libvirt() {
  echo "Configuring libvirt zone..."
  systemctl unmask libvirtd.service
  systemctl enable libvirtd.service --quiet
  systemctl start libvirtd.service --quiet
  setfacl -m user:"$SUDO_USER":rw /var/run/libvirt/libvirt-sock

  # Create libvirt zone with strict rules (CIS RHEL8 3.4.2.4)
  tee /etc/firewalld/zones/libvirt.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<zone target="DROP">
  <short>libvirt</short>
  <description>Zone for libvirt virtual networks with strict access control.</description>
  <service name="dhcp"/>
  <service name="dhcpv6"/>
  <service name="dns"/>
  <service name="ssh"/>
  <protocol value="icmp"/>
  <protocol value="ipv6-icmp"/>
  <rule priority="32767">
    <drop/>
  </rule>
</zone>
EOF
  firewall-cmd --reload
  virsh net-start default
  virsh net-autostart default
}

if command -v virsh &>/dev/null; then
  echo "QEMU/KVM detected, configuring libvirt..."
  fix_libvirt
else
  echo "QEMU/KVM not installed"
fi
}

main() {
  install_firewalld
  disable_iptables
  enable_firewalld
  disable_drifting
  create_zone
  configure_rate_limiting
  #enable_conn_tracking
  restrict_icmp
  drop_invalid_packets
  restrict_access
  log_denied_packets
  auditd_monitoring
  fail2ban_config
  post_conf_adjust
}

main
echo "✅ Firewalld configuration complete"
firewall-cmd --get-active-zones