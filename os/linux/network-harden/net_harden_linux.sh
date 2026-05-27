#!/bin/bash

function set_iptables {
    # Flush/Delete firewall rules
    iptables -F
    iptables -X
    iptables -Z

    # Βlock null packets (DoS)
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

    # Block syn-flood attacks (DoS)
    iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

    # Block XMAS packets (DoS)
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

    # Allow internal traffic on the loopback device
    iptables -A INPUT -i lo -j ACCEPT

    # Allow ssh access
    iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT

    # Allow established connections
    iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow outgoing connections
    iptables -P OUTPUT ACCEPT

    # Set default deny firewall policy
    iptables -P INPUT DROP

    # Set default deny firewall policy
    iptables -P FORWARD DROP

    # Save rules
    iptables-save > /etc/iptables/rules.v4

    # Apply and confirm
    iptables-apply -t 40 /etc/iptables/rules.v4
}

# Disable IP forwarding
sed -i "s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=0/" /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=0

# Disable packet redirect sending
sed -i "/net.ipv4.conf.all.send_redirects.*/s/^#//g" /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects=0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0

# Disable source routed packets
sed -i "/net.ipv4.conf.all.accept_source_route.*/s/^#//g" /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route=0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0

# Disable ICMP redirects
sed -i "/net.ipv4.conf.all.accept_redirects.*/s/^#//g" /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects=0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0

# Disable secure ICMP redirects
sed -i "/ net.ipv4.conf.all.secure_redirects.*/s/^# //g" /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects=0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0

# Log suspicious packets
sed -i "/net.ipv4.conf.all.log_martians.*/s/^#//g" /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians=1" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1

# Ignore broadcast ICMP requests
echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1

# Enable Bad Error Message Protection
echo "net.ipv4.icmp_ignore_bogus_error_responses=1" >> /etc/sysctl.conf
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1

# Enable RFC-recommended Source Route Validation
sed -i "/net.ipv4.conf.all.rp_filter.*/s/^#//g" /etc/sysctl.conf
sed -i "/net.ipv4.conf.default.rp_filter.*/s/^#//g" /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1

# Enable TCP SYN Cookies
sed -i "/net.ipv4.tcp_syncookies.*/s/^#//g" /etc/sysctl.conf
sysctl -w net.ipv4.tcp_syncookies=1

# Install TCP Wrappers
apt -y install tcpd

chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow
chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny

sysctl -w net.ipv4.route.flush=1

if command -v iptables &> /dev/null; then
  echo "iptables exists"
  set_iptables
else
  echo "iptables does not exist"
fi