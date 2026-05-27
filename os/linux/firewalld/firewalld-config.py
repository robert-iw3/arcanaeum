import argparse
import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

# Configuration
LOG_FILE = "/var/log/firewalld_config.log"
JSON_LOG_FILE = "/var/log/firewalld_config.json"
BACKUP_DIR = "/var/backups/firewalld"
FIREWALLD_CONF = "/etc/firewalld/firewalld.conf"
RSYSLOG_CONF = "/etc/rsyslog.d/firewalld-dropped.conf"
FAIL2BAN_CONF = "/etc/fail2ban/jail.d/firewalld.local"
LOG_DENIED_FILE = "/var/log/firewalld-dropped.log"
AUDIT_RULES_FILE = "/etc/audit/rules.d/firewalld.rules"
LIBVIRT_ZONE_FILE = "/etc/firewalld/zones/libvirt.xml"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ],
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
logger = logging.getLogger(__name__)

def setup_json_logging():
    """Initialize JSON log file."""
    Path(JSON_LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(JSON_LOG_FILE).touch()
    os.chown(JSON_LOG_FILE, 0, 0)
    os.chmod(JSON_LOG_FILE, 0o640)

def log_json(status: str, message: str):
    """Log to JSON file."""
    with open(JSON_LOG_FILE, "a") as f:
        json.dump({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "status": status, "message": message}, f)
        f.write("\n")

def check_privileges():
    """Check for root or CAP_NET_ADMIN, CAP_DAC_OVERRIDE."""
    try:
        result = subprocess.run(["capsh", "--print"], capture_output=True, text=True, check=True)
        if "cap_net_admin" not in result.stdout or "cap_dac_override" not in result.stdout:
            logger.error("This script requires root or CAP_NET_ADMIN, CAP_DAC_OVERRIDE privileges")
            log_json("ERROR", "Missing required privileges")
            exit(1)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to check capabilities: {e}")
        log_json("ERROR", f"Failed to check capabilities: {e}")
        exit(1)

def check_deps():
    """Check for required dependencies."""
    deps = ["firewall-cmd", "systemctl", "rsyslogd", "setfacl", "auditctl"]
    for cmd in deps:
        if not shutil.which(cmd):
            logger.warning(f"{cmd} not installed, some features may be skipped")
            log_json("WARNING", f"{cmd} not installed")

def validate_path(path: str) -> Path:
    """Validate and resolve a path."""
    path = Path(path).resolve()
    if ".." in str(path):
        logger.error(f"Invalid path: {path}")
        log_json("ERROR", f"Invalid path: {path}")
        exit(1)
    return path

def get_package_manager():
    """Determine package manager and install command."""
    for pm, cmd in [("dnf", "dnf install -y"), ("apt", "apt install -y"), ("apk", "apk add --no-cache")]:
        if shutil.which(pm):
            return pm, cmd
    logger.error("No supported package manager found (dnf, apt, apk)")
    log_json("ERROR", "No supported package manager found")
    exit(1)

def install_firewalld(pkg_manager: str, install_cmd: str):
    """Install firewalld and fail2ban (STIG V-230354)."""
    logger.info("Checking firewalld installation")
    log_json("INFO", "Checking firewalld installation")
    if not shutil.which("firewall-cmd"):
        logger.info("Installing firewalld and fail2ban...")
        log_json("INFO", "Installing firewalld and fail2ban")
        subprocess.run(f"{install_cmd} firewalld firewall-config fail2ban", shell=True, check=True)
    else:
        logger.info("firewalld already installed")
        log_json("INFO", "firewalld already installed")

def disable_iptables():
    """Disable and mask iptables (CIS RHEL8 3.4.2.1, STIG V-230535)."""
    logger.info("Disabling iptables")
    log_json("INFO", "Disabling iptables")
    if shutil.which("iptables"):
        subprocess.run(["systemctl", "disable", "iptables.service", "ip6tables.service"], check=True, capture_output=True)
        subprocess.run(["systemctl", "mask", "iptables.service", "ip6tables.service"], check=True, capture_output=True)
        logger.info("iptables disabled and masked")
        log_json("INFO", "iptables disabled and masked")
    else:
        logger.info("iptables not installed")
        log_json("INFO", "iptables not installed")

def enable_firewalld():
    """Ensure firewalld is running and enabled (CIS RHEL8 3.4.2.2)."""
    logger.info("Starting and enabling firewalld")
    log_json("INFO", "Starting and enabling firewalld")
    subprocess.run(["systemctl", "unmask", "firewalld.service"], check=True)
    subprocess.run(["systemctl", "enable", "firewalld.service"], check=True, capture_output=True)
    subprocess.run(["systemctl", "start", "firewalld.service"], check=True, capture_output=True)
    try:
        subprocess.run(["firewall-cmd", "--state"], check=True, capture_output=True)
        logger.info("firewalld started successfully")
        log_json("INFO", "firewalld started successfully")
    except subprocess.CalledProcessError:
        logger.error("Failed to start firewalld")
        log_json("ERROR", "Failed to start firewalld")
        exit(1)

def disable_drifting():
    """Harden firewalld.conf (CIS RHEL8 3.4.2.3)."""
    firewalld_conf = validate_path(FIREWALLD_CONF)
    logger.info("Hardening firewalld configuration")
    log_json("INFO", "Hardening firewalld configuration")
    backup_file(firewalld_conf)
    with open(firewalld_conf, "r") as f:
        content = f.read()
    if "AllowZoneDrifting=" not in content:
        content += "\nAllowZoneDrifting=no\n"
    else:
        content = content.replace(r"AllowZoneDrifting=.*", "AllowZoneDrifting=no")
    with open(firewalld_conf, "w") as f:
        f.write(content)
    logger.info("Set AllowZoneDrifting=no")
    log_json("INFO", "Set AllowZoneDrifting=no")

def create_zone(zone: str, interface: str):
    """Create and configure custom zone (CIS RHEL8 3.4.2.4)."""
    logger.info(f"Configuring {zone} zone")
    log_json("INFO", f"Configuring {zone} zone")
    subprocess.run(["firewall-cmd", "--permanent", "--new-zone", zone], capture_output=True, check=False)  # Ignore if exists
    subprocess.run(["firewall-cmd", "--permanent", "--zone", zone, "--set-target", "DROP"], check=True)
    subprocess.run(["firewall-cmd", "--permanent", "--zone", zone, "--change-interface", interface], check=True)
    subprocess.run(["firewall-cmd", "--permanent", "--zone", zone, "--add-service", "dhcpv6-client"], check=True)
    logger.info(f"Created and configured {zone} zone")
    log_json("INFO", f"Created and configured {zone} zone")

def configure_rate_limiting(zone: str):
    """Add services with rate limiting (CIS RHEL8 3.4.2.6, STIG V-230354)."""
    logger.info("Configuring rate-limited services")
    log_json("INFO", "Configuring rate-limited services")
    if shutil.which("sshd"):
        logger.info("Adding SSH service with rate limiting")
        log_json("INFO", "Adding SSH service with rate limiting")
        subprocess.run(["firewall-cmd", "--permanent", "--zone", zone, "--add-service", "ssh"], check=True)
        subprocess.run(["firewall-cmd", "--permanent", "--zone", zone, "--add-rich-rule", 'rule service name="ssh" log prefix="SSH_Bruteforce: " level="warning" limit value="3/m" accept'], check=True)
    if shutil.which("cockpit"):
        logger.info("Adding Cockpit service with rate limiting")
        log_json("INFO", "Adding Cockpit service with rate limiting")
        subprocess.run(["firewall-cmd", "--permanent", "--zone", zone, "--add-service", "cockpit"], check=True)
        subprocess.run(["firewall-cmd", "--permanent", "--zone", zone, "--add-rich-rule", 'rule service name="cockpit" log prefix="Cockpit_Bruteforce: " level="warning" limit value="3/m" accept'], check=True)

def enable_conn_tracking(zone: str):
    """Enable connection tracking (STIG V-230355)."""
    logger.info("Enabling stateful connection tracking")
    log_json("INFO", "Enabling stateful connection tracking")
    subprocess.run(["firewall-cmd", "--permanent", "--zone", zone, "--add-rich-rule", 'rule family="ipv4" connection state="new,established,related" accept'], check=True)
    subprocess.run(["firewall-cmd", "--permanent", "--zone", zone, "--add-rich-rule", 'rule family="ipv6" connection state="new,established,related" accept'], check=True)

def restrict_icmp(zone: str):
    """Restrict ICMP traffic (STIG V-230353)."""
    logger.info("Restricting ICMP traffic")
    log_json("INFO", "Restricting ICMP traffic")
    subprocess.run(["firewall-cmd", "--permanent", "--zone", zone, "--add-icmp-block-inversion"], check=True)
    subprocess.run(["firewall-cmd", "--permanent", "--zone", zone, "--add-icmp-block", "echo-request"], check=True)

def drop_invalid_packets(zone: str):
    """Drop invalid packets (STIG V-230352)."""
    logger.info("Dropping invalid packets")
    log_json("INFO", "Dropping invalid packets")
    subprocess.run(["firewall-cmd", "--permanent", "--zone", zone, "--add-rich-rule", 'rule family="ipv4" source address="0.0.0.0/0" reject type="icmp-host-prohibited"'], check=True)
    subprocess.run(["firewall-cmd", "--permanent", "--zone", zone, "--add-rich-rule", 'rule family="ipv6" source address="::/0" reject type="icmp6-adm-prohibited"'], check=True)

def restrict_access(zone: str, subnet: str):
    """Restrict source addresses to subnet (CIS RHEL8 3.4.2.7)."""
    logger.info(f"Restricting source addresses to {subnet}")
    log_json("INFO", f"Restricting source addresses to {subnet}")
    subprocess.run(["firewall-cmd", "--permanent", "--zone", zone, "--add-rich-rule", f"rule family='ipv4' source address='{subnet}' accept"], check=True)
    subprocess.run(["firewall-cmd", "--permanent", "--zone", zone, "--add-rich-rule", "rule family='ipv4' source address='0.0.0.0/0' drop"], check=True)

def log_denied_packets():
    """Configure logging for denied packets (CIS RHEL8 3.4.2.8)."""
    logger.info("Configuring logging for denied packets")
    log_json("INFO", "Configuring logging for denied packets")
    firewalld_conf = validate_path(FIREWALLD_CONF)
    backup_file(firewalld_conf)
    with open(firewalld_conf, "r") as f:
        content = f.read()
    if "LogDenied=" not in content:
        content += "\nLogDenied=all\n"
    else:
        content = content.replace(r"LogDenied=.*", "LogDenied=all")
    with open(firewalld_conf, "w") as f:
        f.write(content)
    subprocess.run(["firewall-cmd", "--set-log-denied=all"], check=True)

    log_file = validate_path(LOG_DENIED_FILE)
    log_file.touch()
    os.chown(log_file, 0, os.getgrnam("adm").gr_gid)
    os.chmod(log_file, 0o640)
    rsyslog_conf = validate_path(RSYSLOG_CONF)
    backup_file(rsyslog_conf)
    with open(rsyslog_conf, "w") as f:
        f.write(f""":msg,contains,"_DROP" {log_file}
:msg,contains,"_REJECT" {log_file}
& stop
""")
    subprocess.run(["systemctl", "restart", "rsyslog.service"], check=True, capture_output=True)

def auditd_monitoring():
    """Configure auditd to monitor firewall changes (CIS RHEL8 4.1.3)."""
    if shutil.which("auditctl"):
        logger.info("Configuring auditd to monitor firewall changes")
        log_json("INFO", "Configuring auditd to monitor firewall changes")
        audit_rules = validate_path(AUDIT_RULES_FILE)
        with open(audit_rules, "w") as f:
            f.write(f"-w /etc/firewalld -p wa -k firewall_changes\n")
        os.chmod(audit_rules, 0o640)
        subprocess.run(["augenrules", "--load"], check=True)
        logger.info("Audit rules added for firewall changes")
        log_json("INFO", "Audit rules added for firewall changes")
    else:
        logger.warning("auditd not installed, skipping audit rule configuration")
        log_json("WARNING", "auditd not installed")

def fail2ban_config():
    """Configure fail2ban for SSH and Cockpit (STIG V-230354)."""
    if shutil.which("fail2ban-client"):
        logger.info("Configuring fail2ban for SSH and Cockpit")
        log_json("INFO", "Configuring fail2ban for SSH and Cockpit")
        ssh_log = "/var/log/auth.log" if Path("/var/log/auth.log").exists() else "/var/log/secure"
        fail2ban_conf = validate_path(FAIL2BAN_CONF)
        backup_file(fail2ban_conf)
        with open(fail2ban_conf, "w") as f:
            f.write(f"""[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
action = firewallcmd-ipset
logpath = {ssh_log}
maxretry = 3

[cockpit]
enabled = true
port = 9090
action = firewallcmd-ipset
logpath = /var/log/cockpit.log
maxretry = 3
""")
        subprocess.run(["systemctl", "enable", "fail2ban"], check=True, capture_output=True)
        subprocess.run(["systemctl", "start", "fail2ban"], check=True, capture_output=True)
        logger.info("fail2ban configured")
        log_json("INFO", "fail2ban configured")

def backup_file(file: Path):
    """Backup a file before modification."""
    if file.exists():
        backup_path = Path(BACKUP_DIR) / f"{file.name}.{time.strftime('%Y%m%d')}"
        Path(BACKUP_DIR).mkdir(parents=True, exist_ok=True)
        shutil.copy2(file, backup_path)
        logger.info(f"Backed up {file} to {backup_path}")
        log_json("INFO", f"Backed up {file} to {backup_path}")

def post_conf_adjust(zone: str):
    """Disable unused zones, backup config, and set default zone."""
    logger.info("Removing unused zones")
    log_json("INFO", "Removing unused zones")
    result = subprocess.run(["firewall-cmd", "--get-zones"], capture_output=True, text=True, check=True)
    for z in result.stdout.split():
        if z not in [zone, "libvirt"]:
            subprocess.run(["firewall-cmd", "--permanent", "--delete-zone", z], capture_output=True, check=False)

    logger.info("Backing up firewalld configuration")
    log_json("INFO", "Backing up firewalld configuration")
    backup_dir = Path(BACKUP_DIR) / f"firewalld.{time.strftime('%Y%m%d')}"
    shutil.copytree("/etc/firewalld", backup_dir, dirs_exist_ok=True)

    if not subprocess.run("ip addr show | grep inet6", shell=True, capture_output=True, text=True).stdout:
        logger.info("IPv6 not detected, prompting to disable")
        log_json("INFO", "IPv6 not detected, prompting to disable")
        choice = input("Disable IPv6? (y/n): ").lower()
        if choice == "y":
            with open("/etc/sysctl.conf", "a") as f:
                f.write("net.ipv6.conf.all.disable_ipv6 = 1\n")
            subprocess.run(["sysctl", "-p"], check=True, capture_output=True)
            logger.info("IPv6 disabled")
            log_json("INFO", "IPv6 disabled")

    logger.info(f"Setting {zone} as default zone and reloading")
    log_json("INFO", f"Setting {zone} as default zone and reloading")
    subprocess.run(["firewall-cmd", "--set-default-zone", zone], check=True)
    subprocess.run(["firewall-cmd", "--reload"], check=True)
    subprocess.run(["systemctl", "restart", "firewalld.service"], check=True, capture_output=True)

def libvirt_config(sudo_user: Optional[str]):
    """Configure libvirt zone if QEMU/KVM is installed."""
    if shutil.which("virsh"):
        logger.info("Configuring libvirt zone")
        log_json("INFO", "Configuring libvirt zone")
        subprocess.run(["systemctl", "unmask", "libvirtd.service"], check=True)
        subprocess.run(["systemctl", "enable", "libvirtd.service"], check=True, capture_output=True)
        subprocess.run(["systemctl", "start", "libvirtd.service"], check=True, capture_output=True)
        if sudo_user:
            subprocess.run(["setfacl", "-m", f"user:{sudo_user}:rw", "/var/run/libvirt/libvirt-sock"], check=True)

        libvirt_zone = validate_path(LIBVIRT_ZONE_FILE)
        backup_file(libvirt_zone)
        with open(libvirt_zone, "w") as f:
            f.write("""<?xml version="1.0" encoding="utf-8"?>
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
""")
        subprocess.run(["firewall-cmd", "--reload"], check=True)
        subprocess.run(["virsh", "net-start", "default"], check=True)
        subprocess.run(["virsh", "net-autostart", "default"], check=True)
        logger.info("libvirt zone configured")
        log_json("INFO", "libvirt zone configured")
    else:
        logger.info("QEMU/KVM not installed")
        log_json("INFO", "QEMU/KVM not installed")

def main():
    parser = argparse.ArgumentParser(description="Configure firewalld with CIS/STIG recommendations")
    parser.add_argument("--interface", "-i", default="wlo1", help="Network interface (default: wlo1)")
    parser.add_argument("--subnet", "-s", default="192.168.0.0/16", help="Subnet for access restriction (default: 192.168.0.0/16)")
    parser.add_argument("--zone", "-z", default="wireless", help="Custom zone name (default: wireless)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed command output")
    parser.add_argument("--json", "-j", action="store_true", help="Output logs in JSON format")
    args = parser.parse_args()

    # Initialize logging
    Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(LOG_FILE).touch()
    os.chown(LOG_FILE, 0, 0)
    os.chmod(LOG_FILE, 0o640)
    if args.json:
        setup_json_logging()

    logger.info("Starting firewalld configuration")
    log_json("INFO", "Starting firewalld configuration")

    check_privileges()
    check_deps()
    pkg_manager, install_cmd = get_package_manager()
    install_firewalld(pkg_manager, install_cmd)
    disable_iptables()
    enable_firewalld()
    disable_drifting()
    create_zone(args.zone, args.interface)
    configure_rate_limiting(args.zone)
    enable_conn_tracking(args.zone)
    restrict_icmp(args.zone)
    drop_invalid_packets(args.zone)
    restrict_access(args.zone, args.subnet)
    log_denied_packets()
    auditd_monitoring()
    fail2ban_config()
    post_conf_adjust(args.zone)
    libvirt_config(os.environ.get("SUDO_USER"))

    logger.info("Firewalld configuration complete")
    log_json("INFO", "Firewalld configuration complete")
    result = subprocess.run(["firewall-cmd", "--get-active-zones"], capture_output=True, text=True, check=True)
    logger.info(result.stdout)
    log_json("INFO", result.stdout)

if __name__ == "__main__":
    main()