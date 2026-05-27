#!/usr/bin/env python3
import argparse
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Tuple

# Configuration
VERSION = "1.0"
CONFIG_FILE = Path("/etc/linux-sentinel/firewall.conf")
LOG_DIR = Path("/var/log/linux-sentinel") if os.geteuid() == 0 else Path.home() / ".linux-sentinel/logs"
IPTABLES_RULES_FILE = Path("/etc/iptables/rules.v4")
IP6TABLES_RULES_FILE = Path("/etc/iptables/rules.v6")
SYSCTL_CONF_DIR = Path("/etc/sysctl.d")
SYSCTL_CONF_FILE = SYSCTL_CONF_DIR / "99-linux-sentinel.conf"
ALLOWED_SSH_IPS = ["192.168.0.0/16", "10.0.0.0/8"]
SSH_RATE_LIMIT = "3/min"
LOG_FILE = LOG_DIR / "firewall_setup.log"

# Setup logging
LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ],
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
logger = logging.getLogger(__name__)

def check_dependencies() -> bool:
    """Check for required tools."""
    required = ["iptables", "ip6tables", "sysctl", "iptables-save", "ip6tables-save"]
    optional = ["iptables-apply", "firewall-cmd", "apt", "dnf", "yum", "tcpd"]
    missing = []

    for cmd in required:
        if shutil.which(cmd) is None:
            missing.append(cmd)

    for cmd in missing:
        logger.error(f"Required tool missing: {cmd}")

    available = {cmd: shutil.which(cmd) is not None for cmd in optional}
    logger.info(f"Optional tools: {', '.join(f'{k}={v}' for k, v in available.items())}")

    return not missing

def load_config() -> dict:
    """Load configuration from file or use defaults."""
    config = {
        "ALLOWED_SSH_IPS": ALLOWED_SSH_IPS,
        "SSH_RATE_LIMIT": SSH_RATE_LIMIT,
        "USE_FIREWALLD": False,
        "ENABLE_IPV6": True,
        "LOG_DROPPED_PACKETS": True
    }
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                for line in f:
                    if line.strip() and not line.startswith("#"):
                        key, value = line.strip().split("=", 1)
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        if key in config:
                            if key == "ALLOWED_SSH_IPS":
                                config[key] = [x.strip() for x in value.split(",")]
                            elif key == "USE_FIREWALLD":
                                config[key] = value.lower() == "true"
                            else:
                                config[key] = value
            logger.info(f"Configuration loaded from {CONFIG_FILE}")
        except Exception as e:
            logger.warning(f"Config file error: {e}, using defaults")
    return config

def run_command(cmd: List[str], check: bool = True) -> Tuple[bool, str]:
    """Run a shell command and return success status and output."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=check)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {' '.join(cmd)} - {e.stderr}")
        return False, e.stderr

def backup_file(file: Path) -> bool:
    """Backup a file with timestamp."""
    if file.exists():
        backup_path = file.with_suffix(f".backup.{int(datetime.now().timestamp())}")
        try:
            shutil.copy2(file, backup_path)
            logger.info(f"Backed up {file} to {backup_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to backup {file}: {e}")
            return False
    return True

def set_iptables(config: dict) -> bool:
    """Configure iptables and ip6tables rules."""
    logger.info("Configuring iptables and ip6tables...")

    # Commands for iptables and ip6tables
    tables = ["iptables"]
    if config["ENABLE_IPV6"]:
        tables.append("ip6tables")

    for table in tables:
        # Flush and delete existing rules
        run_command([table, "-F"])
        run_command([table, "-X"])
        run_command([table, "-Z"])

        # Block null packets
        run_command([table, "-A", "INPUT", "-p", "tcp", "--tcp-flags", "ALL", "NONE", "-j", "LOG", "--log-prefix", "NULL_PACKET: "]) if config["LOG_DROPPED_PACKETS"] else None
        run_command([table, "-A", "INPUT", "-p", "tcp", "--tcp-flags", "ALL", "NONE", "-j", "DROP"])

        # Block SYN flood attacks
        run_command([table, "-A", "INPUT", "-p", "tcp", "!", "--syn", "-m", "state", "--state", "NEW", "-j", "LOG", "--log-prefix", "SYN_FLOOD: "]) if config["LOG_DROPPED_PACKETS"] else None
        run_command([table, "-A", "INPUT", "-p", "tcp", "!", "--syn", "-m", "state", "--state", "NEW", "-j", "DROP"])

        # Block XMAS packets
        run_command([table, "-A", "INPUT", "-p", "tcp", "--tcp-flags", "ALL", "ALL", "-j", "LOG", "--log-prefix", "XMAS_PACKET: "]) if config["LOG_DROPPED_PACKETS"] else None
        run_command([table, "-A", "INPUT", "-p", "tcp", "--tcp-flags", "ALL", "ALL", "-j", "DROP"])

        # Allow loopback traffic
        run_command([table, "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])

        # Allow SSH with rate limiting
        for ip in config["ALLOWED_SSH_IPS"]:
            run_command([table, "-A", "INPUT", "-p", "tcp", "--dport", "22", "-s", ip, "-m", "recent", "--name", "SSH", "--set"])
            run_command([table, "-A", "INPUT", "-p", "tcp", "--dport", "22", "-s", ip, "-m", "recent", "--name", "SSH", "--rcheck", "--seconds", "60", "--hitcount", "4", "-j", "LOG", "--log-prefix", "SSH_RATE_LIMIT: "]) if config["LOG_DROPPED_PACKETS"] else None
            run_command([table, "-A", "INPUT", "-p", "tcp", "--dport", "22", "-s", ip, "-m", "recent", "--name", "SSH", "--rcheck", "--seconds", "60", "--hitcount", "4", "-j", "DROP"])
            run_command([table, "-A", "INPUT", "-p", "tcp", "--dport", "22", "-s", ip, "-j", "ACCEPT"])

        # Allow established/related connections
        run_command([table, "-I", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])

        # Allow outgoing traffic
        run_command([table, "-P", "OUTPUT", "ACCEPT"])

        # Set default deny policies
        run_command([table, "-P", "INPUT", "DROP"])
        run_command([table, "-P", "FORWARD", "DROP"])

        # Log dropped packets
        if config["LOG_DROPPED_PACKETS"]:
            run_command([table, "-A", "INPUT", "-j", "LOG", "--log-prefix", "DROPPED: "])

    # Save rules
    backup_file(IPTABLES_RULES_FILE)
    backup_file(IP6TABLES_RULES_FILE)
    run_command(["iptables-save", "-f", str(IPTABLES_RULES_FILE)])
    if config["ENABLE_IPV6"]:
        run_command(["ip6tables-save", "-f", str(IP6TABLES_RULES_FILE)])

    # Apply rules with timeout if iptables-apply exists
    if shutil.which("iptables-apply"):
        success, _ = run_command(["iptables-apply", "-t", "40", str(IPTABLES_RULES_FILE)])
        if config["ENABLE_IPV6"]:
            success &= run_command(["iptables-apply", "-t", "40", str(IP6TABLES_RULES_FILE)])[0]
        return success
    return True

def set_firewalld(config: dict) -> bool:
    """Configure firewalld rules."""
    if not shutil.which("firewall-cmd"):
        logger.warning("firewalld not available - skipping")
        return False

    logger.info("Configuring firewalld...")

    # Create custom zone
    zone_file = Path("/etc/firewalld/zones/linux-sentinel.xml")
    backup_file(zone_file)
    zone_content = """<?xml version="1.0" encoding="utf-8"?>
<zone>
  <short>linux Sentinel Firewall</short>
  <description>Firewall rules for linux Sentinel security monitoring</description>
  <interface name="lo"/>
  <service name="ssh"/>
"""
    for ip in config["ALLOWED_SSH_IPS"]:
        zone_content += f"""  <rule family="ipv4">
    <source address="{ip}"/>
    <service name="ssh"/>
    <limit value="{config['SSH_RATE_LIMIT']}"/>
    <accept/>
  </rule>
"""
    if config["ENABLE_IPV6"]:
        for ip in config["ALLOWED_SSH_IPS"]:
            if ":" in ip:  # Only add IPv6 addresses
                zone_content += f"""  <rule family="ipv6">
    <source address="{ip}"/>
    <service name="ssh"/>
    <limit value="{config['SSH_RATE_LIMIT']}"/>
    <accept/>
  </rule>
"""
    zone_content += """  <rule family="ipv4">
    <protocol value="tcp"/>
    <tcp-flags mask="ALL" value="NONE"/>
    <log prefix="NULL_PACKET: "/>
    <reject/>
  </rule>
  <rule family="ipv4">
    <protocol value="tcp"/>
    <tcp-flags mask="ALL" value="ALL"/>
    <log prefix="XMAS_PACKET: "/>
    <reject/>
  </rule>
  <rule family="ipv4">
    <protocol value="tcp"/>
    <match state="NEW"/>
    <tcp-flags mask="SYN" value="!SYN"/>
    <log prefix="SYN_FLOOD: "/>
    <reject/>
  </rule>
  <rule family="ipv4">
    <match state="ESTABLISHED,RELATED"/>
    <accept/>
  </rule>
  <rule family="ipv4">
    <log prefix="DROPPED: "/>
    <reject/>
  </rule>
</zone>"""

    zone_file.write_text(zone_content)

    # Apply firewalld configuration
    commands = [
        ["firewall-cmd", "--permanent", "--new-zone-from-file", str(zone_file), "--name=linux-sentinel"],
        ["firewall-cmd", "--permanent", "--zone=linux-sentinel", "--add-interface=eth0"],
        ["firewall-cmd", "--reload"]
    ]
    success = True
    for cmd in commands:
        success &= run_command(cmd)[0]
    return success

def set_sysctl_settings() -> bool:
    """Configure sysctl settings."""
    logger.info("Configuring sysctl settings...")

    settings = {
        "net.ipv4.ip_forward": 0,
        "net.ipv4.conf.all.send_redirects": 0,
        "net.ipv4.conf.default.send_redirects": 0,
        "net.ipv4.conf.all.accept_source_route": 0,
        "net.ipv4.conf.default.accept_source_route": 0,
        "net.ipv4.conf.all.accept_redirects": 0,
        "net.ipv4.conf.default.accept_redirects": 0,
        "net.ipv4.conf.all.secure_redirects": 0,
        "net.ipv4.conf.default.secure_redirects": 0,
        "net.ipv4.conf.all.log_martians": 1,
        "net.ipv4.conf.default.log_martians": 1,
        "net.ipv4.icmp_echo_ignore_broadcasts": 1,
        "net.ipv4.icmp_ignore_bogus_error_responses": 1,
        "net.ipv4.conf.all.rp_filter": 1,
        "net.ipv4.conf.default.rp_filter": 1,
        "net.ipv4.tcp_syncookies": 1
    }

    backup_file(SYSCTL_CONF_FILE)
    SYSCTL_CONF_DIR.mkdir(parents=True, exist_ok=True)

    with open(SYSCTL_CONF_FILE, "w") as f:
        f.write("# linux Sentinel sysctl settings\n")
        for key, value in settings.items():
            f.write(f"{key}={value}\n")

    success, _ = run_command(["sysctl", "--system"])
    run_command(["sysctl", "-w", "net.ipv4.route.flush=1"])
    return success

def install_tcp_wrappers() -> bool:
    """Install and configure TCP wrappers."""
    logger.info("Configuring TCP wrappers...")

    package_manager = None
    if shutil.which("apt"):
        package_manager = ["apt", "-y", "install", "tcpd"]
    elif shutil.which("dnf"):
        package_manager = ["dnf", "-y", "install", "tcpd"]
    elif shutil.which("yum"):
        package_manager = ["yum", "-y", "install", "tcpd"]

    if package_manager:
        success, _ = run_command(package_manager)
        if not success:
            logger.warning("Failed to install tcpd")

    hosts_allow = Path("/etc/hosts.allow")
    hosts_deny = Path("/etc/hosts.deny")

    backup_file(hosts_allow)
    backup_file(hosts_deny)

    try:
        hosts_allow.write_text("# linux Sentinel: Allow SSH from specific IPs\n")
        for ip in ALLOWED_SSH_IPS:
            hosts_allow.write_text(f"sshd: {ip}\n", mode="a")
        hosts_deny.write_text("# linux Sentinel: Deny all other access\nALL: ALL\n", mode="a")

        os.chown(hosts_allow, 0, 0)
        os.chmod(hosts_allow, 0o644)
        os.chown(hosts_deny, 0, 0)
        os.chmod(hosts_deny, 0o644)
        return True
    except Exception as e:
        logger.error(f"Failed to configure TCP wrappers: {e}")
        return False

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description=f"linux Sentinel Firewall Setup v{VERSION}")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--use-firewalld", action="store_true", help="Use firewalld instead of iptables")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if os.geteuid() != 0:
        logger.error("This script requires root privileges")
        sys.exit(1)

    if not check_dependencies():
        logger.error("Missing required dependencies")
        sys.exit(1)

    config = load_config()
    if args.use_firewalld:
        config["USE_FIREWALLD"] = True

    success = True
    if config["USE_FIREWALLD"]:
        success &= set_firewalld(config)
    else:
        success &= set_iptables(config)

    success &= set_sysctl_settings()
    success &= install_tcp_wrappers()

    if success:
        logger.info("Firewall setup completed successfully")
        print("\033[0;32m✓ Firewall setup completed successfully\033[0m")
        print(f"\033[0;36mLogs: {LOG_FILE}\033[0m")
    else:
        logger.error("Firewall setup failed")
        print("\033[0;31m✗ Firewall setup failed. Check logs at {LOG_FILE}\033[0m")
        sys.exit(1)

if __name__ == "__main__":
    main()