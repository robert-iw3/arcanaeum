#!/usr/bin/env python3
"""
Python script to harden SSH configurations on Linux systems.
Configures /etc/ssh/sshd_config, /etc/ssh/ssh_config, and system banners.

Licensed under the MIT License (MIT).

RW

Usage: sudo python3 ssh_hardening.py [--verbose]
"""

import os
import sys
import re
import json
import argparse
import subprocess
import shutil
from pathlib import Path
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
import logging

# Configuration
LOG_FILE = Path('/var/log/ssh_hardening.log')
SUMMARY_JSON = Path('/var/log/ssh_hardening_summary.json')
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
BACKUP_COUNT = 5  # Keep 5 backup logs
SSHFILE = Path('/etc/ssh/ssh_config')
SSHDFILE = Path('/etc/ssh/sshd_config')
SSH_GRPS = 'sudo'
SSH_PORT = '22'

# Setup logging with rotation
handler = RotatingFileHandler(LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=BACKUP_COUNT)
handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s', datefmt='%Y-%m-%dT%H:%M:%SZ'))
logging.basicConfig(level=logging.INFO, handlers=[handler, logging.StreamHandler(sys.stdout)])
logger = logging.getLogger(__name__)

def ensure_file_permissions(file_path, mode=0o600):
    """Ensure the specified file exists with the given permissions."""
    try:
        file_path.touch(exist_ok=True)
        os.chmod(file_path, mode)
    except OSError as e:
        logger.error(f"Failed to set permissions on {file_path}: {e}")
        sys.exit(1)

def run_command(command, verbose=False):
    """Run a shell command and return its output if verbose is True."""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        if verbose:
            logger.info(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {command}\nError: {e.stderr}")
        return False

def sshdconfig(verbose):
    """Configure /etc/ssh/sshd_config for security."""
    logger.info(f"[sshdconfig] Configuring {SSHDFILE}")
    changes = []

    # Filter moduli for strong DH parameters
    try:
        moduli_tmp = Path('/etc/ssh/moduli.tmp')
        with open('/etc/ssh/moduli', 'r') as f, moduli_tmp.open('w') as tmp:
            for line in f:
                if len(line.split()) >= 5 and int(line.split()[4]) >= 3071:
                    tmp.write(line)
        moduli_tmp.replace('/etc/ssh/moduli')
        changes.append("Filtered /etc/ssh/moduli for DH parameters >= 3071")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to update /etc/ssh/moduli: {e}")

    # Determine SSHDCONF path
    sshdconf = SSHDFILE
    try:
        content = SSHDFILE.read_text()
        include_match = re.search(r'^Include\s+(.+)$', content, re.MULTILINE)
        if include_match:
            include_path = include_match.group(1)
            include_dir = Path(os.path.dirname(include_path))
            include_dir.mkdir(parents=True, exist_ok=True)
            sshdconf = include_dir / 'hardening.conf'
            sshdconf.write_text(content)
            content = re.sub(r'^\s*Subsystem.*', '', content, flags=re.MULTILINE)
            content = re.sub(r'^\s*Include.*', '', content, flags=re.MULTILINE)
            SSHDFILE.write_text(content)
            changes.append(f"Created {sshdconf} from {SSHDFILE}")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to process {SSHDFILE} Include directive: {e}")

    if verbose:
        logger.info(f"Using {sshdconf}")

    # SSHD configuration settings
    configs = [
        (r'HostKey.*ssh_host_dsa_key.*', '', 'remove'),
        (r'KeyRegenerationInterval.*', '', 'remove'),
        (r'ServerKeyBits.*', '', 'remove'),
        (r'UseLogin.*', '', 'remove'),
        (r'X11Forwarding.*', 'X11Forwarding no', 'replace'),
        (r'LoginGraceTime.*', 'LoginGraceTime 20', 'replace'),
        (r'PermitRootLogin.*', 'PermitRootLogin no', 'replace'),
        (r'UsePrivilegeSeparation.*', 'UsePrivilegeSeparation sandbox', 'replace'),
        (r'LogLevel.*', 'LogLevel VERBOSE', 'replace'),
        (r'Banner.*', 'Banner /etc/issue.net', 'replace'),
        (r'Subsystem.*sftp.*', 'Subsystem sftp internal-sftp', 'replace'),
        (r'^#?Compression.*', 'Compression no', 'replace'),
        (r'Port.*', f'Port {SSH_PORT}', 'replace'),
        (r'LogLevel', 'LogLevel VERBOSE', 'append'),
        (r'PrintLastLog', 'PrintLastLog yes', 'append'),
        (r'IgnoreUserKnownHosts', 'IgnoreUserKnownHosts yes', 'append'),
        (r'PermitEmptyPasswords', 'PermitEmptyPasswords no', 'append'),
        (r'AllowGroups', f'AllowGroups {SSH_GRPS}', 'append'),
        (r'MaxAuthTries', 'MaxAuthTries 3', 'replace'),
        (r'ClientAliveInterval', 'ClientAliveInterval 200', 'append'),
        (r'ClientAliveCountMax', 'ClientAliveCountMax 3', 'append'),
        (r'PermitUserEnvironment', 'PermitUserEnvironment no', 'append'),
        (r'KexAlgorithms', 'KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256', 'append'),
        (r'Ciphers', 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr', 'append'),
        (r'Macs', 'Macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256', 'append'),
        (r'MaxSessions', 'MaxSessions 3', 'replace'),
        (r'UseDNS', 'UseDNS no', 'replace'),
        (r'StrictModes', 'StrictModes yes', 'replace'),
        (r'MaxStartups', 'MaxStartups 10:30:60', 'replace'),
        (r'HostbasedAuthentication', 'HostbasedAuthentication no', 'replace'),
        (r'KerberosAuthentication', 'KerberosAuthentication no', 'replace'),
        (r'GSSAPIAuthentication', 'GSSAPIAuthentication no', 'replace'),
        (r'RekeyLimit', 'RekeyLimit 512M 1h', 'replace'),
        (r'AllowTcpForwarding', 'AllowTcpForwarding no', 'replace'),
        (r'AllowAgentForwarding', 'AllowAgentForwarding no', 'replace'),
        (r'TCPKeepAlive', 'TCPKeepAlive no', 'replace'),
    ]

    try:
        content = sshdconf.read_text()
        for pattern, value, action in configs:
            if action == 'remove':
                content = re.sub(rf'^{pattern}', '', content, flags=re.MULTILINE)
            elif action == 'replace':
                content = re.sub(rf'^{pattern}', value, content, flags=re.MULTILINE)
            elif action == 'append' and not re.search(rf'^{pattern}\s+', content, re.MULTILINE):
                content += f"{value}\n"
        sshdconf.write_text(content + "\n")
        changes.append(f"Updated {sshdconf} with security settings")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to update {sshdconf}: {e}")

    # Backup, clean, and restore sshd_config
    try:
        backup_file = Path(f"/etc/ssh/sshd_config.{datetime.now().strftime('%y%m%d')}")
        shutil.copy(sshdconf, backup_file)
        content = [line for line in backup_file.read_text().splitlines() if not re.match(r'#|^$', line)]
        sshdconf.write_text('\n'.join(sorted(set(content))) + '\n')
        backup_file.unlink()
        changes.append(f"Cleaned and sorted {sshdconf}")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to clean {sshdconf}: {e}")

    # Set permissions
    try:
        os.chown(sshdconf, 0, 0)
        os.chmod(sshdconf, 0o600)
        changes.append(f"Set {sshdconf} permissions to 0600")
    except OSError as e:
        logger.error(f"Failed to set {sshdconf} permissions: {e}")

    # Restart SSH service
    if run_command("systemctl restart ssh.service"):
        changes.append("Restarted ssh.service")
    if verbose:
        run_command("systemctl status ssh.service --no-pager", verbose=True)

    return changes

def sshconfig():
    """Configure /etc/ssh/ssh_config for security."""
    logger.info(f"[sshconfig] Configuring {SSHFILE}")
    changes = []

    try:
        # Backup ssh_config
        backup_file = Path(f"/etc/ssh/ssh_config.{datetime.now().strftime('%y%m%d')}")
        shutil.copy(SSHFILE, backup_file)
        changes.append(f"Backed up {SSHFILE} to {backup_file}")

        content = SSHFILE.read_text()
        if not re.search(r'^\s*HashKnownHosts', content, re.MULTILINE):
            content = re.sub(r'HashKnownHosts.*', '', content, flags=re.MULTILINE)
            content += "    HashKnownHosts yes\n"
        content = re.sub(
            r'#.*Ciphers .*',
            '    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr',
            content,
            flags=re.MULTILINE
        )
        content = re.sub(
            r'#.*MACs .*',
            '    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256',
            content,
            flags=re.MULTILINE
        )
        SSHFILE.write_text(content)
        changes.append(f"Updated {SSHFILE} with security settings")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to update {SSHFILE}: {e}")

    return changes

def issue():
    """Configure /etc/issue, /etc/issue.net, and /etc/motd."""
    logger.info("[issue] Configuring /etc/issue, /etc/issue.net, and /etc/motd")
    changes = []

    text = """\\n\n
Call trans opt: received. 2-19-98 13:24:18 REC:Loc

     Trace program: running

           wake up, Neo...
        the matrix has you
      follow the white rabbit.

          knock, knock, Neo.

By accessing this system, you consent to the following conditions:

- This system is for authorized use only.
- Any or all uses of this system and all files on this system may be monitored.
- Communications using, or data stored on, this system are not private.
"""

    for f in ['/etc/issue', '/etc/issue.net', '/etc/motd']:
        try:
            Path(f).write_text(text)
            changes.append(f"Updated {f} with banner")
        except (IOError, PermissionError) as e:
            logger.error(f"Failed to update {f}: {e}")

    try:
        for f in Path('/etc/update-motd.d').glob('*'):
            os.chmod(f, 0o644)
        changes.append("Removed execute permissions from /etc/update-motd.d/*")
    except OSError as e:
        logger.error(f"Failed to update permissions in /etc/update-motd.d: {e}")

    return changes

def main():
    """Main function to apply SSH hardening configurations."""
    parser = argparse.ArgumentParser(description="Harden SSH configurations on Linux.")
    parser.add_argument('--verbose', action='store_true', help="Enable verbose output")
    args = parser.parse_args()

    # Check for root privileges
    if os.geteuid() != 0:
        logger.error("This script requires root privileges.")
        sys.exit(1)

    # Ensure log and JSON file permissions
    ensure_file_permissions(LOG_FILE)
    ensure_file_permissions(SUMMARY_JSON)

    # Check for container environment
    if (Path('/.dockerenv').exists() or
            Path('/run/.containerenv').exists() or
            any('docker' in line or 'lxc' in line for line in Path('/proc/1/cgroup').read_text().splitlines())):
        logger.info("Detected container environment. Some configurations may require additional setup.")

    # Check if ssh is installed
    ssh_path = shutil.which('ssh')
    if not ssh_path:
        logger.error("ssh not installed, please install and rerun script")
        output = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "changes_made": [],
            "error": "ssh not installed"
        }
        with SUMMARY_JSON.open("w") as f:
            json.dump(output, f, indent=4)
        sys.exit(1)

    changes = []
    changes.extend(issue())
    changes.extend(sshconfig())
    changes.extend(sshdconfig(args.verbose))

    # Write JSON summary
    output = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "changes_made": changes
    }
    try:
        with SUMMARY_JSON.open("w") as f:
            json.dump(output, f, indent=4)
        os.chmod(SUMMARY_JSON, 0o600)
    except OSError as e:
        logger.error(f"Failed to write to {SUMMARY_JSON}: {e}")
        sys.exit(1)

    logger.info(f"Summary: Applied {len(changes)} changes.")
    logger.info(f"Detailed report written to {LOG_FILE}")
    logger.info(f"JSON summary written to {SUMMARY_JSON}")
    logger.info("Script finished.")

if __name__ == "__main__":
    main()