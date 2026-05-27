#!/usr/bin/env python3
"""
Python script to harden user-related configurations on Linux systems.
Implements root access restrictions, sudo settings, password policies, logind settings,
login definitions, root account locking, and user account configurations.

Licensed under the MIT License (MIT).

Requirements:
sudo apt install cracklib-runtime
Usage: sudo python3 user_hardening.py [--verbose]
"""

import os
import sys
import re
import json
import argparse
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
import logging

# Configuration
LOG_FILE = Path('/var/log/user_hardening.log')
SUMMARY_JSON = Path('/var/log/user_hardening_summary.json')
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
BACKUP_COUNT = 5  # Keep 5 backup logs
SECURITYACCESS = Path('/etc/security/access.conf')
COMMONPASSWD = Path('/etc/pam.d/common-password')
COMMONACCOUNT = Path('/etc/pam.d/common-account')
COMMONAUTH = Path('/etc/pam.d/common-auth')
PAMLOGIN = Path('/etc/pam.d/login')
LOGINDCONF = Path('/etc/systemd/logind.conf')
LOGINDEFS = Path('/etc/login.defs')
ADDUSER = Path('/etc/adduser.conf')
USERADD = Path('/etc/default/useradd')
FAILLOCKCONF = Path('/etc/security/faillock.conf')

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
        logger.error(f"Failed to set permissions on log file: {e}")
        sys.exit(1)

def run_command(command, verbose=False):
    """Run a shell command and return its success status, logging sanitized errors."""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        if verbose:
            print(result.stdout)  # Print to stdout only, not log
        return True
    except subprocess.CalledProcessError as e:
        # Map commands to sanitized error messages
        error_messages = {
            "systemctl mask debug-shell.service": "Failed to mask debug-shell service",
            "systemctl stop debug-shell.service": "Failed to stop debug-shell service",
            "systemctl daemon-reload": "Failed to reload systemd daemon",
            "systemctl status debug-shell.service --no-pager": "Failed to check debug-shell service status",
            "sudo -ll": "Failed to list sudo configuration",
            "passwd -S root": "Failed to check root account status",
            "grep -v '^$' /usr/share/dict/passwords | strings > /usr/share/dict/passwords_text": "Failed to process password dictionary",
            "update-cracklib": "Failed to update cracklib dictionary"
        }
        # Find matching command prefix or use generic message
        cmd_prefix = command.split()[0] if command else ""
        for cmd, msg in error_messages.items():
            if command.startswith(cmd):
                logger.error(msg)
                break
        else:
            logger.error("Command execution failed")
        if verbose:
            # Sanitize stderr to replace sensitive paths (e.g., /home/user, /etc/passwd)
            sanitized_stderr = re.sub(r'/home/[^/]+', '[HOME]', e.stderr)
            sanitized_stderr = re.sub(r'/etc/[^ ]+', '[ETC_FILE]', sanitized_stderr)
            print(sanitized_stderr)  # Print sanitized stderr to stdout
        return False

def rootaccess(verbose):
    """Restrict root access and mask debug-shell service."""
    logger.info("[rootaccess] Configuring root access policies")
    changes = []

    if not SECURITYACCESS.exists():
        logger.error("Root access configuration file not found")
        return changes

    # Update /etc/security/access.conf
    try:
        content = SECURITYACCESS.read_text()
        if not re.search(r'^\+\s*:\s*root\s*:\s*127\.0\.0\.1$', content, re.MULTILINE):
            content = re.sub(r'^#.*root.*:.*127\.0\.0\.1$', '+:root:127.0.0.1', content, flags=re.MULTILINE)
            SECURITYACCESS.write_text(content)
            changes.append("Updated /etc/security/access.conf for root localhost access")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to update root access configuration: {e}")

    # Restrict /etc/securetty
    try:
        Path('/etc/securetty').write_text("console\n")
        changes.append("Set /etc/securetty to console only")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to update securetty configuration: {e}")

    # Mask and stop debug-shell service
    if run_command("systemctl mask debug-shell.service"):
        changes.append("Masked debug-shell.service")
    if run_command("systemctl stop debug-shell.service"):
        changes.append("Stopped debug-shell.service")
    if run_command("systemctl daemon-reload"):
        changes.append("Reloaded systemd daemon")
    if verbose:
        run_command("systemctl status debug-shell.service --no-pager", verbose=True)

    return changes

def sudo_config(verbose):
    """Configure sudo settings with use_pty, logging, and timeout options."""
    logger.info("[sudo] Configuring sudo policies")
    changes = []

    sudoers_d = Path('/etc/sudoers.d')
    configs = [
        ('011_use_pty', "Defaults use_pty"),
        ('012_logfile', 'Defaults logfile="/var/log/sudo.log"'),
        ('013_pwfeedback', 'Defaults !pwfeedback'),
        ('014_visiblepw', 'Defaults !visiblepw'),
        ('015_passwdtimeout', 'Defaults passwd_timeout=1'),
        ('016_timestamptimeout', 'Defaults timestamp_timeout=5')
    ]

    for filename, content in configs:
        file_path = sudoers_d / filename
        try:
            if not file_path.exists():
                file_path.write_text(content + "\n")
                os.chmod(file_path, 0o440)
                changes.append(f"Created {file_path}")
        except (IOError, PermissionError) as e:
            logger.error(f"Failed to create sudo configuration file: {e}")

    # Set permissions on /etc/sudoers.d/*
    try:
        for file in sudoers_d.glob('[0-9]*'):
            os.chmod(file, 0o440)
        changes.append("Set permissions on /etc/sudoers.d/* to 0440")
    except OSError as e:
        logger.error(f"Failed to set permissions on sudo configuration directory: {e}")

    # Update /etc/pam.d/su
    try:
        pam_su = Path('/etc/pam.d/su')
        if pam_su.exists() and not re.search(r'^auth required pam_wheel\.so', pam_su.read_text(), re.MULTILINE):
            with pam_su.open('a') as f:
                f.write("auth required pam_wheel.so use_uid group=sudo\n")
            changes.append("Added pam_wheel.so to /etc/pam.d/su")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to update su configuration: {e}")

    if verbose:
        run_command("sudo -ll", verbose=True)

    return changes

def password(verbose):
    """Configure password policies in PAM and cracklib."""
    logger.info("[password] Configuring password policy files")
    changes = []

    # Update common-password
    try:
        if COMMONPASSWD.exists():
            content = COMMONPASSWD.read_text()
            if 'pam_pwhistory.so' not in content:
                content += "password\trequired\t\t\tpam_pwhistory.so\tremember=5\n"
                COMMONPASSWD.write_text(content)
                changes.append("Added pam_pwhistory.so to common-password")
            content = content.replace('try_first_pass sha512', 'try_first_pass sha512 rounds=65536')
            COMMONPASSWD.write_text(content)
            if 'retry=' not in content:
                COMMONPASSWD.write_text(content + "password requisite pam_pwquality.so retry=3\n")
                changes.append("Added pam_pwquality.so to common-password")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to update password configuration file: {e}")

    # Copy pwquality.conf
    try:
        pwquality_conf = Path('/etc/security/pwquality.conf')
        if Path('./config/pwquality.conf').exists():
            pwquality_conf.write_bytes(Path('./config/pwquality.conf').read_bytes())
            os.chmod(pwquality_conf, 0o644)
            changes.append("Updated /etc/security/pwquality.conf")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to update password quality configuration: {e}")

    # Update common-auth
    try:
        if COMMONAUTH.exists():
            content = COMMONAUTH.read_text()
            content = re.sub(r'(nullok|nullok_secure)', '', content)
            COMMONAUTH.write_text(content)
            changes.append("Removed nullok/nullok_secure from common-auth")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to update authentication configuration: {e}")

    # Configure faillock or tally2
    try:
        if FAILLOCKCONF.exists():
            content = FAILLOCKCONF.read_text()
            content = re.sub(r'^# audit$', 'audit', content, flags=re.MULTILINE)
            content = re.sub(r'^# local_users_only$', 'local_users_only', content, flags=re.MULTILINE)
            content = re.sub(r'^# deny.*', 'deny = 5', content, flags=re.MULTILINE)
            content = re.sub(r'^# fail_interval.*', 'fail_interval = 900', content, flags=re.MULTILINE)
            FAILLOCKCONF.write_text(content)
            changes.append("Configured faillock in /etc/security/faillock.conf")

            if COMMONAUTH.exists() and 'pam_faillock.so' not in COMMONAUTH.read_text():
                content = COMMONAUTH.read_text()
                content = content.replace(
                    'auth.*pam_unix.so',
                    'auth required pam_faillock.so preauth\nauth [success=1 default=ignore] pam_unix.so\nauth [default=die] pam_faillock.so authfail\nauth sufficient pam_faillock.so authsucc\n'
                )
                COMMONAUTH.write_text(content)
                changes.append("Added pam_faillock.so to common-auth")
            if COMMONACCOUNT.exists() and 'pam_faillock.so' not in COMMONACCOUNT.read_text():
                with COMMONACCOUNT.open('a') as f:
                    f.write("account required pam_faillock.so\n")
                changes.append("Added pam_faillock.so to common-account")
        else:
            if COMMONAUTH.exists() and 'pam_tally2.so' not in COMMONAUTH.read_text():
                with COMMONAUTH.open('a') as f:
                    f.write("auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900\n")
                changes.append("Added pam_tally2.so to common-auth")
            if COMMONACCOUNT.exists() and 'pam_tally2.so' not in COMMONACCOUNT.read_text():
                with COMMONACCOUNT.open('a') as f:
                    f.write("account required pam_tally2.so\n")
                changes.append("Added pam_tally2.so to common-account")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to configure faillock/tally2 settings: {e}")

    # Update pam.d/login
    try:
        if PAMLOGIN.exists():
            content = PAMLOGIN.read_text()
            content = re.sub(r'pam_lastlog.so.*', 'pam_lastlog.so showfailed', content)
            content = re.sub(r'delay=.*', 'delay=4000000', content)
            PAMLOGIN.write_text(content)
            changes.append("Updated pam_lastlog.so and delay in pam.d/login")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to update login configuration: {e}")

    # Update cracklib dictionary
    try:
        passwords_file = Path('/usr/share/dict/passwords')
        passwords_text = Path('/usr/share/dict/passwords_text')
        if Path('./misc/passwords.list').exists():
            passwords_file.write_bytes(Path('./misc/passwords.list').read_bytes())
            run_command(f"grep -v '^$' {passwords_file} | strings > {passwords_text}")
            run_command("update-cracklib")
            changes.append("Updated cracklib dictionary")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to update cracklib dictionary: {e}")

    return changes

def logindconf():
    """Configure systemd logind settings."""
    logger.info("[logindconf] Configuring logind settings")
    changes = []

    try:
        if LOGINDCONF.exists():
            content = LOGINDCONF.read_text()
            content = re.sub(r'^#KillUserProcesses=no', 'KillUserProcesses=yes', content, flags=re.MULTILINE)
            content = re.sub(r'^#KillExcludeUsers=root', 'KillExcludeUsers=root', content, flags=re.MULTILINE)
            content = re.sub(r'^#IdleAction=ignore', 'IdleAction=lock', content, flags=re.MULTILINE)
            content = re.sub(r'^#IdleActionSec=30min', 'IdleActionSec=15min', content, flags=re.MULTILINE)
            content = re.sub(r'^#RemoveIPC=yes', 'RemoveIPC=yes', content, flags=re.MULTILINE)
            LOGINDCONF.write_text(content)
            changes.append("Updated /etc/systemd/logind.conf")
            run_command("systemctl daemon-reload")
            changes.append("Reloaded systemd daemon")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to update logind configuration: {e}")

    return changes

def logindefs():
    """Configure /etc/login.defs settings."""
    logger.info("[logindefs] Configuring login definitions")
    changes = []

    try:
        if LOGINDEFS.exists():
            content = LOGINDEFS.read_text()
            content = re.sub(r'^.*LOG_OK_LOGINS.*', 'LOG_OK_LOGINS yes', content, flags=re.MULTILINE)
            content = re.sub(r'^UMASK.*', 'UMASK 077', content, flags=re.MULTILINE)
            content = re.sub(r'^PASS_MIN_DAYS.*', 'PASS_MIN_DAYS 1', content, flags=re.MULTILINE)
            content = re.sub(r'^PASS_MAX_DAYS.*', 'PASS_MAX_DAYS 60', content, flags=re.MULTILINE)
            content = re.sub(r'^DEFAULT_HOME.*', 'DEFAULT_HOME no', content, flags=re.MULTILINE)
            content = re.sub(r'^ENCRYPT_METHOD.*', 'ENCRYPT_METHOD SHA512', content, flags=re.MULTILINE)
            content = re.sub(r'^USERGROUPS_ENAB.*', 'USERGROUPS_ENAB no', content, flags=re.MULTILINE)
            content = re.sub(r'^#.*SHA_CRYPT_MIN_ROUNDS .*', 'SHA_CRYPT_MIN_ROUNDS 10000', content, flags=re.MULTILINE)
            content = re.sub(r'^#.*SHA_CRYPT_MAX_ROUNDS .*', 'SHA_CRYPT_MAX_ROUNDS 65536', content, flags=re.MULTILINE)
            LOGINDEFS.write_text(content)
            changes.append("Updated /etc/login.defs")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to update login definitions: {e}")

    return changes

def lockroot(verbose):
    """Lock the root account."""
    logger.info("[lockroot] Locking root account")
    changes = []

    if run_command("usermod -L root"):
        changes.append("Locked root account")
    if verbose:
        run_command("passwd -S root", verbose=True)

    return changes

def adduser():
    """Configure /etc/adduser.conf and /etc/default/useradd, and set user home permissions."""
    logger.info("[adduser] Configuring user creation settings")
    changes = []

    try:
        if ADDUSER.exists():
            content = ADDUSER.read_text()
            content = re.sub(r'^#?DIR_MODE=.*', 'DIR_MODE=0750', content, flags=re.MULTILINE)
            content = re.sub(r'^#?DSHELL=.*', 'DSHELL=/bin/false', content, flags=re.MULTILINE)
            content = re.sub(r'^#?USERGROUPS=.*', 'USERGROUPS=yes', content, flags=re.MULTILINE)
            ADDUSER.write_text(content)
            changes.append("Updated /etc/adduser.conf")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to update user creation configuration: {e}")

    try:
        if USERADD.exists():
            content = USERADD.read_text()
            content = re.sub(r'^SHELL=.*', 'SHELL=/bin/false', content, flags=re.MULTILINE)
            content = re.sub(r'^# INACTIVE=.*', 'INACTIVE=30', content, flags=re.MULTILINE)
            USERADD.write_text(content)
            changes.append("Updated /etc/default/useradd")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to update useradd configuration: {e}")

    # Set permissions on user home directories
    try:
        with open('/etc/passwd', 'r') as f:
            for line in f:
                fields = line.split(':')
                if len(fields) >= 6 and fields[2].isdigit():
                    uid = int(fields[2])
                    home_dir = fields[5]
                    if 1000 <= uid <= 65000 and home_dir and Path(home_dir).is_dir():
                        os.chmod(home_dir, 0o750)
                        changes.append(f"Set permissions on user home directory")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to set user home directory permissions: {e}")

    return changes

def main():
    """Main function to apply user hardening configurations."""
    parser = argparse.ArgumentParser(description="Harden user-related configurations on Linux.")
    parser.add_argument('--verbose', action='store_true', help="Enable verbose output (stdout only)")
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

    changes = []
    changes.extend(rootaccess(args.verbose))
    changes.extend(sudo_config(args.verbose))
    changes.extend(password(args.verbose))
    changes.extend(logindconf())
    changes.extend(logindefs())
    changes.extend(lockroot(args.verbose))
    changes.extend(adduser())

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
        logger.error(f"Failed to write JSON summary: {e}")
        sys.exit(1)

    logger.info(f"Summary: Applied {len(changes)} changes.")
    logger.info(f"Detailed report written to {LOG_FILE}")
    logger.info(f"JSON summary written to {SUMMARY_JSON}")
    logger.info("Script finished.")

if __name__ == "__main__":
    main()