#!/usr/bin/env python3

"""
This Python script is designed to secure Linux-based Docker containers by applying best practices and configurations
derived from CIS (Center for Internet Security) and STIG (Security Technical Implementation Guide) standards.

It is distro-agnostic, meaning it works across various Linux distributions commonly used as Docker base images, including
Ubuntu, Debian, AlmaLinux, and Alpine. The script automates the application of security configurations to enhance the container's security posture.

RW
"""

import os
import subprocess
import sys
import configparser
import shutil
import stat
import logging
import pwd
import grp
import re
from datetime import datetime

# Configure verbose logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - STIG/CIS %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

def detect_distro():
    """Detect the Linux distribution by parsing /etc/os-release or other files."""
    logger.info("Detecting Linux distribution (CIS 1.1.1)")
    if os.path.exists('/etc/os-release'):
        config = configparser.ConfigParser()
        config.read('/etc/os-release')
        distro_id = config['DEFAULT'].get('ID', '').lower()
        logger.info(f"Detected distribution: {distro_id}")
        return distro_id
    elif os.path.exists('/etc/alpine-release'):
        logger.info("Detected distribution: alpine")
        return 'alpine'
    logger.warning("Unknown distribution detected")
    return 'unknown'

def run_command(cmd, shell=False, check=True):
    """Run a subprocess command and handle errors."""
    cmd_str = ' '.join(cmd) if not shell else cmd
    logger.info(f"Executing command: {cmd_str}")
    try:
        result = subprocess.run(cmd, shell=shell, check=check, capture_output=True, text=True)
        logger.debug(f"Command output: {result.stdout}")
        return result
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running command {cmd_str}: {e.stderr}")
        return None
    except FileNotFoundError:
        logger.error(f"Command not found: {cmd[0]}")
        return None

def replace_or_append(config_file, key, value, cce, format_str="%s = %s"):
    """Replace or append a configuration setting in a file."""
    logger.info(f"Configuring {key} in {config_file} (CCE-{cce})")
    try:
        if not os.path.exists(config_file):
            with open(config_file, 'a'):
                pass
        with open(config_file, 'r') as f:
            lines = f.readlines()
        stripped_key = re.sub(r'[\^=\$,;+]*', '', key)
        formatted_output = format_str % (stripped_key, value)
        found = False
        for i, line in enumerate(lines):
            if re.match(f'^{key}\\s*', line):
                lines[i] = f"{formatted_output}\n"
                found = True
                logger.info(f"Updated {key} to {value} in {config_file}")
                break
        if not found:
            lines.append(f"\n# Per CCE-{cce}: Set {formatted_output} in {config_file}\n")
            lines.append(f"{formatted_output}\n")
            logger.info(f"Appended {key}={value} to {config_file}")
        with open(config_file, 'w') as f:
            f.writelines(lines)
    except OSError as e:
        logger.error(f"Error modifying {config_file}: {e}")

def update_and_upgrade(distro):
    """Update and upgrade packages based on the distro (STIG RHEL-08-010120)."""
    logger.info("Updating and upgrading packages to minimize attack surface (STIG RHEL-08-010120, CIS 1.1.2)")
    if distro in ['ubuntu', 'debian']:
        run_command(['apt', 'update', '-y'])
        run_command(['apt', 'upgrade', '-y'])
        run_command(['apt', 'autoremove', '-y'])
        run_command(['apt', 'autoclean', '-y'])
    elif distro == 'rhel':
        run_command(['dnf', 'update', '-y'])
        run_command(['dnf', 'autoremove', '-y'])
        run_command(['dnf', 'clean', 'all'])
    elif distro == 'alpine':
        run_command(['apk', 'update'])
        run_command(['apk', 'upgrade'])
        logger.warning("Alpine does not have autoremove; manually review packages (CIS 1.1.2)")
    else:
        logger.warning("Unknown distro; skipping package update")

def lock_root_account():
    """Lock the root account to prevent direct login (STIG RHEL-08-010140)."""
    logger.info("Locking root account to secure application access (STIG RHEL-08-010140, CIS 5.4.3)")
    run_command(['passwd', '-l', 'root'])

def set_secure_umask():
    """Set a secure umask (077) in multiple config files to protect application files (STIG RHEL-08-020024, CIS 5.4.4)."""
    logger.info("Setting secure umask to 077 for file protection (STIG RHEL-08-020024, CIS 5.4.4)")
    configs = [
        ('/etc/profile', 'umask 077', 'CCE-82888-9'),
        ('/etc/bashrc', 'umask 077', 'CCE-82888-9'),
        ('/etc/csh.cshrc', 'umask 077', 'CCE-82888-9'),
        ('/etc/login.defs', 'UMASK 077', 'CCE-82888-9', '%s %s')
    ]
    for config_file, umask_line, cce, *fmt in configs:
        if os.path.exists(config_file):
            replace_or_append(config_file, '^umask|^UMASK', '077', cce, fmt[0] if fmt else '%s')
        else:
            logger.warning(f"{config_file} not found; skipping umask configuration")

def secure_file_permissions():
    """Set secure permissions on sensitive files to protect application data (STIG RHEL-08-010060, CIS 5.2.2)."""
    logger.info("Securing file permissions for sensitive files (STIG RHEL-08-010060, CIS 5.2.2)")
    files_permissions = {
        '/etc/passwd': 0o644,
        '/etc/group': 0o644,
        '/etc/shadow': 0o600 if os.path.exists('/etc/shadow') else None,
        '/etc/gshadow': 0o600 if os.path.exists('/etc/gshadow') else None,
        '/boot': 0o700 if os.path.exists('/boot') else None,
        '/usr/src': 0o700 if os.path.exists('/usr/src') else None,
    }
    for file_path, mode in files_permissions.items():
        if mode is not None and os.path.exists(file_path):
            try:
                os.chmod(file_path, mode)
                logger.info(f"Set permissions {oct(mode)} on {file_path}")
            except OSError as e:
                logger.error(f"Error setting permissions on {file_path}: {e}")

    # Remove world-writable permissions
    logger.info("Removing world-writable permissions to prevent unauthorized app modifications (STIG RHEL-08-010070)")
    run_command("find / -perm -002 -type f -exec chmod o-w {} \;", shell=True, check=False)

def remove_unnecessary_suid_sgid():
    """Remove SUID/SGID bits from binaries to reduce privilege escalation risks for the app (STIG RHEL-08-010149)."""
    logger.info("Removing unnecessary SUID/SGID bits (STIG RHEL-08-010149, CIS 5.1.8)")
    common_binaries = [
        '/bin/ping', '/bin/ping6', '/usr/bin/passwd', '/usr/bin/chsh', '/usr/bin/chfn',
        '/bin/mount', '/bin/umount', '/usr/bin/wall', '/usr/bin/chage', '/usr/bin/gpasswd',
    ]
    for binary in common_binaries:
        if os.path.exists(binary):
            try:
                mode = os.stat(binary).st_mode
                if mode & (stat.S_ISUID | stat.S_ISGID):
                    os.chmod(binary, mode & ~(stat.S_ISUID | stat.S_ISGID))
                    logger.info(f"Removed SUID/SGID bits from {binary}")
            except OSError as e:
                logger.error(f"Error modifying {binary}: {e}")

def disable_core_dumps():
    """Disable core dumps to prevent sensitive app data leakage (STIG RHEL-08-010673, CIS 1.6.1)."""
    logger.info("Disabling core dumps (STIG RHEL-08-010673, CIS 1.6.1)")
    limits_conf = '/etc/security/limits.conf'
    if os.path.exists(limits_conf):
        replace_or_append(limits_conf, '^\*\\s+hard\\s+core', '0', 'CCE-80784-2')
    else:
        logger.warning(f"{limits_conf} not found; creating and setting core dump limit")
        with open(limits_conf, 'a') as f:
            f.write("* hard core 0\n")
        logger.info("Disabled core dumps in limits.conf")

    coredump_conf = '/etc/systemd/coredump.conf'
    if os.path.exists(coredump_conf) or not os.path.exists(coredump_conf):
        if not os.path.exists(coredump_conf):
            with open(coredump_conf, 'a'):
                pass
        replace_or_append(coredump_conf, '^Storage', 'none', 'CCE-80784-2')
        replace_or_append(coredump_conf, '^ProcessSizeMax', '0', 'CCE-80784-2')
    else:
        logger.warning(f"{coredump_conf} not found; skipping systemd coredump configuration")

def apply_kernel_hardening():
    """Apply feasible kernel hardening parameters in container context (STIG RHEL-08-010375, CIS 3.1.2)."""
    logger.info("Applying kernel hardening parameters (limited in container; STIG RHEL-08-010375, CIS 3.1.2)")
    sysctl_conf = '/etc/sysctl.conf'
    hardening_params = [
        'fs.suid_dumpable=0',                  # Feasible: Disable suid dumps
        'net.ipv4.tcp_syncookies=1',           # Network protections
        'net.ipv4.conf.all.rp_filter=1',
        'net.ipv4.conf.default.rp_filter=1',
        'net.ipv4.conf.all.accept_redirects=0',
        'net.ipv4.conf.default.accept_redirects=0',
        'net.ipv6.conf.all.accept_redirects=0',
        'net.ipv6.conf.default.accept_redirects=0',
        'net.ipv4.icmp_echo_ignore_broadcasts=1',
        'vm.swappiness=1',                     # Memory management
    ]
    if os.path.exists(sysctl_conf):
        with open(sysctl_conf, 'a') as f:
            for param in hardening_params:
                f.write(f"{param}\n")
        logger.info(f"Appended container-feasible kernel parameters to {sysctl_conf}")
        result = run_command(['sysctl', '-p'], check=False)
        if result and result.returncode != 0:
            logger.warning("sysctl -p failed; expected in unprivileged containers - parameters may not apply")
    else:
        logger.warning(f"{sysctl_conf} not found; applying parameters directly (may fail in container)")
        for param in hardening_params:
            run_command(['sysctl', '-w', param], check=False)

def configure_password_quality(distro):
    """Configure password quality to secure app user accounts (STIG RHEL-08-020110, CIS 5.4.1)."""
    logger.info("Configuring password quality for secure app authentication (STIG RHEL-08-020110, CIS 5.4.1)")
    if distro in ['ubuntu', 'debian']:
        pwquality_conf = '/etc/security/pwquality.conf'
        if os.path.exists(pwquality_conf) or not os.path.exists(pwquality_conf):
            if not os.path.exists(pwquality_conf):
                with open(pwquality_conf, 'a'):
                    pass
            settings = [
                ('minlen', '15', 'CCE-80656-2'),
                ('dcredit', '-1', 'CCE-80653-9'),
                ('ucredit', '-1', 'CCE-80665-3'),
                ('lcredit', '-1', 'CCE-80655-4'),
                ('ocredit', '-1', 'CCE-80663-8'),
                ('difok', '8', 'CCE-80654-7'),
                ('minclass', '4', 'CCE-82046-4'),
                ('maxrepeat', '3', 'CCE-82066-2'),
                ('maxclassrepeat', '4', 'CCE-81034-1'),
                ('dictcheck', '1', 'CCE-86233-4'),
                ('enforce_for_root', '', 'CCE-86356-3', '%s')
            ]
            for key, value, cce, *fmt in settings:
                replace_or_append(pwquality_conf, f'^{key}', value, cce, fmt[0] if fmt else '%s = %s')
        else:
            logger.warning("pwquality.conf not found; install libpam-pwquality if needed")
    elif distro == 'rhel':
        run_command(['authselect', 'select', 'sssd', 'with-faillock', 'with-smartcard', '--force'], check=False)
        settings = [
            ('PASS_MAX_DAYS', '60', 'CCE-82888-9', '%s %s'),
            ('PASS_MIN_DAYS', '1', 'CCE-82888-9', '%s %s'),
            ('PASS_MIN_LEN', '15', 'CCE-82888-9', '%s %s'),
            ('FAIL_DELAY', '4', 'CCE-84037-1', '%s %s'),
            ('INACTIVE', '35', 'CCE-80954-1', '%s=%s'),
            ('UMASK', '077', 'CCE-82888-9', '%s %s')
        ]
        for key, value, cce, fmt in settings:
            replace_or_append('/etc/login.defs', f'^{key}', value, cce, fmt)
        logger.info("Applied authselect and login.defs configuration for rhel")
    elif distro == 'alpine':
        login_defs = '/etc/login.defs'
        if os.path.exists(login_defs):
            settings = [
                ('PASS_MIN_LEN', '15', 'CCE-82888-9', '%s %s'),
                ('PASS_MAX_DAYS', '60', 'CCE-82888-9', '%s %s'),
                ('PASS_MIN_DAYS', '1', 'CCE-82888-9', '%s %s'),
                ('FAIL_DELAY', '4', 'CCE-84037-1', '%s %s'),
                ('UMASK', '077', 'CCE-82888-9', '%s %s')
            ]
            for key, value, cce, fmt in settings:
                replace_or_append(login_defs, f'^{key}', value, cce, fmt)
        else:
            logger.warning("Alpine: /etc/login.defs not found; configure manually")
    else:
        logger.warning("Unknown distro; skipping password quality configuration")

def configure_pam_faillock(distro):
    """Configure pam_faillock for account lockout to protect app logins (STIG RHEL-08-020110)."""
    logger.info("Configuring pam_faillock for login protection (STIG RHEL-08-020110)")
    if distro in ['ubuntu', 'debian', 'rhel']:
        if distro == 'rhel':
            result = run_command(['authselect', 'check'], check=False)
            if result and result.returncode == 0:
                run_command(['authselect', 'enable-feature', 'with-faillock'], check=False)
                run_command(['authselect', 'apply-changes'], check=False)
                logger.info("Enabled faillock feature with authselect on rhel")
            else:
                logger.warning("authselect check failed; manual PAM configuration required")
        faillock_conf = '/etc/security/faillock.conf'
        if os.path.exists(faillock_conf) or not os.path.exists(faillock_conf):
            if not os.path.exists(faillock_conf):
                with open(faillock_conf, 'a'):
                    pass
            settings = [
                ('deny', '3', 'CCE-82888-9'),
                ('fail_interval', '900', 'CCE-82888-9'),
                ('unlock_time', '0', 'CCE-82888-9'),
                ('even_deny_root', '', 'CCE-82888-9', '%s')
            ]
            for key, value, cce, *fmt in settings:
                replace_or_append(faillock_conf, f'^{key}', value, cce, fmt[0] if fmt else '%s = %s')
        auth_files = ['/etc/pam.d/system-auth', '/etc/pam.d/password-auth']
        for pam_file in auth_files:
            if os.path.exists(pam_file):
                lines = open(pam_file, 'r').readlines()
                preauth_present = any(re.match(r'^\s*auth\s+required\s+pam_faillock\.so\s+preauth', line) for line in lines)
                authfail_present = any(re.match(r'^\s*auth\s+\[default=die\]\s+pam_faillock\.so\s+authfail', line) for line in lines)
                account_present = any(re.match(r'^\s*account\s+required\s+pam_faillock\.so', line) for line in lines)
                if not preauth_present:
                    for i, line in enumerate(lines):
                        if re.match(r'^\s*auth\s+.*\s+pam_unix\.so', line):
                            lines.insert(i, 'auth        required      pam_faillock.so preauth silent deny=3 fail_interval=900 unlock_time=0 even_deny_root\n')
                            logger.info(f"Added pam_faillock.so preauth to {pam_file}")
                            break
                if not authfail_present:
                    for i, line in enumerate(lines):
                        if re.match(r'^\s*auth\s+.*\s+pam_unix\.so', line):
                            lines.insert(i + 1, 'auth        [default=die] pam_faillock.so authfail deny=3 fail_interval=900 unlock_time=0 even_deny_root\n')
                            logger.info(f"Added pam_faillock.so authfail to {pam_file}")
                            break
                if not account_present:
                    for i, line in enumerate(lines):
                        if re.match(r'^\s*account\s+required\s+pam_unix.so', line):
                            lines.insert(i, 'account     required      pam_faillock.so\n')
                            logger.info(f"Added pam_faillock.so account to {pam_file}")
                            break
                with open(pam_file, 'w') as f:
                    f.writelines(lines)
    else:
        logger.warning("pam_faillock not supported on Alpine or unknown distro; configure manually")

def configure_pam_pwhistory(distro):
    """Configure pam_pwhistory to remember previous passwords for app security (STIG RHEL-08-020110)."""
    logger.info("Configuring pam_pwhistory for password reuse prevention (STIG RHEL-08-020110)")
    if distro in ['ubuntu', 'debian', 'rhel']:
        auth_files = ['/etc/pam.d/system-auth', '/etc/pam.d/password-auth']
        for pam_file in auth_files:
            if os.path.exists(pam_file):
                lines = open(pam_file, 'r').readlines()
                pwhistory_present = any(re.match(r'^\s*password\s+.*\s+pam_pwhistory\.so', line) for line in lines)
                if pwhistory_present:
                    for i, line in enumerate(lines):
                        if re.match(r'^\s*password\s+.*\s+pam_pwhistory\.so', line):
                            if 'remember=5' not in line:
                                lines[i] = re.sub(r'(pam_pwhistory\.so.*)', r'\1 remember=5', line)
                                logger.info(f"Updated pam_pwhistory.so with remember=5 in {pam_file}")
                            if 'required' not in line:
                                lines[i] = re.sub(r'password\s+(required|requisite)\s+', 'password required ', line)
                                logger.info(f"Set pam_pwhistory.so to required in {pam_file}")
                else:
                    for i, line in enumerate(lines):
                        if re.match(r'^\s*password\s+.*\s+pam_unix\.so', line):
                            lines.insert(i, 'password required pam_pwhistory.so use_authtok remember=5\n')
                            logger.info(f"Added pam_pwhistory.so with remember=5 to {pam_file}")
                            break
                with open(pam_file, 'w') as f:
                    f.writelines(lines)
    else:
        logger.warning("pam_pwhistory not supported on Alpine or unknown distro; configure manually")

def configure_pam_unix_remember(distro):
    """Configure pam_unix to remember previous passwords (STIG RHEL-08-020110)."""
    logger.info("Configuring pam_unix password history (STIG RHEL-08-020110)")
    if distro in ['ubuntu', 'debian', 'rhel']:
        auth_files = ['/etc/pam.d/system-auth', '/etc/pam.d/password-auth']
        for pam_file in auth_files:
            if os.path.exists(pam_file):
                lines = open(pam_file, 'r').readlines()
                for i, line in enumerate(lines):
                    if re.match(r'^\s*password\s+sufficient\s+pam_unix\.so', line):
                        if 'remember=5' not in line:
                            lines[i] = re.sub(r'(pam_unix\.so.*)', r'\1 remember=5', line)
                            logger.info(f"Updated pam_unix.so with remember=5 in {pam_file}")
                with open(pam_file, 'w') as f:
                    f.writelines(lines)
    else:
        logger.warning("pam_unix password history not supported on Alpine or unknown distro; configure manually")

def remove_unnecessary_packages(distro):
    """Remove unnecessary packages to reduce app attack surface (STIG RHEL-08-010000, CIS 2.2.1)."""
    logger.info("Removing unnecessary packages (STIG RHEL-08-010000, CIS 2.2.1)")
    packages = ['telnet', 'nis', 'rsh-server', 'rsh-client', 'talk', 'talk-server']
    if distro in ['ubuntu', 'debian']:
        for pkg in packages:
            result = run_command(['dpkg', '-s', pkg], check=False)
            if result and result.returncode == 0:
                run_command(['apt', 'purge', '-y', pkg], check=False)
                logger.info(f"Removed package {pkg}")
    elif distro == 'rhel':
        for pkg in packages:
            result = run_command(['rpm', '-q', pkg], check=False)
            if result and result.returncode == 0:
                run_command(['dnf', 'remove', '-y', pkg], check=False)
                logger.info(f"Removed package {pkg}")
    elif distro == 'alpine':
        for pkg in packages:
            result = run_command(['apk', 'info', pkg], check=False)
            if result and result.returncode == 0:
                run_command(['apk', 'del', pkg], check=False)
                logger.info(f"Removed package {pkg}")
    else:
        logger.warning("Unknown distro; skipping package removal")

def install_required_packages(distro):
    """Install minimal required security packages for app protection (STIG RHEL-08-010000)."""
    logger.info("Installing minimal required security packages (STIG RHEL-08-010000)")
    packages = ['sudo']  # Minimal for containers; others like usbguard, iptables may not apply
    if distro in ['ubuntu', 'debian']:
        for pkg in packages:
            result = run_command(['dpkg', '-s', pkg], check=False)
            if result and result.returncode != 0:
                run_command(['apt', 'install', '-y', pkg], check=False)
                logger.info(f"Installed package {pkg}")
    elif distro == 'rhel':
        for pkg in packages:
            result = run_command(['rpm', '-q', pkg], check=False)
            if result and result.returncode != 0:
                run_command(['dnf', 'install', '-y', pkg], check=False)
                logger.info(f"Installed package {pkg}")
    elif distro == 'alpine':
        for pkg in packages:
            result = run_command(['apk', 'info', pkg], check=False)
            if result and result.returncode != 0:
                run_command(['apk', 'add', pkg], check=False)
                logger.info(f"Installed package {pkg}")
    else:
        logger.warning("Unknown distro; skipping package installation")
    logger.warning("Skipped non-essential packages like usbguard, iptables as they are not feasible in containers")

def configure_auditd(distro):
    """Configure auditd if feasible for app logging (STIG RHEL-08-030000, CIS 4.1.1)."""
    logger.info("Configuring auditd (may be limited in containers; STIG RHEL-08-030000, CIS 4.1.1)")
    if distro in ['ubuntu', 'debian']:
        run_command(['apt', 'install', '-y', 'auditd'], check=False)  # Skip audispd-plugins if not needed
        run_command(['systemctl', 'enable', 'auditd'], check=False)
        result = run_command(['systemctl', 'start', 'auditd'], check=False)
        if result and result.returncode != 0:
            logger.warning("auditd start failed; may not be supported in this container environment")
        logger.info("Installed and attempted to enable auditd on Ubuntu/Debian")
    elif distro == 'rhel':
        run_command(['dnf', 'install', '-y', 'audit'], check=False)
        run_command(['systemctl', 'enable', 'auditd'], check=False)
        result = run_command(['systemctl', 'start', 'auditd'], check=False)
        if result and result.returncode != 0:
            logger.warning("auditd start failed; may not be supported in this container environment")
        logger.info("Installed and attempted to enable auditd on rhel")
    elif distro == 'alpine':
        logger.warning("auditd not typically available on Alpine; use syslog for app logging")
    else:
        logger.warning("Unknown distro; skipping auditd configuration")

def secure_ssh_config():
    """Secure SSH if present, but warn as SSH is rare in app containers (STIG RHEL-08-010290, CIS 5.2.1)."""
    logger.info("Securing SSH configuration if present (STIG RHEL-08-010290, CIS 5.2.1)")
    logger.warning("SSH is uncommon in application containers; configure only if needed for your app")
    sshd_config = '/etc/ssh/sshd_config'
    if os.path.exists(sshd_config):
        ssh_settings = {
            'PermitRootLogin': 'no',
            'Protocol': '2',
            'PermitEmptyPasswords': 'no',
            'MaxAuthTries': '4',
            'LoginGraceTime': '60',
            'X11Forwarding': 'no',
            'IgnoreRhosts': 'yes',
            'HostbasedAuthentication': 'no',
            'PermitUserEnvironment': 'no',
        }
        with open(sshd_config, 'r') as f:
            lines = f.readlines()
        for key, value in ssh_settings.items():
            found = False
            for i, line in enumerate(lines):
                if re.match(f'^{key}\\s+', line):
                    lines[i] = f"{key} {value}\n"
                    found = True
                    logger.info(f"Updated SSH setting: {key} {value}")
            if not found:
                lines.append(f"{key} {value}\n")
                logger.info(f"Added SSH setting: {key} {value}")
        with open(sshd_config, 'w') as f:
            f.writelines(lines)
        result = run_command(['systemctl', 'restart', 'sshd'], check=False)
        if result and result.returncode != 0:
            logger.warning("SSH restart failed; may not be running in this container")
    else:
        logger.info(f"{sshd_config} not found; skipping SSH configuration as it's not present")

def configure_login_banner():
    """Configure login banner for compliance (STIG RHEL-08-020040)."""
    logger.info("Configuring login banner (STIG RHEL-08-020040)")
    banner_text = "You are accessing a Super Cool Container !"
    issue_file = '/etc/issue'
    try:
        with open(issue_file, 'w') as f:
            f.write(banner_text + "\n\n")
        logger.info(f"Configured login banner in {issue_file}")
    except OSError as e:
        logger.error(f"Error writing to {issue_file}: {e}")

def configure_sudo():
    """Configure sudo if present for controlled app elevation (STIG RHEL-08-010384)."""
    logger.info("Configuring sudo settings if sudo is used by the app (STIG RHEL-08-010384)")
    sudoers_file = '/etc/sudoers'
    settings = [
        ('timestamp_timeout', '0', 'CCE-82888-9', '%s=%s'),
        ('!targetpw', '', 'CCE-82888-9', '%s'),
        ('!rootpw', '', 'CCE-82888-9', '%s'),
        ('!runaspw', '', 'CCE-82888-9', '%s')
    ]
    if os.path.exists(sudoers_file):
        for key, value, cce, fmt in settings:
            replace_or_append(sudoers_file, f'^(Defaults\\s+)?{key}', value, cce, fmt)
        result = run_command(['visudo', '-c'], check=False)
        if result and result.returncode != 0:
            logger.error(f"sudoers validation failed; please check {sudoers_file}")
    else:
        logger.warning(f"{sudoers_file} not found; skipping sudo configuration as it's not present")

def configure_pam_login_attempts(distro):
    """Configure PAM to display login attempts for app monitoring (STIG RHEL-08-020110)."""
    logger.info("Configuring PAM login attempts display (STIG RHEL-08-020110)")
    if distro in ['ubuntu', 'debian', 'rhel']:
        pam_file = '/etc/pam.d/postlogin'
        if os.path.exists(pam_file) or not os.path.exists(pam_file):
            if not os.path.exists(pam_file):
                with open(pam_file, 'a'):
                    pass
            lines = open(pam_file, 'r').readlines()
            lastlog_present = any(re.match(r'^\s*session\s+required\s+pam_lastlog\.so', line) for line in lines)
            if lastlog_present:
                for i, line in enumerate(lines):
                    if re.match(r'^\s*session\s+required\s+pam_lastlog\.so', line):
                        if 'showfailed' not in line:
                            lines[i] = re.sub(r'(pam_lastlog\.so.*)', r'\1 showfailed', line)
                            logger.info(f"Updated pam_lastlog.so with showfailed in {pam_file}")
                        if 'silent' in line:
                            lines[i] = re.sub(r'\s+silent', '', line)
                            logger.info(f"Removed silent option from pam_lastlog.so in {pam_file}")
            else:
                lines.append('session required pam_lastlog.so showfailed\n')
                logger.info(f"Added pam_lastlog.so with showfailed to {pam_file}")
            with open(pam_file, 'w') as f:
                f.writelines(lines)
    else:
        logger.warning("PAM login attempts display not supported on Alpine or unknown distro")

def configure_openssl_entropy():
    """Configure OpenSSL to use strong entropy for app crypto operations (STIG RHEL-08-010384)."""
    logger.info("Configuring OpenSSL strong entropy (STIG RHEL-08-010384)")
    openssl_script = '/etc/profile.d/openssl-rand.sh'
    script_content = """\
#!/bin/bash
openssl()
(
  openssl_bin=/usr/bin/openssl
  case "$*" in
    *\\ -rand\\ *|*\\ -help*) exec $openssl_bin "$@" ;;
  esac
  cmds=`$openssl_bin list -digest-commands -cipher-commands | tr '\\n' ' '`
  for i in `$openssl_bin list -commands`; do
    if $openssl_bin list -options "$i" | grep -q '^rand '; then
      cmds=" $i $cmds"
    fi
  done
  case "$cmds" in
    *\\ "$1"\\ *)
      cmd="$1"; shift
      exec $openssl_bin "$cmd" -rand /dev/random "$@"
      ;;
  esac
  exec $openssl_bin "$@"
)
"""
    try:
        with open(openssl_script, 'w') as f:
            f.write(script_content)
        os.chmod(openssl_script, 0o755)
        logger.info(f"Configured OpenSSL entropy in {openssl_script}")
    except OSError as e:
        logger.error(f"Error writing to {openssl_script}: {e}")

def remove_empty_passwords(distro):
    """Remove nullok from PAM to secure app authentication (STIG RHEL-08-020110)."""
    logger.info("Removing empty passwords for secure logins (STIG RHEL-08-020110)")
    if distro in ['ubuntu', 'debian', 'rhel']:
        auth_files = ['/etc/pam.d/system-auth', '/etc/pam.d/password-auth']
        for pam_file in auth_files:
            if os.path.exists(pam_file):
                run_command(['sed', '-i', '--follow-symlinks', 's/\<nullok\>//g', pam_file], check=False)
                logger.info(f"Removed nullok from {pam_file}")
    else:
        logger.warning("Empty password removal not supported on Alpine or unknown distro")

def configure_max_logins(distro):
    """Configure maximum concurrent login sessions for app control (STIG RHEL-08-020110)."""
    logger.info("Configuring maximum concurrent login sessions (STIG RHEL-08-020110)")
    if distro in ['ubuntu', 'debian', 'rhel']:
        limits_conf = '/etc/security/limits.conf'
        limits_d = '/etc/security/limits.d'
        max_logins = '10'
        if os.path.exists(limits_conf):
            replace_or_append(limits_conf, '^\*\s+hard\s+maxlogins', max_logins, 'CCE-82888-9')
        if os.path.exists(limits_d):
            for conf_file in os.listdir(limits_d):
                conf_path = os.path.join(limits_d, conf_file)
                if os.path.isfile(conf_path):
                    run_command(['sed', '-i', '--follow-symlinks', '/^\s*\*\s+hard\s+maxlogins/d', conf_path], check=False)
                    logger.info(f"Removed maxlogins from {conf_path}")
    else:
        logger.warning("Max logins configuration not supported on Alpine or unknown distro")

def create_non_root_user():
    """Create a non-root user for running the application (CIS 4.6)."""
    logger.info("Creating non-root user for application runtime (CIS 4.6)")
    app_user = 'appuser'
    try:
        pwd.getpwnam(app_user)
        logger.info(f"User {app_user} already exists")
    except KeyError:
        run_command(['useradd', '-m', '-s', '/bin/bash', app_user], check=False)
        run_command(['passwd', '-l', app_user], check=False)  # Lock password
        logger.info(f"Created and locked non-root user {app_user} for app")
    # Suggest in logs to run app as this user in Dockerfile or entrypoint

def remove_unnecessary_users_groups():
    """Remove unnecessary users and groups to minimize app access (STIG RHEL-08-020000, CIS 5.4.2)."""
    logger.info("Removing unnecessary users and groups (STIG RHEL-08-020000, CIS 5.4.2)")
    essential_users = ['root', 'bin', 'daemon', 'adm', 'lp', 'sync', 'shutdown', 'halt', 'mail', 'appuser']
    essential_groups = ['root', 'bin', 'daemon', 'adm', 'lp', 'mail']
    for user in pwd.getpwall():
        if user.pw_name not in essential_users and user.pw_uid >= 1000:
            run_command(['userdel', '-r', user.pw_name], check=False)
            logger.info(f"Removed non-essential user: {user.pw_name}")
    for group in grp.getgrall():
        if group.gr_name not in essential_groups and group.gr_gid >= 1000:
            run_command(['groupdel', group.gr_name], check=False)
            logger.info(f"Removed non-essential group: {group.gr_name}")

def main():
    if os.geteuid() != 0:
        logger.error("This script must be run as root")
        sys.exit(1)

    distro = detect_distro()
    logger.info(f"Starting container-specific hardening process for {distro}")

    update_and_upgrade(distro)
    lock_root_account()
    set_secure_umask()
    secure_file_permissions()
    remove_unnecessary_suid_sgid()
    disable_core_dumps()
    apply_kernel_hardening()
    configure_password_quality(distro)
    configure_pam_faillock(distro)
    configure_pam_pwhistory(distro)
    configure_pam_unix_remember(distro)
    remove_unnecessary_packages(distro)
    install_required_packages(distro)
    configure_auditd(distro)
    secure_ssh_config()
    configure_login_banner()
    configure_sudo()
    configure_pam_login_attempts(distro)
    configure_openssl_entropy()
    remove_empty_passwords(distro)
    configure_max_logins(distro)
    create_non_root_user()
    remove_unnecessary_users_groups()

    logger.info("Container hardening complete. Focus: Application security via minimalism, non-root runtime, and config protections. Review logs. Restart container if needed.")
    logger.warning("For full app security, ensure Dockerfile runs app as non-root (e.g., USER appuser), drops capabilities, and uses read-only filesystem where possible.")

if __name__ == "__main__":
    main()