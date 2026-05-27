#!/usr/bin/env python3
import os
import subprocess
import shutil
import datetime
import logging
import pwd
from pathlib import Path

# Check for root privileges
if os.geteuid() != 0:
    print("❌ Run me as root")
    exit(1)

# Setup logging
backup_dir = f"/root/hardening-backups-{datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')}"
log_file = "/var/log/hardening.log"
os.makedirs(os.path.dirname(log_file), exist_ok=True)
logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s: %(message)s")
logger = logging.getLogger()

# Variables
apt = shutil.which("apt")
verbose = False
lxc = "container=lxc" in open("/proc/1/environ").read() if os.path.exists("/proc/1/environ") else False
ntp_servers = "0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org 2.ubuntu.pool.ntp.org 3.ubuntu.pool.ntp.org pool.ntp.org"
timesyncd_conf = "/etc/systemd/timesyncd.conf"
system_conf = "/etc/systemd/system.conf"
user_conf = "/etc/systemd/user.conf"
script_count = 1

def log(message):
    global script_count
    print(message)
    logger.info(message)

def backup_file(*files):
    os.makedirs(backup_dir, exist_ok=True)
    for file in files:
        if os.path.isfile(file):
            shutil.copy(file, f"{backup_dir}/{os.path.basename(file)}.{datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')}")
            log(f"Backed up {file} to {backup_dir}")

def run_command(cmd, check=True):
    try:
        result = subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)
        return result
    except subprocess.CalledProcessError as e:
        log(f"Warning: Command '{cmd}' failed: {e}")
        return None

def apport():
    global script_count
    log(f"[{script_count}] Disabling apport, ubuntu-report, and popularity-contest")
    backup_file("/etc/default/apport")

    if shutil.which("gsettings"):
        run_command("gsettings set com.ubuntu.update-notifier show-apport-crashes false", check=False)

    if shutil.which("ubuntu-report"):
        run_command("ubuntu-report -f send no", check=False)

    if os.path.isfile("/etc/default/apport"):
        with open("/etc/default/apport", "r") as f:
            content = f.read()
        with open("/etc/default/apport", "w") as f:
            f.write(content.replace("enabled=1", "enabled=0"))
        run_command("systemctl stop apport.service", check=False)
        run_command("systemctl mask apport.service", check=False)

    if run_command("dpkg -l | grep '^ii.*popularity-contest'", check=False):
        run_command(f"{apt} purge -y popularity-contest", check=False)

    run_command("systemctl daemon-reload", check=False)
    if verbose:
        run_command("systemctl status apport.service --no-pager", check=False)
    script_count += 1

def aptget():
    global script_count
    log(f"[{script_count}] Updating package index")
    run_command(f"{apt} update") or exit(1)
    script_count += 1

    log(f"[{script_count}] Upgrading installed packages")
    run_command(f"{apt} -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' -y upgrade") or exit(1)
    script_count += 1

def aptget_clean():
    global script_count
    log(f"[{script_count}] Removing unused packages")
    run_command(f"{apt} -y clean", check=False)
    run_command(f"{apt} -y autoremove", check=False)

    result = run_command("dpkg -l | grep '^rc' | awk '{print $2}'", check=False)
    if result and result.stdout:
        for pkg in result.stdout.splitlines():
            run_command(f"{apt} purge -y {pkg}", check=False)
    script_count += 1

def aptget_configure():
    global script_count
    log(f"[{script_count}] Configuring APT")
    apt_conf = "/etc/apt/apt.conf.d/98-hardening-ubuntu"
    periodic_conf = "/etc/apt/apt.conf.d/10periodic"
    unattended_conf = "/etc/apt/apt.conf.d/50unattended-upgrades"
    backup_file(apt_conf, periodic_conf, unattended_conf)

    with open(apt_conf, "w") as f:
        f.write("""\
Acquire::http::AllowRedirect "false";
APT::Get::AllowUnauthenticated "false";
APT::Install-Recommends "false";
APT::Get::AutomaticRemove "true";
APT::Install-Suggests "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
Acquire::AllowInsecureRepositories "false";
APT::Sandbox::Seccomp "1";
""")

    with open(periodic_conf, "w") as f:
        f.write("""\
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
""")

    with open(unattended_conf, "a") as f:
        f.write("""\
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
""")

    if verbose:
        for conf in (apt_conf, periodic_conf, unattended_conf):
            with open(conf, "r") as f:
                print(f.read())
    script_count += 1

def aptget_noexec():
    global script_count
    if lxc:
        log(f"[{script_count}] Skipping /tmp noexec in LXC")
        return
    log(f"[{script_count}] Configuring DPkg noexec for /tmp")
    backup_file("/etc/apt/apt.conf.d/99noexec-tmp")
    with open("/etc/apt/apt.conf.d/99noexec-tmp", "w") as f:
        f.write("""\
DPkg::Pre-Invoke {"mount -o remount,exec,nodev,nosuid /tmp";};
DPkg::Post-Invoke {"mount -o remount,mode=1777,strictatime,noexec,nodev,nosuid /tmp";};
""")
    script_count += 1

def remove_users():
    global script_count
    log(f"[{script_count}] Removing unnecessary users")
    for user in ["games", "gnats", "irc", "list", "news", "sync", "uucp"]:
        try:
            pwd.getpwnam(user)
            run_command(f"pkill -u {user}", check=False)
            run_command(f"userdel -r {user}", check=False)
            log(f"User {user} deleted successfully")
        except KeyError:
            if verbose:
                log(f"User {user} does not exist")
    script_count += 1

def timesyncd():
    global script_count
    log(f"[{script_count}] Configuring systemd-timesyncd")
    backup_file(timesyncd_conf)
    with open(timesyncd_conf, "w") as f:
        f.write(f"""\
[Time]
NTP={ntp_servers}
FallbackNTP=pool.ntp.org
RootDistanceMaxSec=1
""")
    run_command("systemctl restart systemd-timesyncd", check=False)
    run_command("timedatectl set-ntp true", check=False)
    if verbose:
        run_command("systemctl status systemd-timesyncd --no-pager", check=False)
        run_command("timedatectl", check=False)
    script_count += 1

def systemdconf():
    global script_count
    log(f"[{script_count}] Configuring systemd system and user settings")
    backup_file(system_conf, user_conf)
    for conf in (system_conf, user_conf):
        with open(conf, "r") as f:
            content = f.read()
        content = content.replace("#DumpCore=yes", "DumpCore=no").replace("#CrashShell=yes", "CrashShell=no")
        content = content.replace("#DefaultLimitCORE=.*", "DefaultLimitCORE=0")
        content = content.replace("#DefaultLimitNOFILE=.*", "DefaultLimitNOFILE=1024")
        content = content.replace("#DefaultLimitNPROC=.*", "DefaultLimitNPROC=1024")
        with open(conf, "w") as f:
            f.write(content)
    run_command("systemctl daemon-reload", check=False)
    if verbose:
        for conf in (system_conf, user_conf):
            with open(conf, "r") as f:
                print(f.read())
    script_count += 1

def kernel_params():
    global script_count
    log(f"[{script_count}] Configuring kernel parameters")
    sysctl_conf = "/etc/sysctl.d/99-hardening.conf"
    backup_file(sysctl_conf)
    with open(sysctl_conf, "w") as f:
        f.write("""\
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.ip_forward = 0
fs.suid_dumpable = 0
""")
    run_command(f"sysctl -p {sysctl_conf}", check=False)
    script_count += 1

def disable_filesystems():
    global script_count
    log(f"[{script_count}] Disabling unnecessary filesystems")
    modprobe_conf = "/etc/modprobe.d/CIS.conf"
    backup_file(modprobe_conf)
    with open(modprobe_conf, "w") as f:
        f.write("""\
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
""")
    script_count += 1

def file_permissions():
    global script_count
    log(f"[{script_count}] Setting file permissions")
    for file in ("/etc/passwd", "/etc/group"):
        os.chmod(file, 0o644) or log(f"Warning: Failed to set permissions on {file}")
    os.chmod("/etc/shadow", 0o600) or log("Warning: Failed to set permissions on /etc/shadow")
    script_count += 1

def password_policy():
    global script_count
    log(f"[{script_count}] Configuring password policies")
    login_defs = "/etc/login.defs"
    backup_file(login_defs)
    with open(login_defs, "r") as f:
        content = f.read()
    content = content.replace("PASS_MAX_DAYS.*", "PASS_MAX_DAYS 90")
    content = content.replace("PASS_MIN_DAYS.*", "PASS_MIN_DAYS 1")
    content = content.replace("PASS_WARN_AGE.*", "PASS_WARN_AGE 7")
    with open(login_defs, "w") as f:
        f.write(content)
    script_count += 1

def ssh_hardening():
    global script_count
    log(f"[{script_count}] Hardening SSH configuration")
    sshd_conf = "/etc/ssh/sshd_config"
    backup_file(sshd_conf)
    with open(sshd_conf, "a") as f:
        f.write("\nPermitRootLogin no\nPasswordAuthentication no\n")
    run_command("systemctl restart sshd", check=False)
    if verbose:
        with open(sshd_conf, "r") as f:
            print(f.read())
    script_count += 1

# Main execution
if shutil.which("apt"):
    log("Starting Ubuntu hardening")
    apport()
    aptget()
    aptget_clean()
    aptget_configure()
    aptget_noexec()
    remove_users()
    timesyncd()
    systemdconf()
    kernel_params()
    disable_filesystems()
    file_permissions()
    password_policy()
    ssh_hardening()
    log("Hardening complete")
else:
    log("Error: This is not an Ubuntu/Debian system")
    exit(1)