import os
import subprocess
import logging
import shutil
import datetime
import argparse

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Apply RHEL 8 and RHEL 9 STIG configurations to RHEL 10-like systems.")
parser.add_argument("--disruptive", action="store_true", help="Enable disruptive CAT III remediations")
parser.add_argument("--container", action="store_true", help="Run in container mode, skipping inapplicable controls")
args = parser.parse_args()

# Configure logging
logging.basicConfig(
    filename=f"rhel10_stig_compliance_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def run_command(command, check=True):
    """Execute a shell command and return output."""
    try:
        result = subprocess.run(command, shell=True, check=check, capture_output=True, text=True)
        logging.info(f"Command executed: {command}\nOutput: {result.stdout}")
        return result
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {command}\nError: {e.stderr}")
        return e

def backup_file(file_path):
    """Create a backup of the specified file."""
    if os.path.exists(file_path):
        backup_path = f"{file_path}.bak_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        shutil.copy2(file_path, backup_path)
        logging.info(f"Backed up {file_path} to {backup_path}")
        return backup_path
    return None

def check_root():
    """Ensure script is run as root."""
    if os.geteuid() != 0:
        logging.error("This script must be run as root.")
        raise PermissionError("This script must be run as root.")

def enable_fips_mode():
    """Enable FIPS mode (CAT I: RHEL-08-010470, RHEL-09-671010, V-257888)."""
    logging.info("Checking FIPS mode status...")
    result = run_command("cat /proc/sys/crypto/fips_enabled")
    if result.stdout.strip() == "1":
        logging.info("FIPS mode already enabled.")
        return

    logging.info("Enabling FIPS mode...")
    run_command("grubby --update-kernel=ALL --args='fips=1'")
    run_command("update-crypto-policies --set FIPS")
    logging.warning("FIPS mode enabled. System reboot required to apply changes.")
    print("FIPS mode enabled. Please reboot the system to apply changes.")

def apply_cat1_configs():
    """Apply CAT I STIG configurations (RHEL 8, RHEL 9, MITRE InSpec)."""
    logging.info("Applying CAT I configurations...")

    # Harden SSH configuration (CAT I: RHEL-08-010050, RHEL-09-631020, V-257888)
    sshd_config = "/etc/ssh/sshd_config"
    backup_file(sshd_config)
    with open(sshd_config, "a") as f:
        f.write("\n# STIG Hardening (CAT I)\n")
        f.write("Protocol 2\n")
        f.write("Ciphers aes256-ctr,aes192-ctr,aes128-ctr\n")
        f.write("MACs hmac-sha2-512,hmac-sha2-256\n")
        f.write("PermitRootLogin no\n")
        f.write("LoginGraceTime 60\n")  # RHEL-08-010290
        f.write("MaxAuthTries 4\n")  # V-258024
    run_command("systemctl restart sshd")
    logging.info("SSH configuration hardened (CAT I).")

    # Ensure only root has UID 0 (CAT I: RHEL-08-010150, RHEL-09-020310)
    result = run_command("awk -F: '($3 == 0 && $1 != \"root\") {print $1}' /etc/passwd", check=False)
    if result.stdout.strip():
        logging.warning(f"Non-root accounts with UID 0 found: {result.stdout.strip()}")
        print("Warning: Non-root accounts with UID 0 detected. Manual remediation required.")

def apply_cat2_configs():
    """Apply CAT II STIG configurations (RHEL 8, RHEL 9, MITRE InSpec)."""
    logging.info("Applying CAT II configurations...")

    # Set permissions on critical files (CAT II: RHEL-08-010600, RHEL-09-232265)
    run_command("chmod 600 /etc/crontab")
    run_command("chown root:root /etc/crontab")
    logging.info("Permissions on /etc/crontab hardened.")

    # Configure password policies (CAT II: RHEL-08-020110, RHEL-09-010280, V-257888)
    backup_file("/etc/security/pwquality.conf")
    run_command("sed -i '/^minlen/s/.*/minlen = 15/' /etc/security/pwquality.conf")
    run_command("sed -i '/^dcredit/s/.*/dcredit = -1/' /etc/security/pwquality.conf")
    run_command("sed -i '/^ucredit/s/.*/ucredit = -1/' /etc/security/pwquality.conf")
    run_command("sed -i '/^ocredit/s/.*/ocredit = -1/' /etc/security/pwquality.conf")
    run_command("sed -i '/^lcredit/s/.*/lcredit = -1/' /etc/security/pwquality.conf")
    logging.info("Password policies configured (minlen=15, complexity requirements).")

    # Configure account lockout (CAT II: V-257888)
    backup_file("/etc/security/faillock.conf")
    run_command("sed -i '/^deny/s/.*/deny = 3/' /etc/security/faillock.conf")
    run_command("sed -i '/^unlock_time/s/.*/unlock_time = 600/' /etc/security/faillock.conf")
    logging.info("Account lockout configured (deny=3, unlock_time=600).")

    # Disable IPv4 ICMP redirects (CAT II: RHEL-08-040170, RHEL-09-040641)
    run_command("sysctl -w net.ipv4.conf.all.accept_redirects=0")
    backup_file("/etc/sysctl.conf")
    run_command("echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.conf")
    logging.info("IPv4 ICMP redirects disabled.")

    # Synchronize clocks with NTP server (CAT II: RHEL-08-040290, RHEL-09-040500)
    if not args.container:
        backup_file("/etc/chrony.conf")
        run_command("sed -i '/^server /d' /etc/chrony.conf")
        run_command("echo 'server time.google.com iburst maxpoll 10' >> /etc/chrony.conf")
        run_command("systemctl enable chronyd")
        run_command("systemctl restart chronyd")
        logging.info("Chrony configured for NTP synchronization.")
    else:
        logging.info("Skipping NTP configuration in container environment.")

def apply_cat3_configs():
    """Apply CAT III STIG configurations, with optional disruptive remediations (RHEL 8, RHEL 9, MITRE InSpec)."""
    logging.info("Applying CAT III configurations...")

    # Set UMASK for default permissions (CAT III: RHEL-08-020240, RHEL-09-020240)
    backup_file("/etc/login.defs")
    run_command("sed -i '/^UMASK/s/.*/UMASK 077/' /etc/login.defs")
    logging.info("UMASK set to 077 for default permissions.")

    # Disable unused filesystems (CAT III: RHEL-08-010380)
    if not args.container:
        filesystems = ["cramfs", "squashfs", "udf"]
        for fs in filesystems:
            run_command(f"modprobe -r {fs}", check=False)
            run_command(f"echo 'install {fs} /bin/true' >> /etc/modprobe.d/disable-filesystems.conf")
        logging.info("Unused filesystems disabled.")
    else:
        logging.info("Skipping filesystem disablement in container environment.")

    # Configure session timeout (CAT III: V-258024)
    backup_file("/etc/profile.d/tmout.sh")
    with open("/etc/profile.d/tmout.sh", "w") as f:
        f.write('export TMOUT=900\n')
        f.write('readonly TMOUT\n')
    logging.info("Session timeout set to 900 seconds.")

    if args.disruptive:
        # Configure auditd (CAT III: RHEL-08-030490, RHEL-09-411075)
        backup_file("/etc/audit/auditd.conf")
        run_command("sed -i '/^max_log_file/s/.*/max_log_file = 100/' /etc/audit/auditd.conf")
        run_command("sed -i '/^space_left_action/s/.*/space_left_action = email/' /etc/audit/auditd.conf")
        run_command("systemctl restart auditd")
        logging.info("Auditd configured with max_log_file=100 and space_left_action=email (disruptive).")
    else:
        logging.info("Skipping disruptive CAT III configurations (e.g., extensive auditd rules).")

def run_oscap_scan():
    """Run OpenSCAP scan to verify compliance."""
    logging.info("Running OpenSCAP compliance scan...")
    profile = "xccdf_org.ssgproject.content_profile_stig"
    result_file = f"stig_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
    run_command(f"oscap xccdf eval --profile {profile} --results {result_file} /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml")
    logging.info(f"OpenSCAP scan completed. Results saved to {result_file}.")
    print(f"OpenSCAP scan completed. Results saved to {result_file}.")

def main():
    try:
        check_root()
        enable_fips_mode()
        apply_cat1_configs()
        apply_cat2_configs()
        apply_cat3_configs()
        run_oscap_scan()
        logging.info("STIG configuration completed successfully.")
        print("STIG configuration applied. Check the log file and OpenSCAP results for details.")
    except Exception as e:
        logging.error(f"Error during execution: {str(e)}")
        print(f"An error occurred. Check the log file for details.")

if __name__ == "__main__":
    main()