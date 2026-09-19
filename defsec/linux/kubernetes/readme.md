# Kubernetes Hardening Guide

This project hardens a Kubernetes host based on NSA/CISA and CIS/STIG guidelines.

## Prerequisites
- Linux (Debian/Ubuntu or CentOS/RHEL)
- Root access
- Python 3.8+
- Ansible 6.0.0+, ansible-core 2.12.0+, invoke 2.0.0+
- Kubernetes installed

## File Structure
- `inventory.ini`: Defines target hosts (localhost by default).
- `tasks.py`: Invoke tasks to run or check the hardening playbook.
- `requirements.txt`: Python dependencies.
- `playbook.yml`: Main Ansible playbook.
- `firewall_tasks.yml`: Firewall configuration.
- `mac_tasks.yml`: SELinux/AppArmor configuration.
- `templates/k8s-hardening.rules.j2`: Auditd rules.
- `templates/chrony.conf.j2`: Chrony configuration.

## Setup
1. Clone the repository or copy files to the target host.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Ensure `/var/log/k8s_hardening.log` and `/var/backups/` are writable by root.

## Usage
- **Dry Run**: Check changes without applying:
  ```bash
  sudo invoke check
  ```
- **Apply Hardening**: Run the playbook:
  ```bash
  sudo invoke harden
  ```
- Review `/var/log/k8s_hardening.log` for logs.
- Reboot the system after hardening to apply changes.

## Notes
- Backups are stored in `/var/backups/k8s_hardening_<timestamp>`.
- Ensure Kubernetes ports (e.g., 6443, 10250) are allowed in your firewall.
- Verify SELinux/AppArmor and auditd compatibility with your system.