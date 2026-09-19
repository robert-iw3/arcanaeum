# tasks.py
import invoke
from invoke import task
import os
import sys
import datetime
import logging

# --- Configuration ---
LOG_FILE = "/var/log/k8s_hardening.log"
INVENTORY_FILE = "inventory.ini"
PLAYBOOK_FILE = "playbook.yml"
BACKUP_DIR = f"/var/backups/k8s_hardening_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

@task
def harden(c):
    """
    Runs the full Kubernetes host hardening playbook.
    """
    if os.geteuid() != 0:
        logging.error("This script must be run as root.")
        print("ERROR: This script must be run as root.")
        sys.exit(1)

    # Validate file existence
    if not os.path.exists(INVENTORY_FILE):
        logging.error(f"Inventory file {INVENTORY_FILE} not found.")
        print(f"ERROR: Inventory file {INVENTORY_FILE} not found.")
        sys.exit(1)
    if not os.path.exists(PLAYBOOK_FILE):
        logging.error(f"Playbook file {PLAYBOOK_FILE} not found.")
        print(f"ERROR: Playbook file {PLAYBOOK_FILE} not found.")
        sys.exit(1)

    logging.info("Starting Kubernetes host hardening...")
    print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting Kubernetes host hardening...")

    # Ensure backup directory exists
    os.makedirs(BACKUP_DIR, exist_ok=True)
    logging.info(f"Backups will be stored in {BACKUP_DIR}")
    print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Backups will be stored in {BACKUP_DIR}")

    # Run the Ansible playbook
    cmd = f"ansible-playbook -i {INVENTORY_FILE} {PLAYBOOK_FILE} --extra-vars 'backup_dir={BACKUP_DIR}'"
    try:
        c.run(cmd, pty=True)
        logging.info("Kubernetes host hardening complete.")
        print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Kubernetes host hardening complete.")
        print("Please review configurations and reboot the system to ensure all settings are applied.")
    except invoke.exceptions.Failure as e:
        logging.error("Ansible playbook failed.")
        print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: Ansible playbook failed. See above for details.")
        sys.exit(e.result.exited)

@task
def check(c):
    """
    Performs a dry run to check for any changes without applying them.
    """
    if os.geteuid() != 0:
        logging.error("This script must be run as root.")
        print("ERROR: This script must be run as root.")
        sys.exit(1)

    # Validate file existence
    if not os.path.exists(INVENTORY_FILE):
        logging.error(f"Inventory file {INVENTORY_FILE} not found.")
        print(f"ERROR: Inventory file {INVENTORY_FILE} not found.")
        sys.exit(1)
    if not os.path.exists(PLAYBOOK_FILE):
        logging.error(f"Playbook file {PLAYBOOK_FILE} not found.")
        print(f"ERROR: Playbook file {PLAYBOOK_FILE} not found.")
        sys.exit(1)

    logging.info("Starting dry run to check host state...")
    print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting dry run to check host state...")
    cmd = f"ansible-playbook -i {INVENTORY_FILE} {PLAYBOOK_FILE} --check"
    try:
        c.run(cmd, pty=True)
        logging.info("Dry run complete.")
        print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Dry run complete. Changes that would be made are shown above.")
    except invoke.exceptions.Failure as e:
        logging.error("Dry run failed.")
        print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: Dry run failed. See above for details.")
        sys.exit(e.result.exited)