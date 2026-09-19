#!/usr/bin/env python3
import argparse
import yaml
import subprocess
import os
import time
import shutil
import logging
from pathlib import Path
from datetime import datetime

CONFIG_FILE = "/etc/selinux_guardian/selinux-config.yaml"
WORK_DIR = "/var/lib/selinux_guardian"
LOG_FILE = "/var/log/selinux_guardian.log"

os.makedirs(WORK_DIR, exist_ok=True)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s | %(message)s")

def log(msg):
    print(f"[{datetime.utcnow().isoformat()}] {msg}")
    logging.info(msg)

def run(cmd, check=True):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)

def detect_distro():
    if Path("/etc/redhat-release").exists() or Path("/etc/rocky-release").exists():
        return "rhel"
    elif Path("/etc/debian_version").exists():
        return "debian"
    return "unknown"

def install_prereqs():
    distro = detect_distro()
    log(f"Detected distro: {distro}")
    if distro == "rhel":
        run("dnf install -y policycoreutils setools-console audit2allow policycoreutils-python-utils selinux-policy-devel")
    elif distro == "debian":
        run("apt update && apt install -y selinux-basics selinux-policy-default auditd setools policycoreutils")
        run("selinux-activate")
    log("Prerequisites installed")

def setup_selinux():
    run("setenforce 0", check=False)
    with open("/etc/selinux/config", "w") as f:
        f.write(f"SELINUX=permissive\nSELINUXTYPE=targeted\n")
    log("SELinux set to permissive + targeted policy")

def learning_phase(hours):
    log(f"Starting LEARNING PHASE for {hours}h — use the system normally")
    log("All AVC denials will be recorded...")
    run("systemctl restart auditd", check=False)
    time.sleep(hours * 3600)  # or use interactive wait
    log("Learning phase complete")

def generate_policies(config):
    log("Generating policies from audit logs + YAML config")
    # Global audit2allow for base module
    run("ausearch -m avc -ts recent | audit2allow -M base_policy")
    run("semodule -i base_policy.pp")

    for app in config.get("applications", []):
        name = app["name"]
        binary = app.get("binary")
        if binary and Path(binary).exists():
            run(f"sepolicy generate --init {binary} -n {name}_policy")
            run(f"semodule -i {name}_policy.pp")
            log(f"Generated policy for {name}")

    # Apply YAML booleans & contexts
    for b in config.get("global_booleans", []):
        run(f"setsebool -P {b['name']} {str(b['value']).lower()}")
    for fc in config.get("file_contexts", []):
        run(f"semanage fcontext -a -t {fc['context']} '{fc['path']}'")
        run(f"restorecon -R -v {fc['path'].split('(')[0]}")

def enforce_mode():
    run("setenforce 1")
    with open("/etc/selinux/config", "w") as f:
        f.write("SELINUX=enforcing\nSELINUXTYPE=targeted\n")
    log("SELinux now in ENFORCING mode")

def main():
    parser = argparse.ArgumentParser(description="SELinux Guardian - 2026 Edition")
    parser.add_argument("--mode", choices=["setup", "learn", "generate", "enforce"], required=True)
    parser.add_argument("--config", default=CONFIG_FILE)
    args = parser.parse_args()

    Path("/etc/selinux_guardian").mkdir(parents=True, exist_ok=True)
    shutil.copy(args.config, CONFIG_FILE) if Path(args.config).exists() else None

    with open(CONFIG_FILE) as f:
        config = yaml.safe_load(f)

    install_prereqs()
    setup_selinux()

    if args.mode == "learn":
        learning_phase(config["selinux"]["learning_hours"])
    elif args.mode == "generate":
        generate_policies(config)
    elif args.mode == "enforce":
        enforce_mode()

    log("SELinux Guardian complete. Review /var/log/audit/audit.log and generated policies.")

if __name__ == "__main__":
    main()