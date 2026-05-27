#!/usr/bin/env python3
"""
Python script to audit SSH keys in user home directories, ensuring secure logging practices.

Licensed under the MIT License (MIT).

RW

Usage: sudo python3 ssh_key_audit_v2.py [--verbose] [--json] [--key-count <count>] [--seconds <seconds>]
"""

import argparse
import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import List
import re
import shutil

# Configuration
LOG_FILE = "/var/log/ssh_key_audit.log"
JSON_LOG_FILE = "/var/log/ssh_key_audit.json"
KEY_COUNT = 10
SECONDS_LIMIT = 86400  # 24 hours

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
    """Initialize JSON log file with secure permissions."""
    Path(JSON_LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(JSON_LOG_FILE).touch()
    os.chown(JSON_LOG_FILE, 0, 0)
    os.chmod(JSON_LOG_FILE, 0o600)  # Root-only permissions

def log_json(status: str, message: str):
    """Log to JSON file."""
    with open(JSON_LOG_FILE, "a") as f:
        json.dump({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "status": status, "message": message}, f)
        f.write("\n")

def redact_path(path: str) -> str:
    """Redact usernames from file paths (e.g., /home/user/.ssh -> [HOME]/.ssh)."""
    return re.sub(r'/home/[^/]+', '[HOME]', str(path))

def check_privileges():
    """Check for root or CAP_DAC_READ_SEARCH and container environment."""
    try:
        result = subprocess.run(["capsh", "--print"], capture_output=True, text=True, check=True)
        if "cap_dac_read_search" not in result.stdout:
            logger.error("This script requires root or CAP_DAC_READ_SEARCH privileges")
            log_json("ERROR", "This script requires root or CAP_DAC_READ_SEARCH privileges")
            exit(1)
        # Warn about container environment
        if (Path('/.dockerenv').exists() or
                Path('/run/.containerenv').exists() or
                any('docker' in line or 'lxc' in line for line in Path('/proc/1/cgroup').read_text().splitlines())):
            logger.warning("Running in a container environment; logs may be exposed to host or other containers")
            log_json("WARNING", "Running in a container environment; logs may be exposed")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to check capabilities: {e}")
        log_json("ERROR", f"Failed to check capabilities: {e}")
        exit(1)

def check_deps():
    """Check for required dependencies."""
    deps = ["awk", "grep", "sort", "uniq", "stat"]
    for cmd in deps:
        if not shutil.which(cmd):
            logger.error(f"{cmd} is required but not installed")
            log_json("ERROR", f"{cmd} not installed")
            exit(1)

def validate_path(path: str) -> Path:
    """Validate and resolve a path."""
    path = Path(path).resolve()
    if ".." in str(path):
        logger.error("Invalid path detected")
        log_json("ERROR", "Invalid path detected")
        exit(1)
    return path

def get_home_dirs() -> List[Path]:
    """Get list of valid home directories."""
    try:
        result = subprocess.run("awk -F':' '$6 && $6 !~ /\/nologin|\/false/ {print $6}' /etc/passwd | sort -u", shell=True, capture_output=True, text=True, check=True)
        return [validate_path(d) for d in result.stdout.splitlines()]
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to read /etc/passwd: {e}")
        log_json("ERROR", f"Failed to read /etc/passwd: {e}")
        exit(1)

def find_ssh_private_key(home_dirs: List[Path], verbose: bool):
    """Check for SSH private keys."""
    logger.info("Checking for SSH private keys")
    log_json("INFO", "Checking for SSH private keys")
    for dir in home_dirs:
        ssh_dir = dir / ".ssh"
        if ssh_dir.is_dir():
            if (ssh_dir.stat().st_mode & 0o777) != 0o700:
                msg = "Incorrect permissions on user SSH directory (should be 700)"
                logger.info(f"FAIL, {msg}")
                log_json("FAIL", msg)
            for file in ssh_dir.glob("*"):
                if file.is_file():
                    try:
                        with open(file, "r") as f:
                            if "PRIVATE KEY" in f.read():
                                msg = "Private key found in user SSH directory"
                                logger.info(f"FAIL, {msg}")
                                log_json("FAIL", msg)
                                if verbose:
                                    print("Command: grep -l 'PRIVATE KEY' [HOME]/.ssh/*")
                                    print("Output: Private key detected")
                        if (file.stat().st_mode & 0o777) != 0o600:
                            msg = "Incorrect permissions on user SSH file (should be 600)"
                            logger.info(f"FAIL, {msg}")
                            log_json("FAIL", msg)
                    except (PermissionError, IOError) as e:
                        msg = f"Cannot read user SSH file: {e}"
                        logger.warning(msg)
                        log_json("WARNING", msg)
        else:
            logger.debug("No user SSH directory found")

def find_ssh_keys_duplicates(home_dirs: List[Path], verbose: bool):
    """Check for duplicate SSH keys."""
    logger.info("Checking for duplicate SSH keys")
    log_json("INFO", "Checking for duplicate SSH keys")
    for dir in home_dirs:
        auth_keys = dir / ".ssh/authorized_keys"
        if auth_keys.is_file():
            if (auth_keys.stat().st_mode & 0o777) != 0o600:
                msg = "Incorrect permissions on user authorized_keys (should be 600)"
                logger.info(f"FAIL, {msg}")
                log_json("FAIL", msg)
            try:
                result = subprocess.run(f"sort {auth_keys} | uniq -c | awk '$1 > 1'", shell=True, capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    count = line.strip().split(maxsplit=1)[0]
                    msg = f"Duplicate key found in user authorized_keys ({count} occurrences)"
                    logger.info(f"FAIL, {msg}")
                    log_json("FAIL", msg)
                    if verbose:
                        print("Command: sort [HOME]/.ssh/authorized_keys | uniq -c")
                        print(f"Output: {count} duplicate(s) detected")
            except subprocess.CalledProcessError as e:
                msg = f"Failed to check duplicates in user authorized_keys: {e}"
                logger.warning(msg)
                log_json("WARNING", msg)

def find_ssh_keys_excessive(home_dirs: List[Path], key_count: int, verbose: bool):
    """Check for excessive SSH keys."""
    logger.info(f"Checking for excessive SSH keys (threshold: {key_count})")
    log_json("INFO", f"Checking for excessive SSH keys (threshold: {key_count})")
    for dir in home_dirs:
        auth_keys = dir / ".ssh/authorized_keys"
        if auth_keys.is_file():
            num_keys = sum(1 for _ in auth_keys.open())
            if num_keys >= key_count:
                msg = f"User authorized_keys has {num_keys} keys (exceeds {key_count})"
                logger.info(f"FAIL, {msg}")
                log_json("FAIL", msg)
                if verbose:
                    print("Command: wc -l [HOME]/.ssh/authorized_keys")
                    print(f"Output: {num_keys} keys")

def find_ssh_keys_modified_24hr(home_dirs: List[Path], seconds_limit: int, verbose: bool):
    """Check for recently modified SSH keys."""
    logger.info(f"Checking for recently modified SSH keys (within {seconds_limit} seconds)")
    log_json("INFO", f"Checking for recently modified SSH keys (within {seconds_limit} seconds)")
    now = int(time.time())
    for dir in home_dirs:
        auth_keys = dir / ".ssh/authorized_keys"
        if auth_keys.is_file():
            mtime = int(auth_keys.stat().st_mtime)
            diff = now - mtime
            if diff <= seconds_limit:
                msg = f"User authorized_keys modified {diff} seconds ago"
                logger.info(f"FAIL, {msg}")
                log_json("FAIL", msg)
                if verbose:
                    print("Command: stat -c %Y [HOME]/.ssh/authorized_keys")
                    print(f"Output: {mtime}")

def find_ssh_keys_options_search(home_dirs: List[Path], verbose: bool):
    """Check for SSH key options."""
    logger.info("Checking for SSH key options")
    log_json("INFO", "Checking for SSH key options")
    for dir in home_dirs:
        auth_keys = dir / ".ssh/authorized_keys"
        if auth_keys.is_file():
            try:
                result = subprocess.run(f"grep -E '^(command|environment|agent-forwarding|port-forwarding|user-rc|X11-forwarding)' {auth_keys}", shell=True, capture_output=True, text=True)
                for _ in result.stdout.splitlines():
                    msg = "SSH key option found in user directory"
                    logger.info(f"FAIL, {msg}")
                    log_json("FAIL", msg)
                    if verbose:
                        print("Command: grep -E '^(command|environment|agent-forwarding|port-forwarding|user-rc|X11-forwarding)' [HOME]/.ssh/authorized_keys")
                        print("Output: SSH key option detected")
            except subprocess.CalledProcessError:
                pass  # No options found

def ssh_keys2_search(home_dirs: List[Path], verbose: bool):
    """Check for deprecated authorized_keys2 files."""
    logger.info("Checking for deprecated authorized_keys2 files")
    log_json("INFO", "Checking for deprecated authorized_keys2 files")
    for dir in home_dirs:
        auth_keys2 = dir / ".ssh/authorized_keys2"
        if auth_keys2.is_file():
            msg = "Deprecated authorized_keys2 found in user directory"
            logger.info(f"FAIL, {msg}")
            log_json("FAIL", msg)
            if verbose:
                print("Command: find [HOME]/.ssh -name authorized_keys2")
                print("Output: Deprecated authorized_keys2 found")

def main():
    parser = argparse.ArgumentParser(description="Audit SSH keys in user home directories")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed command output (stdout only)")
    parser.add_argument("--json", "-j", action="store_true", help="Output logs in JSON format")
    parser.add_argument("--key-count", "-k", type=int, default=KEY_COUNT, help=f"Set max keys threshold (default: {KEY_COUNT})")
    parser.add_argument("--seconds", "-s", type=int, default=SECONDS_LIMIT, help=f"Set modification time limit in seconds (default: {SECONDS_LIMIT})")
    args = parser.parse_args()

    # Initialize logging with secure permissions
    Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(LOG_FILE).touch()
    os.chown(LOG_FILE, 0, 0)
    os.chmod(LOG_FILE, 0o600)  # Root-only permissions
    if args.json:
        setup_json_logging()

    logger.info("Starting SSH key audit")
    log_json("INFO", "Starting SSH key audit")

    check_deps()
    check_privileges()

    home_dirs = get_home_dirs()

    find_ssh_private_key(home_dirs, args.verbose)
    find_ssh_keys_duplicates(home_dirs, args.verbose)
    find_ssh_keys_excessive(home_dirs, args.key_count, args.verbose)
    find_ssh_keys_modified_24hr(home_dirs, args.seconds, args.verbose)
    find_ssh_keys_options_search(home_dirs, args.verbose)
    ssh_keys2_search(home_dirs, args.verbose)

    logger.info("SSH key audit complete")
    log_json("INFO", "SSH key audit complete")
    if args.json:
        logger.info(f"JSON output written to {JSON_LOG_FILE}")
        log_json("INFO", f"JSON output written to {JSON_LOG_FILE}")

if __name__ == "__main__":
    main()