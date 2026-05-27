#!/usr/bin/env python3
"""
Python script to toggle Suricata rule actions between 'alert' and 'drop' for user-selected rules or all rules in a directory.
Includes rollback, concurrency, and rule syntax validation with auto-correction for common issues.
Example rules: Salt Typhoon/UNC4841 and Docker API malware rulesets.
Requires Suricata in inline IPS mode (see suricata.yaml).
"""

import os
import argparse
import re
import logging
import shutil
from pathlib import Path
import subprocess
import glob
import concurrent.futures
import tempfile

# Configuration
RULES_DIR = "/etc/suricata/rules/"
BACKUP_DIR = "/etc/suricata/rules/backup/"
SURICATA_CONFIG = "/etc/suricata/suricata.yaml"
LOG_FILE = "/var/log/suricata/toggle_rule_blocking.log"
MAX_WORKERS = 4  # Adjust based on system resources

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def validate_rule_file(rule_file):
    """Validate that the rule file exists."""
    rule_path = Path(RULES_DIR) / rule_file
    if not rule_path.is_file():
        logger.error(f"Rule file {rule_path} not found.")
        raise FileNotFoundError(f"Rule file {rule_path} not found.")
    return rule_path

def backup_rule_file(rule_file):
    """Create a backup of the rule file."""
    rule_path = Path(RULES_DIR) / rule_file
    backup_path = Path(BACKUP_DIR) / f"{rule_file}.{os.getpid()}.bak"
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(rule_path, backup_path)
    logger.info(f"Backed up {rule_path} to {backup_path}")
    return backup_path

def restore_rule_file(rule_file):
    """Restore the rule file from the most recent backup."""
    rule_path = Path(RULES_DIR) / rule_file
    backup_files = sorted(glob.glob(os.path.join(BACKUP_DIR, f"{rule_file}.*.bak")))
    if not backup_files:
        logger.error(f"No backup found for {rule_file}")
        return False

    latest_backup = backup_files[-1]
    shutil.copy(latest_backup, rule_path)
    logger.info(f"Restored {rule_path} from {latest_backup}")
    return True

def correct_rule_syntax(line):
    """Attempt to correct common rule syntax issues."""
    original_line = line
    # Fix missing semicolon at end of rule
    if not line.rstrip().endswith(";"):
        line = line.rstrip() + ";"
        logger.info(f"Added missing semicolon to rule: {line.strip()}")

    # Ensure valid action (alert or drop)
    line = re.sub(r'^\s*(?:alert|drop)\b', lambda m: m.group(0).lower(), line, flags=re.IGNORECASE)
    if not re.match(r'^\s*(alert|drop)\s+', line):
        logger.warning(f"Invalid action in rule, skipping correction: {original_line.strip()}")
        return original_line

    # Ensure sid is numeric
    sid_match = re.search(r'sid:(\d+);', line)
    if not sid_match:
        logger.warning(f"Missing or invalid SID in rule, skipping correction: {original_line.strip()}")
        return original_line

    if original_line != line:
        logger.info(f"Corrected rule: {line.strip()}")
    return line

def validate_rule_syntax(rule_file, content_lines):
    """Validate rule syntax using Suricata's test mode."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.rules', delete=False) as temp_file:
        temp_file.writelines(content_lines)
        temp_file_path = temp_file.name

    try:
        result = subprocess.run(
            ["suricata", "-T", "-c", SURICATA_CONFIG, "-S", temp_file_path],
            capture_output=True,
            text=True,
            check=True
        )
        logger.info(f"Syntax validation passed for {rule_file}")
        os.unlink(temp_file_path)
        return True, None
    except subprocess.CalledProcessError as e:
        logger.error(f"Syntax validation failed for {rule_file}: {e.stderr}")
        os.unlink(temp_file_path)
        return False, e.stderr

def toggle_rule_action(rule_file, sid, action):
    """Toggle the rule action (alert/drop) for the specified SID."""
    if action not in ["alert", "drop"]:
        logger.error(f"Invalid action: {action}. Must be 'alert' or 'drop'.")
        raise ValueError(f"Invalid action: {action}")

    rule_path = validate_rule_file(rule_file)
    backup_rule_file(rule_file)

    with rule_path.open("r") as f:
        lines = f.readlines()

    sid_pattern = re.compile(rf'(\b{action}\s+.*?sid:{sid};)')
    found = False
    new_lines = []
    for line in lines:
        if sid_pattern.search(line):
            new_action = "drop" if action == "alert" else "alert"
            new_line = sid_pattern.sub(rf"{new_action} \1".replace(f"sid:{sid};", ""), line)
            new_line = new_line.replace(action, new_action, 1)
            new_line = correct_rule_syntax(new_line)
            new_lines.append(new_line)
            found = True
            logger.info(f"Toggled SID {sid} in {rule_file} from {action} to {new_action}")
        else:
            new_lines.append(line)

    if not found:
        logger.warning(f"SID {sid} not found in {rule_file}")
        return False

    # Validate syntax before writing
    is_valid, error = validate_rule_syntax(rule_file, new_lines)
    if not is_valid:
        logger.error(f"Aborting modification of {rule_file} due to syntax error: {error}")
        return False

    with rule_path.open("w") as f:
        f.writelines(new_lines)
    return True

def toggle_all_rules_to_drop(rule_file):
    """Toggle all 'alert' rules in a single file to 'drop'."""
    rule_path = validate_rule_file(rule_file)
    backup_rule_file(rule_file)

    with rule_path.open("r") as f:
        lines = f.readlines()

    new_lines = []
    alert_pattern = re.compile(r'^\s*alert\s+')
    sid_pattern = re.compile(r'sid:(\d+);')
    modified = False
    for line in lines:
        if alert_pattern.match(line):
            sid_match = sid_pattern.search(line)
            if sid_match:
                sid = sid_match.group(1)
                new_line = line.replace("alert", "drop", 1)
                new_line = correct_rule_syntax(new_line)
                new_lines.append(new_line)
                logger.info(f"Toggled SID {sid} in {rule_path.name} to drop")
                modified = True
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)

    if not modified:
        logger.warning(f"No rules toggled to drop in {rule_file}")
        return False

    # Validate syntax before writing
    is_valid, error = validate_rule_syntax(rule_file, new_lines)
    if not is_valid:
        logger.error(f"Aborting modification of {rule_file} due to syntax error: {error}")
        return False

    with rule_path.open("w") as f:
        f.writelines(new_lines)
    return True

def process_all_rules_concurrently(directory):
    """Process all rule files in the directory concurrently to toggle to drop."""
    rule_files = glob.glob(os.path.join(directory, "*.rules"))
    if not rule_files:
        logger.error(f"No .rules files found in {directory}")
        return False

    modified = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_file = {executor.submit(toggle_all_rules_to_drop, Path(rule_file).name): rule_file for rule_file in rule_files}
        for future in concurrent.futures.as_completed(future_to_file):
            rule_file = future_to_file[future]
            try:
                if future.result():
                    modified = True
            except Exception as e:
                logger.error(f"Error processing {rule_file}: {str(e)}")

    return modified

def validate_suricata_config():
    """Validate Suricata configuration."""
    try:
        result = subprocess.run(
            ["suricata", "-T", "-c", SURICATA_CONFIG],
            check=True,
            capture_output=True,
            text=True
        )
        logger.info("Suricata configuration validated successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Suricata configuration validation failed: {e.stderr}")
        return False

def reload_suricata():
    """Reload Suricata to apply rule changes."""
    try:
        result = subprocess.run(
            ["suricatasc", "-c", "reload-rules"],
            check=True,
            capture_output=True,
            text=True
        )
        logger.info("Suricata rules reloaded successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to reload Suricata rules: {e.stderr}")
        return False

def list_available_sids(rule_file):
    """List available SIDs in a rule file."""
    rule_path = validate_rule_file(rule_file)
    sids = []
    sid_pattern = re.compile(r'sid:(\d+);')
    with rule_path.open("r") as f:
        for line in f:
            match = sid_pattern.search(line)
            if match:
                sids.append(match.group(1))
    return sids

def main():
    parser = argparse.ArgumentParser(
        description="Toggle Suricata rule actions (alert/drop) for specified SIDs or all rules in directory.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  List available SIDs: python3 toggle_rule_blocking.py --list
  Toggle SID to drop: python3 toggle_rule_blocking.py --sid 1000001 --action drop
  Toggle SID to alert: python3 toggle_rule_blocking.py --sid 1000001 --action alert
  Toggle all rules to drop: python3 toggle_rule_blocking.py --all-drop
  Restore from backup: python3 toggle_rule_blocking.py --restore --file salt_typhoon_unc4841.rules
"""
    )
    parser.add_argument(
        "--sid", type=int, help="Rule SID to toggle (e.g., 1000001)"
    )
    parser.add_argument(
        "--action", choices=["alert", "drop"], help="Target action (alert or drop)"
    )
    parser.add_argument(
        "--list", action="store_true", help="List available SIDs in rule files"
    )
    parser.add_argument(
        "--file", help="Rule file to modify (default: all .rules files in RULES_DIR)"
    )
    parser.add_argument(
        "--all-drop", action="store_true", help="Toggle all rules in RULES_DIR to drop"
    )
    parser.add_argument(
        "--restore", action="store_true", help="Restore rule file from latest backup"
    )
    args = parser.parse_args()

    if args.list:
        rule_files = glob.glob(os.path.join(RULES_DIR, "*.rules"))
        for rule_file in rule_files:
            sids = list_available_sids(Path(rule_file).name)
            logger.info(f"Available SIDs in {Path(rule_file).name}: {', '.join(sids)}")
        return

    if args.restore:
        rule_files = [args.file] if args.file else glob.glob(os.path.join(RULES_DIR, "*.rules"))
        modified = False
        for rule_file in rule_files:
            if restore_rule_file(Path(rule_file).name):
                modified = True
        if modified and validate_suricata_config():
            reload_suricata()
        elif not modified:
            logger.warning("No rules were restored")
        else:
            logger.error("Aborting rule reload due to invalid configuration")
        return

    if args.all_drop:
        if process_all_rules_concurrently(RULES_DIR):
            if validate_suricata_config():
                reload_suricata()
            else:
                logger.error("Aborting rule reload due to invalid configuration")
        return

    if not args.sid or not args.action:
        parser.error("Both --sid and --action are required unless --list, --all-drop, or --restore is specified")

    rule_files = [args.file] if args.file else glob.glob(os.path.join(RULES_DIR, "*.rules"))
    modified = False
    for rule_file in rule_files:
        if toggle_rule_action(Path(rule_file).name, args.sid, args.action):
            modified = True
    if modified and validate_suricata_config():
        reload_suricata()
    elif not modified:
        logger.warning("No rules were modified")
    else:
        logger.error("Aborting rule reload due to invalid configuration")

if __name__ == "__main__":
    main()

# Notes:
# - Requires root privileges to modify rule files, restore backups, and reload Suricata.
# - Place rule files (e.g., salt_typhoon_unc4841.rules, docker_malware.rules) and supporting files (e.g., salt_typhoon_ips.txt, docker_malware_hashes.txt) in /etc/suricata/rules/ and /etc/suricata/data/.
# - Run with:
#   - Toggle all to drop: python3 toggle_rule_blocking.py --all-drop
#   - Restore backup: python3 toggle_rule_blocking.py --restore [--file <rule_file>]
#   - List SIDs: python3 toggle_rule_blocking.py --list
#   - Toggle specific SID: python3 toggle_rule_blocking.py --sid 1000001 --action drop
# - Uses ThreadPoolExecutor for concurrent processing of rule files.
# - Validates rule syntax with Suricata's test mode and corrects common issues (e.g., missing semicolons).
# - Backups are created in /etc/suricata/rules/backup/ before modifying rules.
# - Logs to /var/log/suricata/toggle_rule_blocking.log for auditing.
# - Follows Suricata best practices: https://suricata.readthedocs.io/en/latest/rules/index.html