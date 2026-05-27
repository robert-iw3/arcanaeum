"""
Argument parser for CSV path and skip-deny-default flag (e.g., python firewall_csv.py --csv_path "firewall_rules.csv" --skip_deny_default).
Checks if running as admin (using ctypes).
Error handling and logging with timestamps.
Skips existing rules by querying netsh.
Requires Python 3.x; run on Windows.
"""

import csv
import subprocess
import argparse
import datetime
import re
import sys
import ctypes
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def log_message(message, log_path='firewall_log.txt'):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_path, 'a') as f:
        f.write(f"{timestamp} - {message}\n")
    print(message)

def rule_exists(display_name):
    try:
        result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name="{display_name}"'], capture_output=True, text=True)
        # Regex for robustness across locales
        return bool(re.search(r'(?i)Rule Name:\s+' + re.escape(display_name), result.stdout))
    except Exception as e:
        log_message(f"Error checking {display_name}: {e}")
        return False

def create_rule(display_name, direction, local_port, protocol, remote_address, action, profile):
    dir_map = {'Inbound': 'in', 'Outbound': 'out'}
    action_map = {'Allow': 'allow', 'Block': 'block'}
    port_type = 'remoteport' if direction == 'Outbound' else 'localport'
    cmd = [
        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
        f'name="{display_name}"', f'dir={dir_map[direction]}',
        f'protocol={protocol}', f'{port_type}={local_port}',
        f'remoteip={remote_address}', f'action={action_map[action]}',
        f'profile={profile.lower()}'
    ]
    subprocess.run(cmd, check=True, capture_output=True)
    log_message(f"[{action.upper()}] Created: {display_name}")

def validate_rule(rule):
    try:
        if rule['port'] != 'Any':
            port = int(rule['port'])
            if not (1 <= port <= 65535):
                raise ValueError("Invalid port")
        if rule['protocol'] not in ['TCP', 'UDP', 'Any']:
            raise ValueError("Invalid protocol")
        if rule['action'] not in ['Allow', 'Block']:
            raise ValueError("Invalid action")
        if rule['profile'] not in ['Any', 'Domain', 'Private', 'Public']:
            raise ValueError("Invalid profile")
        # Updated regex for basic IPv4 and IPv6 support
        if rule['remote_address'] != 'Any':
            ip_regex = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(/(3[0-2]|[12]?[0-9]))?$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(/([0-9]|[1-9][0-9]|1[0-2][0-8]))?$'
            if not re.match(ip_regex, rule['remote_address']):
                raise ValueError("Invalid IP/subnet (IPv4 or IPv6)")
        return True
    except ValueError as e:
        log_message(f"Validation error for {rule['rule_name']}: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Super Enhanced Windows Firewall Python Script",
        epilog="Examples:\n  python script.py --csv_path rules.csv --dry_run --max_workers 5\n  python script.py --interactive\n  python script.py --generate_template",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--csv_path', default='firewall_rules.csv')
    parser.add_argument('--dry_run', action='store_true')
    parser.add_argument('--skip_deny_default', action='store_true')
    parser.add_argument('--restore_backup', action='store_true')
    parser.add_argument('--generate_template', action='store_true')
    parser.add_argument('--interactive', action='store_true')
    parser.add_argument('--backup_path', default='firewall_backup.wfw')
    parser.add_argument('--max_workers', type=int, default=10, help='Max threads for parallel checks')
    args = parser.parse_args()

    if not is_admin():
        log_message("Run as Administrator.")
        sys.exit(1)

    if args.restore_backup:
        if os.path.exists(args.backup_path):
            log_message(f"Restoring from {args.backup_path}")
            subprocess.run(['netsh', 'advfirewall', 'import', args.backup_path])
            log_message("Restore complete.")
        else:
            log_message("No backup found.")
        sys.exit(0)

    if args.generate_template:
        template = """rule_name,direction,port,protocol,remote_address,action,profile
00_FW_HTTP_INBOUND_ALLOW,Inbound,80,TCP,192.168.100.0/24,Allow,Any
01_FW_HTTPS_INBOUND_ALLOW,Inbound,443,TCP,192.168.100.0/24,Allow,Any
02_FW_SSH_INBOUND_ALLOW,Inbound,22,TCP,192.168.100.0/24,Allow,Any
"""
        with open(args.csv_path, 'w') as f:
            f.write(template)
        log_message(f"Template generated at {args.csv_path}")
        sys.exit(0)

    if args.interactive:
        log_message("Interactive mode: Enter rules (blank rule_name to exit).")
        new_rules = []
        while True:
            rule_name = input("Rule Name: ")
            if not rule_name:
                break
            direction = input("Direction (Inbound/Outbound): ")
            port = input("Port: ")
            protocol = input("Protocol (TCP/UDP/Any): ")
            remote_addr = input("Remote Address (IPv4/IPv6): ")
            action = input("Action (Allow/Block): ")
            profile = input("Profile (Any/Domain/Private/Public): ")
            new_rules.append(f"{rule_name},{direction},{port},{protocol},{remote_addr},{action},{profile}\n")
        if new_rules:
            with open(args.csv_path, 'a') as f:
                f.writelines(new_rules)
            log_message(f"Added {len(new_rules)} rules to {args.csv_path}")

    # Backup
    log_message(f"Backing up to {args.backup_path}")
    subprocess.run(['netsh', 'advfirewall', 'export', args.backup_path])

    # Load rules with header validation
    required_headers = ['rule_name', 'direction', 'port', 'protocol', 'remote_address', 'action', 'profile']
    with open(args.csv_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        if not all(h in reader.fieldnames for h in required_headers):
            log_message(f"Invalid CSV headers. Required: {', '.join(required_headers)}")
            sys.exit(1)
        rules = [row for row in reader if validate_rule(row)]

    # Parallel existence checks
    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        futures = {executor.submit(rule_exists, rule['rule_name']): rule for rule in rules}
        existing = {}
        for future in as_completed(futures):
            rule = futures[future]
            try:
                existing[rule['rule_name']] = future.result()
            except Exception as e:
                log_message(f"Check error for {rule['rule_name']}: {e}")

    for rule in rules:
        if existing.get(rule['rule_name'], False):
            log_message(f"Skipping existing: {rule['rule_name']}")
            continue
        if args.dry_run:
            log_message(f"[DryRun] Would create: {rule['rule_name']} {rule}")
            continue
        try:
            create_rule(
                rule['rule_name'], rule['direction'], rule['port'], rule['protocol'],
                rule['remote_address'], rule['action'], rule['profile']
            )
        except Exception as e:
            log_message(f"Error: {e}")

    if not args.skip_deny_default and not args.dry_run:
        deny_inbound_name = "Deny All Inbound"
        if not rule_exists(deny_inbound_name):
            create_rule(deny_inbound_name, 'Inbound', 'Any', 'Any', 'Any', 'Block', 'Any')
        deny_outbound_name = "Deny All Outbound"
        if not rule_exists(deny_outbound_name):
            create_rule(deny_outbound_name, 'Outbound', 'Any', 'Any', 'Any', 'Block', 'Any')

    log_message("Script complete.")

if __name__ == "__main__":
    main()