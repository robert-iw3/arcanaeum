# Windows Firewall Baselining and Configuration

## Overview
This guide explains how to baseline your system's network activity to generate a firewall rule CSV, refine and validate it, and apply it using provided PowerShell or Python scripts to configure a deny-by-default Windows Firewall. Requires admin privileges.

## Prerequisites
- **Scripts Needed**:
  - `baseline_monitor.ps1`: Monitors network connections and generates a CSV.
  - `firewall_config.ps1`: PowerShell script to apply firewall rules.
  - `firewall_config.py`: Python script alternative for applying rules.
- **Backup Current Rules**:
  - PowerShell: `Export-NetFirewallRule -Path backup.xml`
  - Command Prompt: `netsh advfirewall export backup.wfw`
- **Python Requirement**: Python 3.x installed for `firewall_config.py`.
- **Admin Privileges**: Run all scripts as Administrator.

## Step 1: Execute the Baseline Monitoring Script
- **Purpose**: Monitor TCP (Listen/Established) and UDP endpoints to generate a CSV of proposed firewall allow rules based on observed network activity.
- **Command** (in PowerShell, as Administrator):
  ```powershell
  .\baseline_monitor.ps1 -Duration <seconds> -Interval <seconds> -OutputCsv "baseline_rules.csv" -LogFile "monitor_log.txt"
  ```
  - **Examples**:
    - Short test (1 hour): `.\baseline_monitor.ps1 -Duration 3600 -Interval 5`
    - Long run (2 weeks): `.\baseline_monitor.ps1 -Duration 1209600 -Interval 30`
  - **For Long Runs**: Use Task Scheduler to ensure continuity:
    1. Open Task Scheduler, create a new task.
    2. Set action to `powershell.exe -File "C:\path\to\baseline_monitor.ps1" -Duration 1209600 -Interval 30 -OutputCsv "baseline_rules.csv"`.
    3. Enable "Run whether user is logged on or not" and "Wake the computer to run this task."
  - **Output**: `baseline_rules.csv` (e.g., `AUTO_TCP_OUT_443_svchost,Outbound,443,TCP,192.168.1.100,Allow,Any`) and `monitor_log.txt` for debugging.
  - **Tips**: Run during typical usage (e.g., work hours, app activity) to capture real traffic. Longer runs (e.g., 2 weeks) ensure comprehensive baselining.

## Step 2: Modify and Validate the CSV
- **Purpose**: Refine the generated CSV to ensure accuracy, security, and completeness.
- **Steps**:
  1. **Open CSV**: Use a text editor or spreadsheet (e.g., Excel) to view `baseline_rules.csv`.
  2. **Modifications**:
     - **Aggregate Addresses**: Replace specific IPs (e.g., `192.168.1.100`) with subnets (e.g., `192.168.1.0/24`) or "Any" for broader rules.
     - **Add/Remove Rules**: Delete one-time connections; add missing protocols (e.g., ICMP: `port="Any",protocol="ICMPv4"`).
     - **Set Profiles**: Adjust `profile` (Any/Domain/Private/Public) for network-specific rules.
     - **Ensure Security**: Avoid "Any" for sensitive inbound ports (e.g., 3389/RDP); use specific IPs/subnets.
  3. **Validation**:
     - Verify format: Columns must be `rule_name,direction,port,protocol,remote_address,action,profile`.
     - Check: Ports (1-65535 or "Any"), protocols (TCP/UDP/Any/ICMPv4), actions (Allow/Block), valid IPs (IPv4/IPv6).
     - Rule count: 10-100 is typical; excessive rules may need pruning.
     - Cross-check: Use `netstat -ano` or Wireshark to confirm all critical traffic is included.
- **Tip**: Save a backup of the CSV before editing.

## Step 3: Configure the Firewall Using the CSV
- **Purpose**: Apply the refined CSV to create firewall rules with a deny-by-default policy.
- **PowerShell Option**:
  - **Command**:
    ```powershell
    .\firewall_config.ps1 -CsvPath "baseline_rules.csv" -DryRun
    ```
    Then, if dry-run looks good: `.\firewall_config.ps1 -CsvPath "baseline_rules.csv"`
  - **Options**: `-SkipDenyDefault` to skip deny rules; `-MaxJobs 5` for parallelism.
- **Python Option**:
  - **Command**:
    ```bash
    python firewall_config.py --csv_path "baseline_rules.csv" --dry_run
    ```
    Then: `python firewall_config.py --csv_path "baseline_rules.csv"`
  - **Options**: `--skip_deny_default`; `--max_workers 5`.
- **Post-Apply**:
  - **Verify**: `Get-NetFirewallRule` or `netsh advfirewall firewall show rule all`.
  - **Test**: Ensure apps work; check Event Viewer (Windows Firewall logs) for blocks.
  - **Rollback**: Restore backup if needed (`Import-NetFirewallRule -Path backup.xml` or `netsh advfirewall import backup.wfw`).

## Troubleshooting
- **Script Errors**: Check `monitor_log.txt` or console output; ensure admin mode.
- **Incomplete Baseline**: Re-run monitoring during varied usage (e.g., different apps).
- **Firewall Issues**: Temporarily disable firewall for testing: `Set-NetFirewallProfile -All -Enabled False` (re-enable after).
- **Help**: See script comments or Microsoft docs for `New-NetFirewallRule`.

## Notes
- **Long Runs**: The monitoring script is optimized for 2-week runs with adaptive intervals and periodic CSV exports to manage memory.
- **CSV Compatibility**: The generated CSV matches the firewall scripts’ format. For outbound rules, firewall scripts may need modification to use `-RemotePort` (PowerShell) or `remoteport` (Python) instead of `localport`. Contact support if needed.
- **Security**: Review CSV to avoid overly permissive rules (e.g., "Any" for inbound).