# User Hardening Script

## Overview
The `user_hardening.py` script is a Python-based tool designed to apply security hardening measures to user-related configurations on Linux systems. It modifies system files to enforce stricter policies for root access, sudo, passwords, logind, login definitions, user accounts, and root locking. The script logs actions securely to `/var/log/user_hardening.log` (with rotation) and generates a JSON summary at `/var/log/user_hardening_summary.json`, using generic messages to avoid exposing sensitive data (e.g., file paths, usernames) in compliance with OWASP and CWE-532 guidelines.

## Features
- Restricts root access and masks debug-shell service.
- Configures sudo with use_pty, logging, and timeout options.
- Enforces password policies using PAM and cracklib.
- Configures systemd logind for process killing and idle actions.
- Updates login definitions for umask, password aging, and encryption.
- Locks the root account.
- Configures adduser and useradd for secure defaults and sets home directory permissions.
- Uses secure logging with generic messages to avoid leaking sensitive data.
- Supports verbose mode for detailed, sanitized output (stdout only).
- Detects container environments and logs a warning.

## Requirements
- Python 3.6+
- Linux system with root privileges
- Dependencies: `cracklib-runtime` (install via `sudo apt install cracklib-runtime`)
- Write access to `/var/log` for logging
- Files like `./config/pwquality.conf` and `./misc/passwords.list` for custom configurations (optional)

## Installation
1. Save the script as `user_hardening.py`.
2. Set appropriate permissions:
   ```bash
   sudo chmod 750 user_hardening.py
   sudo chown root:root user_hardening.py
   ```

## Usage
Run the script with root privileges:
```bash
sudo python3 user_hardening.py [options]
```

### Options
- `--verbose`: Enable verbose output (to stdout only, sanitized).

Example:
```bash
sudo python3 user_hardening.py --verbose
```

## Verification Steps
To ensure the script runs correctly, applies changes securely, and avoids exposing sensitive data (e.g., file paths, usernames), follow these steps:

### 1. Save and Prepare the Script
- Save the script as `user_hardening.py` in a secure location.
- Verify permissions:
  ```bash
  ls -l user_hardening.py
  ```
  Expected output:
  ```
  -rwxr-x--- 1 root root ... user_hardening.py
  ```

### 2. Install Dependencies
- Install required packages:
  ```bash
  sudo apt install cracklib-runtime
  ```

### 3. Run the Script
Test the script in different modes to verify functionality and output sanitization.

#### Default Mode
Run without options to check basic functionality and logging:
```bash
sudo python3 user_hardening.py
```
- Expected behavior: Applies hardening measures, logs to `/var/log/user_hardening.log`, and generates `/var/log/user_hardening_summary.json`.

#### Verbose Mode
Run with `--verbose` to verify sanitized output:
```bash
sudo python3 user_hardening.py --verbose
```
- Expected stdout output (example, no sensitive data):
  ```
  [rootaccess] Configured root access policies
  [sudo_config] Configured sudo policies
  [password] Configured password policy files
  [logindconf] Configured logind settings
  [logindefs] Configured login definitions
  [lockroot] Locked root account
  [adduser] Configured user creation settings
  Summary: Applied 22 changes.
  Detailed report written to /var/log/user_hardening.log
  JSON summary written to /var/log/user_hardening_summary.json
  Script finished.
  ```
- For failures (e.g., permission error), stdout shows sanitized stderr (e.g., `[ETC_FILE]: Permission denied`).

### 4. Check Log Files
Verify that log files contain generic messages without sensitive data.

#### Main Log File
Check `/var/log/user_hardening.log`:
```bash
sudo cat /var/log/user_hardening.log
```
- Expected entries (example, no file paths or command strings):
  ```
  [2025-08-27T12:39:00Z] INFO: Starting user hardening
  [2025-08-27T12:39:00Z] INFO: Detected container environment. Some configurations may require additional setup.
  [2025-08-27T12:39:00Z] INFO: [rootaccess] Configuring root access policies
  [2025-08-27T12:39:00Z] ERROR: Failed to mask debug-shell service
  [2025-08-27T12:39:00Z] INFO: [sudo_config] Configuring sudo policies
  [2025-08-27T12:39:00Z] ERROR: Failed to list sudo configuration
  [2025-08-27T12:39:00Z] INFO: [password] Configuring password policy files
  [2025-08-27T12:39:00Z] ERROR: Failed to update password configuration file: PermissionError
  [2025-08-27T12:39:00Z] ERROR: Failed to update cracklib dictionary
  [2025-08-27T12:39:00Z] INFO: [logindconf] Configuring logind settings
  [2025-08-27T12:39:00Z] INFO: [logindefs] Configuring login definitions
  [2025-08-27T12:39:00Z] INFO: [lockroot] Locking root account
  [2025-08-27T12:39:00Z] ERROR: Failed to check root account status
  [2025-08-27T12:39:00Z] INFO: [adduser] Configuring user creation settings
  [2025-08-27T12:39:00Z] INFO: Summary: Applied 22 changes.
  [2025-08-27T12:39:00Z] INFO: Detailed report written to /var/log/user_hardening.log
  [2025-08-27T12:39:00Z] INFO: JSON summary written to /var/log/user_hardening_summary.json
  [2025-08-27T12:39:00Z] INFO: Script finished.
  ```
- Verify permissions:
  ```bash
  ls -l /var/log/user_hardening.log
  ```
  Expected output:
  ```
  -rw------- 1 root root ... user_hardening.log
  ```

#### JSON Summary File
Check `/var/log/user_hardening_summary.json`:
```bash
sudo cat /var/log/user_hardening_summary.json
```
- Expected content (example, action descriptions include file paths as they are secure in a `0o600` file):
  ```
  {
      "timestamp": "2025-08-27T12:39:00Z",
      "changes_made": [
          "Updated /etc/security/access.conf for root localhost access",
          "Set /etc/securetty to console only",
          "Masked debug-shell.service",
          "Stopped debug-shell.service",
          "Reloaded systemd daemon",
          "Created /etc/sudoers.d/011_use_pty",
          "Created /etc/sudoers.d/012_logfile",
          "Created /etc/sudoers.d/013_pwfeedback",
          "Created /etc/sudoers.d/014_visiblepw",
          "Created /etc/sudoers.d/015_passwdtimeout",
          "Created /etc/sudoers.d/016_timestamptimeout",
          "Set permissions on /etc/sudoers.d/* to 0440",
          "Added pam_wheel.so to /etc/pam.d/su",
          "Added pam_pwhistory.so to common-password",
          "Added pam_pwquality.so to common-password",
          "Updated /etc/security/pwquality.conf",
          "Removed nullok/nullok_secure from common-auth",
          "Configured faillock in /etc/security/faillock.conf",
          "Added pam_faillock.so to common-auth",
          "Added pam_faillock.so to common-account",
          "Updated pam_lastlog.so and delay in pam.d/login",
          "Updated cracklib dictionary",
          "Updated /etc/systemd/logind.conf",
          "Reloaded systemd daemon",
          "Updated /etc/login.defs",
          "Locked root account",
          "Updated /etc/adduser.conf",
          "Updated /etc/default/useradd",
          "Set permissions on user home directory"
      ]
  }
  ```
- Verify permissions:
  ```bash
  ls -l /var/log/user_hardening_summary.json
  ```
  Expected output:
  ```
  -rw------- 1 root root ... user_hardening_summary.json
  ```

### 5. Verify Security Compliance
Ensure no sensitive data (file paths, usernames, command strings, stderr) is logged or printed:
- **Log Files**: Confirm `/var/log/user_hardening.log` contains only generic messages (e.g., `"Failed to update password configuration file"`) without file paths or command details.
- **JSON Summary**: Verify `/var/log/user_hardening_summary.json` lists completed actions with file paths (acceptable in a `0o600` file for audit purposes).
- **Verbose Output**: Confirm stdout in verbose mode shows sanitized stderr (e.g., `[ETC_FILE]: Permission denied`) via `run_command`, avoiding file paths or commands.
- **Container Warning**: Verify a container warning is logged if running in a container:
  ```bash
  sudo cat /var/log/user_hardening.log | grep "container environment"
  ```
  Expected: `[2025-08-27T12:39:00Z] INFO: Detected container environment...`

### 6. Test Edge Cases
- **Permission Errors**: Simulate a file permission error (e.g., `sudo chmod 000 /etc/pam.d/common-password`) and run:
  ```bash
  sudo python3 user_hardening.py --verbose
  ```
  Verify logs show generic errors (e.g., `"Failed to update password configuration file: PermissionError"`) and stdout shows sanitized stderr (e.g., `[ETC_FILE]: Permission denied`).
- **Successful Run**: Run on a clean system and verify logs and JSON contain only generic messages (except JSON action descriptions).
- **Verbose Stdout Capture**: Avoid capturing stdout in production; test in a safe environment to confirm no sensitive data.

## Security Notes
- **Log Security**: Logs and JSON files are stored with `0o600` permissions (root-only) to minimize unauthorized access.
- **Sanitized Output**: All log messages use generic descriptions (e.g., `"Configuring password policy files"`) to prevent exposing file paths or sensitive data. Verbose output sanitizes stderr (e.g., `[ETC_FILE]` for `/etc/*`).
- **Verbose Output**: Outputs to stdout only (ephemeral), reducing persistence risks.
- **Container Detection**: Logs a warning in container environments to alert about potential log exposure.
- **Root Privileges**: Requires root and exits if not run as such, preventing unauthorized execution.

## Troubleshooting
- **Permission Errors**: Ensure the script runs as root. Verify `/var/log` is writable (`sudo chmod 750 /var/log`).
- **Dependency Missing**: Install `cracklib-runtime` if password configuration errors occur.
- **No Changes Applied**: The script may report no changes if the system is already hardened; review the JSON summary.
- **Verbose Output**: If output contains unexpected data, ensure the script matches the provided version with sanitization fixes.

## License
MIT License