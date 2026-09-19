# SSH Key Audit Script

## Overview
The `ssh_key_audit_v2.py` script audits SSH keys in user home directories, checking for private keys, duplicate keys, excessive keys, recently modified keys, key options, and deprecated `authorized_keys2` files. It logs securely to `/var/log/ssh_key_audit.log` and optionally `/var/log/ssh_key_audit.json`, using generic messages (no paths/usernames) to comply with OWASP and CWE-532.

## Usage
Run with root privileges:
```bash
sudo python3 ssh_key_audit_v2.py --verbose --json --key-count 5 --seconds 3600
```

### Options
- `--verbose`: Show sanitized command output (stdout only, e.g., `[HOME]/.ssh/*`).
- `--json`: Enable JSON logging to `/var/log/ssh_key_audit.json`.
- `--key-count <count>`: Max allowed keys (default: 10).
- `--seconds <seconds>`: Modification time limit in seconds (default: 86400).

## Verification Steps
Ensure the script runs correctly and logs/output are sanitized:

1. **Prepare the Script**:
   - Save as `ssh_key_audit_v2.py`.
   - Set permissions:
     ```bash
     sudo chmod 750 ssh_key_audit_v2.py
     sudo chown root:root ssh_key_audit_v2.py
     ```
   - Verify:
     ```bash
     ls -l ssh_key_audit_v2.py
     ```
     Expected: `-rwxr-x--- 1 root root ...`

2. **Run the Script**:
   - Default mode:
     ```bash
     sudo python3 ssh_key_audit_v2.py
     ```
   - Verbose mode (check sanitized output):
     ```bash
     sudo python3 ssh_key_audit_v2.py --verbose
     ```
     Expected stdout (no paths):
     ```
     Command: grep -l 'PRIVATE KEY' [HOME]/.ssh/*
     Output: Private key detected
     Command: sort [HOME]/.ssh/authorized_keys | uniq -c
     Output: 2 duplicate(s) detected
     ```
   - JSON mode:
     ```bash
     sudo python3 ssh_key_audit_v2.py --json
     ```

3. **Check Logs**:
   - Main log:
     ```bash
     sudo tail -f /var/log/ssh_key_audit.log
     ```
     Expected (no paths):
     ```
     [2025-08-27T12:05:00Z] FAIL: Private key found in user SSH directory
     [2025-08-27T12:05:00Z] FAIL: User authorized_keys has 5 keys (exceeds 5)
     ```
   - JSON log:
     ```bash
     sudo tail -f /var/log/ssh_key_audit.json | jq
     ```
     Expected:
     ```
     {"timestamp": "2025-08-27T12:05:00Z", "status": "FAIL", "message": "Private key found in user SSH directory"}
     ```
   - Verify permissions:
     ```bash
     ls -l /var/log/ssh_key_audit.*
     ```
     Expected: `-rw------- 1 root root ...`

4. **Docker/Podman**:
   - Build:
     ```bash
     podman build -t ssh-key-audit .
     ```
   - Run:
     ```bash
     podman run --rm --cap-add DAC_READ_SEARCH -v /etc/passwd:/etc/passwd:ro -v /home:/home:ro -v /var/log:/var/log ssh-key-audit
     ```
   - Verify container warning:
     ```bash
     sudo cat /var/log/ssh_key_audit.log
     ```
     Expected: `[2025-08-27T12:05:00Z] WARNING: Running in a container environment...`

5. **Kubernetes**:
   - Apply:
     ```bash
     kubectl apply -f ssh_key_audit.yaml
     ```
   - Check logs:
     ```bash
     kubectl logs -l app=ssh-key-audit
     ```
   - Verify container warning and sanitized logs (same as above). Note: Logs are ephemeral due to `emptyDir` for `/var/log`.

## Security Notes
- Logs use generic messages (e.g., "Private key found in user SSH directory").
- Log files have `0o600` permissions (root-only).
- Verbose output uses static placeholders (e.g., `[HOME]/.ssh/*`), stdout-only.
- Avoid capturing stdout in insecure environments.
- Container runs log a warning about potential log exposure.

## Troubleshooting
- **Permission Errors**: Ensure root or `CAP_DAC_READ_SEARCH`.
- **Missing Dependencies**: Install `awk`, `grep`, `sort`, `uniq`, `stat`.
- **Log Access**: Ensure `/var/log` is writable (`sudo chmod 750 /var/log`).
- **Kubernetes Logs**: Use `kubectl logs` for ephemeral logs; consider persistent storage if needed.