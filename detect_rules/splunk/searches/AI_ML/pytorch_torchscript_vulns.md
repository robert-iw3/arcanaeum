### PyTorch TorchScript Engine Vulnerabilities
---

This report details critical vulnerabilities within the PyTorch TorchScript engine, specifically focusing on how malicious actors can achieve Remote Code Execution (RCE) by exploiting insecure deserialization practices. The core issue revolves around the torch.load function and its interaction with Python's pickle module, as well as the potential for abuse of TorchScript operators.

Recent intelligence highlights a bypass for the weights_only=True mitigation in torch.load, demonstrating that even with this security measure enabled, RCE is still possible in PyTorch versions prior to 2.6.0. This is significant because weights_only=True was previously considered a secure method for loading models, but new research shows it can be circumvented by manipulating TorchScript's internal function calls.

### Actionable Threat Data
---

Monitor for torch.load calls in PyTorch applications, especially those loading models from untrusted sources, and ensure PyTorch is updated to version 2.6.0 or later.

Implement strict validation and sandboxing for any PyTorch models loaded from external or untrusted origins to prevent arbitrary code execution during deserialization.

Prioritize the use of safer serialization formats like safetensors over pickle for PyTorch models, as safetensors is designed to mitigate arbitrary code execution risks.

Scan and flag PyTorch models that contain suspicious TorchScript operators, particularly those related to file system operations (aten::save, aten::from_file) or system command execution.

Enforce the use of weights_only=True in torch.load as a baseline security measure, but recognize its limitations and combine it with other defenses like environment isolation and input validation.

### Query
---

This query searches for three distinct patterns in your endpoint data:


    A Python process loading a model from a potentially untrusted directory.

    A Python process creating a suspicious child process (like a shell or network tool).

    A Python process writing to a sensitive file commonly used for persistence.

```sql
((index=*) (tag=process OR tag=endpoint))
-- This SPL query combines three detection patterns related to PyTorch exploitation (e.g., CVE-2025-32434).

-- Pattern 1: Detects a Python process loading a model from an untrusted path.
( (process_name IN ("python","python3","python.exe")) AND (process LIKE "%.pt%" OR process LIKE "%.pth%" OR process LIKE "%.bin%") AND (process LIKE "%/tmp/%" OR process LIKE "%/var/tmp/%" OR process LIKE "%/dev/shm/%" OR process LIKE "%/mnt/%" OR process LIKE "%Downloads%" OR process LIKE "%C:\\Windows\\Temp\\%" OR process LIKE "%\\AppData\\Local\\Temp%"))

OR

-- Pattern 2: Detects a Python process spawning a suspicious child process (shell, network tool, etc.).
( (parent_process_name IN ("python","python3","python.exe")) AND (process_name IN ("sh", "bash", "dash", "ksh", "zsh", "tcsh", "csh", "nc", "ncat", "netcat", "wget", "curl", "powershell.exe", "pwsh.exe") OR process LIKE "% -c %") )

OR

-- Pattern 3: Detects a Python process writing to a sensitive file used for persistence.
( (parent_process_name IN ("python","python3","python.exe")) AND (file_name IN ("authorized_keys", ".bashrc", ".zshrc", ".profile", "crontab") OR file_path IN ("*/.ssh/*", "*/etc/cron*", "*/var/spool/cron*")) )

-- Use a case statement to categorize the matched event and provide a clear description.
| eval threat_description=case(
    (process LIKE "%.pt%" OR process LIKE "%.pth%" OR process LIKE "%.bin%"), "PyTorch Model Loaded from Untrusted Location",
    (process_name IN ("sh", "bash", "dash", "ksh", "zsh", "tcsh", "csh", "nc", "ncat", "netcat", "wget", "curl", "powershell.exe", "pwsh.exe") OR process LIKE "% -c %"), "Suspicious Child Process Spawned by Python",
    (file_name IN ("authorized_keys", ".bashrc", ".zshrc", ".profile", "crontab") OR file_path IN ("*/.ssh/*", "*/etc/cron*", "*/var/spool/cron*")), "Python Wrote to Sensitive File"
  )
-- Format the results for easy analysis.
| table _time, host, user, threat_description, process_name, process, parent_process_name, file_name, file_path
| sort -_time
```