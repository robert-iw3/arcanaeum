### NOVABLIGHT Infostealer Report
---

NOVABLIGHT is a NodeJS-based information stealer offered as Malware-as-a-Service (MaaS) by the Sordeal Group, primarily used for credential theft and cryptocurrency wallet compromise. It employs sophisticated obfuscation and anti-analysis techniques, making detection challenging, and is distributed through deceptive means like fake video game installers.

Recent intelligence indicates NOVABLIGHT continues to be actively developed and distributed, with its operators leveraging Telegram and Discord for sales and support, and promoting it as an "educational tool" despite its clear malicious intent. The malware's ongoing evolution includes new methods for system sabotage, such as disabling Windows Defender, Task Manager, and internet connectivity, and removing administrative rights, making it a persistent and adaptable threat.

### Actionable Threat Data
---

Monitor for the execution of `netsh` commands to disable network adapters or `reagentc /disable` and `vssadmin delete shadows /all` for system recovery sabotage.

Detect attempts to modify the registry key `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr` to disable Task Manager.

Look for PowerShell commands querying `root/SecurityCenter2` for antivirus details (`Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct`).

Identify suspicious network connections to known NOVABLIGHT C2 domains such as `api.nova-blight[.]top`, `shadow.nova-blight[.]top`, `nova-blight[.]site`, `nova-blight[.]xyz`, and `bamboulacity.nova-blight[.]xyz`.

Monitor for the download and execution of batch scripts (e.g., `DisableWD.bat`) from public GitHub repositories, particularly those attempting to disable security features.

Implement detection for the creation of files named `System Info.txt`, `TaskManagerInfo.txt`, `Avdetails.txt`, `Clipboard.txt`, `WifiPasswords.txt`, and `Bighead.avi` in unusual directories.

Look for processes attempting to capture screenshots using libraries like `screenshot-desktop` or video using `direct-synch-show`.

Detect the execution of `tasklist /FO CSV /NH` for process enumeration.

Monitor for `netsh wlan show profile *wifi_ssid* key=clear` commands to exfiltrate Wi-Fi passwords.

Identify attempts to inject malicious code into Electron-based applications like Discord, Exodus, and Mullvad VPN, especially those involving unpacking and repacking ASAR files.

Look for downloads of `bin.zip` from GitHub repositories like `https://github.com/Hyutop/pandakmc-auto-vote/blob/main/bin.zip`, which may contain Chrome data decryption tools.

### System Sabotage via Netsh/Reagentc/Vssadmin
---
```sql
FROM *
WHERE host.os.type == "windows"
AND (
    (process.name == "vssadmin.exe" AND process.command_line ILIKE "*delete*shadows*/all*")
    OR
    (process.name == "reagentc.exe" AND process.command_line ILIKE "*disable*")
    OR
    (process.name == "netsh.exe" AND process.command_line ILIKE "*set*interface*admin=disable*")
)
| EVAL host = host.hostname, user = user.name, parent_process = process.parent.name, process_name = process.name
| STATS count = COUNT(*), command_lines = ARRAY_AGG(process.command_line)
  BY host, user, parent_process, process_name
```

### Registry Modification for TaskMgr
---
```sql
FROM *
WHERE host.os.type == "windows"
AND registry.path ILIKE "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskMgr"
AND registry.data.strings == "1"
| EVAL host = host.hostname, user = user.name, parent_process = process.parent.name
| STATS count = COUNT(*), process_path = ARRAY_AGG(process.executable), registry_path = ARRAY_AGG(registry.path)
  BY host, user, parent_process
```

### Antivirus Product Discovery via PowerShell
---
```sql
FROM *
WHERE host.os.type == "windows"
AND process.name IN ("powershell.exe", "pwsh.exe")
AND process.command_line ILIKE "*root/SecurityCenter2*"
AND process.command_line ILIKE "*AntiVirusProduct*"
| EVAL host = host.hostname, user = user.name, parent_process = process.parent.name
| STATS count = COUNT(*), command_line = ARRAY_AGG(process.command_line)
  BY host, user, parent_process
```

### NOVABLIGHT C2 Domain Connections
---
```sql
FROM *
WHERE host.os.type == "windows"
AND destination.domain IN (
  "api.nova-blight.top",
  "shadow.nova-blight.top",
  "nova-blight.site",
  "nova-blight.xyz",
  "bamboulacity.nova-blight.xyz"
)
| EVAL src_ip = source.ip, dest_domain = destination.domain, user = user.name, process_name = process.name
| STATS count = COUNT(*), dest_port = ARRAY_AGG(destination.port)
  BY src_ip, dest_domain, user, process_name
```

### Batch Script Execution from GitHub
---
```sql
FROM *
WHERE host.os.type == "windows"
AND process.name IN ("curl.exe", "wget.exe", "bitsadmin.exe", "powershell.exe", "pwsh.exe")
AND process.command_line ILIKE "*github.com*"
OR process.command_line ILIKE "*raw.githubusercontent.com*"
AND (process.command_line ILIKE "*.bat*" OR process.command_line ILIKE "*.cmd*")
| EVAL host = host.hostname, user = user.name, parent_process = process.parent.name
| STATS count = COUNT(*), command_line = ARRAY_AGG(process.command_line)
  BY host, user, parent_process
```

### Suspicious File Creation by Infostealer
---
```sql
FROM *
WHERE host.os.type == "windows"
AND file.name IN (
  "System Info.txt",
  "TaskManagerInfo.txt",
  "Avdetails.txt",
  "Clipboard.txt",
  "WifiPasswords.txt",
  "Bighead.avi"
)
| EVAL host = host.hostname, user = user.name, creating_process = process.name
| STATS count = COUNT(*), file_paths = ARRAY_AGG(file.path), file_names = ARRAY_AGG(file.name)
  BY host, user, creating_process
```

### Process Enumeration via Tasklist
---
```sql
FROM *
WHERE host.os.type == "windows"
AND process.name == "tasklist.exe"
AND process.command_line ILIKE "* /FO CSV*"
AND process.command_line ILIKE "* /NH*"
| EVAL host = host.hostname, user = user.name, parent_process = process.parent.name
| STATS count = COUNT(*), command_line = ARRAY_AGG(process.command_line)
  BY host, user, parent_process
```

### Wi-Fi Password Exfiltration
---
```sql
FROM *
WHERE host.os.type == "windows"
AND process.name == "netsh.exe"
AND process.command_line ILIKE "*wlan*"
AND process.command_line ILIKE "*show*"
AND process.command_line ILIKE "*profile*"
AND process.command_line ILIKE "*key=clear*"
| EVAL host = host.hostname, user = user.name, parent_process = process.parent.name
| STATS count = COUNT(*), command_lines = ARRAY_AGG(process.command_line)
  BY host, user, parent_process
```

### Electron Application Injection
---
```sql
FROM *
WHERE host.os.type == "windows"
AND process.command_line ILIKE "*asar*"
AND process.command_line ILIKE "*app.asar*"
AND (process.command_line ILIKE "*extract*" OR process.command_line ILIKE "*pack*")
| EVAL host = host.hostname, user = user.name, parent_process = process.parent.name, process_name = process.name
| STATS count = COUNT(*), command_lines = ARRAY_AGG(process.command_line)
  BY host, user, parent_process, process_name
```

### Chrome Data Decryption Tool Download
---
```sql
FROM *
WHERE host.os.type == "windows"
AND (url.full ILIKE "*github.com/*/bin.zip" OR url.full ILIKE "*raw.githubusercontent.com/*/bin.zip")
| EVAL src_ip = source.ip, user = user.name, process_name = process.name
| STATS count = COUNT(*), urls = ARRAY_AGG(url.full)
  BY src_ip, user, process_name
```