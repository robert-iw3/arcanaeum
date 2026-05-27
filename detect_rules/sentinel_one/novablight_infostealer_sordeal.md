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
EndpointOS = "Windows"
AND (
    (ProcessName = "vssadmin.exe" AND ProcessCmd LIKE "%delete%shadows%/all%")
    OR
    (ProcessName = "reagentc.exe" AND ProcessCmd LIKE "%disable%")
    OR
    (ProcessName = "netsh.exe" AND ProcessCmd LIKE "%set%interface%admin=disable%")
)
| GROUP BY AgentName, User, ParentProcessName, ProcessName
| SELECT AgentName AS host, User AS user, ParentProcessName AS parent_process, ProcessName AS process_name, COUNT(*) AS count, ARRAY_AGG(ProcessCmd) AS command_lines
```

### Registry Modification for TaskMgr
---
```sql
EndpointOS = "Windows" AND EventType = "Registry Modification"
AND RegistryPath LIKE "%\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskMgr"
AND RegistryValueData = "1"
| GROUP BY AgentName, User, ParentProcessName
| SELECT AgentName AS host, User AS user, ParentProcessName AS parent_process, COUNT(*) AS count, ARRAY_AGG(ProcessPath) AS process_path, ARRAY_AGG(RegistryPath) AS registry_path
```

### Antivirus Product Discovery via PowerShell
---
```sql
EndpointOS = "Windows"
AND ProcessName IN ("powershell.exe", "pwsh.exe")
AND ProcessCmd LIKE "%root/SecurityCenter2%"
AND ProcessCmd LIKE "%AntiVirusProduct%"
| GROUP BY AgentName, User, ParentProcessName
| SELECT AgentName AS host, User AS user, ParentProcessName AS parent_process, COUNT(*) AS count, ARRAY_AGG(ProcessCmd) AS command_line
```

### NOVABLIGHT C2 Domain Connections
---
```sql
EndpointOS = "Windows" AND EventType = "Network Connection"
AND DstDomain IN (
  "api.nova-blight.top",
  "shadow.nova-blight.top",
  "nova-blight.site",
  "nova-blight.xyz",
  "bamboulacity.nova-blight.xyz"
)
| GROUP BY SrcIP, DstDomain, User, ProcessName
| SELECT SrcIP AS src_ip, DstDomain AS dest_domain, User AS user, ProcessName AS process_name, COUNT(*) AS count, ARRAY_AGG(DstPort) AS dest_port
```

### Batch Script Execution from GitHub
---
```sql
EndpointOS = "Windows"
AND ProcessName IN ("curl.exe", "wget.exe", "bitsadmin.exe", "powershell.exe", "pwsh.exe")
AND (ProcessCmd LIKE "%github.com%" OR ProcessCmd LIKE "%raw.githubusercontent.com%")
AND (ProcessCmd LIKE "%.bat%" OR ProcessCmd LIKE "%.cmd%")
| GROUP BY AgentName, User, ParentProcessName
| SELECT AgentName AS host, User AS user, ParentProcessName AS parent_process, COUNT(*) AS count, ARRAY_AGG(ProcessCmd) AS command_line
```

### Suspicious File Creation by Infostealer
---
```sql
EndpointOS = "Windows" AND EventType = "File Creation"
AND FileName IN (
  "System Info.txt",
  "TaskManagerInfo.txt",
  "Avdetails.txt",
  "Clipboard.txt",
  "WifiPasswords.txt",
  "Bighead.avi"
)
| GROUP BY AgentName, User, ProcessName
| SELECT AgentName AS host, User AS user, ProcessName AS creating_process, COUNT(*) AS count, ARRAY_AGG(FilePath) AS file_paths, ARRAY_AGG(FileName) AS file_names
```

### Process Enumeration via Tasklist
---
```sql
EndpointOS = "Windows"
AND ProcessName = "tasklist.exe"
AND ProcessCmd LIKE "%/FO CSV%"
AND ProcessCmd LIKE "%/NH%"
| GROUP BY AgentName, User, ParentProcessName
| SELECT AgentName AS host, User AS user, ParentProcessName AS parent_process, COUNT(*) AS count, ARRAY_AGG(ProcessCmd) AS command_line
```

### Wi-Fi Password Exfiltration
---
```sql
EndpointOS = "Windows"
AND ProcessName = "netsh.exe"
AND ProcessCmd LIKE "%wlan%"
AND ProcessCmd LIKE "%show%"
AND ProcessCmd LIKE "%profile%"
AND ProcessCmd LIKE "%key=clear%"
| GROUP BY AgentName, User, ParentProcessName
| SELECT AgentName AS host, User AS user, ParentProcessName AS parent_process, COUNT(*) AS count, ARRAY_AGG(ProcessCmd) AS command_lines
```

### Electron Application Injection
---
```sql
EndpointOS = "Windows"
AND ProcessCmd LIKE "%asar%"
AND ProcessCmd LIKE "%app.asar%"
AND (ProcessCmd LIKE "%extract%" OR ProcessCmd LIKE "%pack%")
| GROUP BY AgentName, User, ParentProcessName, ProcessName
| SELECT AgentName AS host, User AS user, ParentProcessName AS parent_process, ProcessName AS process_name, COUNT(*) AS count, ARRAY_AGG(ProcessCmd) AS command_lines
```

### Chrome Data Decryption Tool Download
---
```sql
EndpointOS = "Windows" AND EventType = "Network Connection"
AND (NetworkUrl LIKE "%github.com/%/bin.zip" OR NetworkUrl LIKE "%raw.githubusercontent.com/%/bin.zip")
| GROUP BY SrcIP, User, ProcessName
| SELECT SrcIP AS src_ip, User AS user, ProcessName AS process_name, COUNT(*) AS count, ARRAY_AGG(NetworkUrl) AS urls
```