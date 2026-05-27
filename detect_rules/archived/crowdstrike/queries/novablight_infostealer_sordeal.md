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
event_platform=Win
| (
    (process_name="vssadmin.exe" AND cmdline~/.*delete.*shadows.*\/all.*/i)
    OR
    (process_name="reagentc.exe" AND cmdline~/.*disable.*/i)
    OR
    (process_name="netsh.exe" AND cmdline~/.*set.*interface.*admin=disable.*/i)
)
| group by ComputerName, UserName, ParentBaseFileName, BaseFileName
| project ComputerName as host, UserName as user, ParentBaseFileName as parent_process, BaseFileName as process_name, count() as count, collect(cmdline) as command_lines
```

### Registry Modification for TaskMgr
---
```sql
event_platform=Win event_simpleName=RegKeyModified
| RegistryKey~"*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskMgr" AND RegistryValueData="1"
| group by ComputerName, UserName, ParentBaseFileName
| project ComputerName as host, UserName as user, ParentBaseFileName as parent_process, count() as count, collect(FileName) as process_path, collect(RegistryKey) as registry_path
```

### Antivirus Product Discovery via PowerShell
---
```sql
event_platform=Win
| (process_name IN ("powershell.exe", "pwsh.exe") AND cmdline~/.*root\/SecurityCenter2.*/i AND cmdline~/.*AntiVirusProduct.*/i)
| group by ComputerName, UserName, ParentBaseFileName
| project ComputerName as host, UserName as user, ParentBaseFileName as parent_process, count() as count, collect(cmdline) as command_line
```

### NOVABLIGHT C2 Domain Connections
---
```sql
event_platform=Win event_simpleName=NetworkConnectIP4
| RemoteAddress IN ("api.nova-blight.top", "shadow.nova-blight.top", "nova-blight.site", "nova-blight.xyz", "bamboulacity.nova-blight.xyz")
| group by LocalAddress, RemoteAddress, UserName, BaseFileName
| project LocalAddress as src_ip, RemoteAddress as dest_domain, UserName as user, BaseFileName as process_name, count() as count, collect(RemotePort) as dest_port
```

### Batch Script Execution from GitHub
---
```sql
event_platform=Win
| process_name IN ("curl.exe", "wget.exe", "bitsadmin.exe", "powershell.exe", "pwsh.exe")
  AND cmdline~/.*(github\.com|raw\.githubusercontent\.com).*/i
  AND cmdline~/.*\.(bat|cmd).*/i
| group by ComputerName, UserName, ParentBaseFileName
| project ComputerName as host, UserName as user, ParentBaseFileName as parent_process, count() as count, collect(cmdline) as command_line
```

### Suspicious File Creation by Infostealer
---
```sql
event_platform=Win event_simpleName=FileCreate
| FileName IN ("System Info.txt", "TaskManagerInfo.txt", "Avdetails.txt", "Clipboard.txt", "WifiPasswords.txt", "Bighead.avi")
| group by ComputerName, UserName, BaseFileName
| project ComputerName as host, UserName as user, BaseFileName as creating_process, count() as count, collect(FilePath) as file_paths, collect(FileName) as file_names
```

### Process Enumeration via Tasklist
---
```sql
event_platform=Win
| process_name="tasklist.exe" AND cmdline~/.*\/FO\s+CSV.*/i AND cmdline~/.*\/NH.*/i
| group by ComputerName, UserName, ParentBaseFileName
| project ComputerName as host, UserName as user, ParentBaseFileName as parent_process, count() as count, collect(cmdline) as command_line
```

### Wi-Fi Password Exfiltration
---
```sql
event_platform=Win
| process_name="netsh.exe" AND cmdline~/.*wlan.*/i AND cmdline~/.*show.*/i AND cmdline~/.*profile.*/i AND cmdline~/.*key=clear.*/i
| group by ComputerName, UserName, ParentBaseFileName
| project ComputerName as host, UserName as user, ParentBaseFileName as parent_process, count() as count, collect(cmdline) as command_lines
```

### Electron Application Injection
---
```sql
event_platform=Win
| cmdline~/.*asar.*/i AND cmdline~/.*app\.asar.*/i AND cmdline~/.*(extract|pack).*/i
| group by ComputerName, UserName, ParentBaseFileName, BaseFileName
| project ComputerName as host, UserName as user, ParentBaseFileName as parent_process, BaseFileName as process_name, count() as count, collect(cmdline) as command_lines
```

### Chrome Data Decryption Tool Download
---
```sql
event_platform=Win event_simpleName=NetworkConnectIP4
| URL~/.*(github\.com|raw\.githubusercontent\.com)\/.*bin\.zip/i
| group by LocalAddress, UserName, BaseFileName
| project LocalAddress as src_ip, UserName as user, BaseFileName as process_name, count() as count, collect(URL) as urls
```