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
`comment("This rule detects system sabotage techniques used by malware like NOVABLIGHT to inhibit system recovery and network access, as described in the associated intelligence.")`
from datamodel=Endpoint.Processes
where (
    `comment("Looks for deletion of all volume shadow copies, a common anti-recovery technique (T1490).")`
    (Processes.process_name="vssadmin.exe" AND Processes.process="*delete*shadows*/all*")
    OR
    `comment("Looks for disabling of the Windows Recovery Environment (T1490).")`
    (Processes.process_name="reagentc.exe" AND Processes.process="*disable*")
    OR
    `comment("Looks for network adapters being disabled via netsh. This may require tuning to filter legitimate administrative activity.")`
    (Processes.process_name="netsh.exe" AND Processes.process="* set *interface *admin=disable*")
)
`comment("Group results by host, user, and parent process to provide context for the activity.")`
| stats
    count
    values(Processes.process) as command_lines
    by
    Processes.dest
    Processes.user
    Processes.parent_process_name
    Processes.process_name
| rename
    Processes.dest as host,
    Processes.user as user,
    Processes.parent_process_name as parent_process,
    Processes.process_name as process_name
```

### Registry Modification for TaskMgr
---
```sql
`comment("This rule detects attempts to disable the Task Manager by modifying the registry, a technique used by malware like NOVABLIGHT to prevent users from terminating malicious processes (T1562.001).")`
from datamodel=Endpoint.Registry
where
    `comment("Looks for the specific registry key path and value data that disables the Task Manager.")`
    Registry.registry_path = "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskMgr"
    AND Registry.registry_value_data = "1"
`comment("This activity can be performed by legitimate administrators or Group Policy. Review the user and parent_process to determine if the activity is malicious. Consider adding known administrative tools or users to an exclusion list.")`
| stats
    count
    values(Registry.process_path) as process_path
    values(Registry.registry_path) as registry_path
    by
    Registry.dest
    Registry.user
    Registry.parent_process_name
| rename
    Registry.dest as host,
    Registry.user as user,
    Registry.parent_process_name as parent_process
```

### Antivirus Product Discovery via PowerShell
---
```sql
`comment("This rule detects attempts to discover installed antivirus products using PowerShell, a technique used by malware like NOVABLIGHT to evade defenses (T1518.001).")`
from datamodel=Endpoint.Processes
where
    `comment("Looks for PowerShell processes executing commands to query the SecurityCenter2 WMI namespace for AntiVirusProduct information.")`
    (Processes.process_name = "powershell.exe" OR Processes.process_name = "pwsh.exe")
    AND Processes.process = "*root/SecurityCenter2*"
    AND Processes.process = "*AntiVirusProduct*"
`comment("This activity may be performed by legitimate security tools or administrators. Review the user and parent_process to determine if the activity is malicious. Consider adding known administrative tools or users to an exclusion list.")`
| stats
    count
    values(Processes.process) as command_line
    by
    Processes.dest
    Processes.user
    Processes.parent_process_name
| rename
    Processes.dest as host,
    Processes.user as user,
    Processes.parent_process_name as parent_process
```

### NOVABLIGHT C2 Domain Connections
---
```sql
`comment("This rule detects network traffic to known Command and Control (C2) domains associated with the NOVABLIGHT infostealer, indicating a potential infection (T1071.001).")`
from datamodel=Network_Traffic
where
    `comment("Looks for connections to domains identified as NOVABLIGHT C2 infrastructure.")`
    All_Traffic.dest IN (
        "api.nova-blight.top",
        "shadow.nova-blight.top",
        "nova-blight.site",
        "nova-blight.xyz",
        "bamboulacity.nova-blight.xyz"
    )
`comment("This is an IOC-based detection; false positives are unlikely unless the domains have been sinkholed or repurposed. Investigate the source system for further signs of compromise.")`
| stats
    count
    values(All_Traffic.dest_port) as dest_port
    by
    All_Traffic.src
    All_Traffic.dest
    All_Traffic.user
    All_Traffic.process_name
| rename
    All_Traffic.src as src_ip,
    All_Traffic.dest as dest_domain,
    All_Traffic.user as user,
    All_Traffic.process_name as process_name
```

### Batch Script Execution from GitHub
---
```sql
`comment("This rule detects the download of a Windows batch script from a public code repository like GitHub, a technique used by threats like NOVABLIGHT to fetch and execute malicious code (T1105, T1059.003).")`
from datamodel=Endpoint.Processes
where
    `comment("Looks for common command-line tools used for downloading files.")`
    Processes.process_name IN ("curl.exe", "wget.exe", "bitsadmin.exe", "powershell.exe", "pwsh.exe")
    AND
    `comment("Identifies command lines that reference a batch file (.bat, .cmd) on a GitHub domain.")`
    (
        (Processes.process LIKE "%github.com%" OR Processes.process LIKE "%raw.githubusercontent.com%")
        AND
        (Processes.process LIKE "%.bat%" OR Processes.process LIKE "%.cmd%")
    )
`comment("This behavior may be legitimate for developers or system administrators. Review the user, host, and full command line to assess legitimacy. Consider excluding known developer systems or administrative scripts if noise occurs.")`
| stats
    count
    values(Processes.process) as command_line
    by
    Processes.dest
    Processes.user
    Processes.parent_process_name
| rename
    Processes.dest as host,
    Processes.user as user,
    Processes.parent_process_name as parent_process
```

### Suspicious File Creation by Infostealer
---
```sql
`comment("This rule detects the creation of specific files used by the NOVABLIGHT infostealer to stage collected data before exfiltration (T1005, T1056.001, T1113, T1123).")`
from datamodel=Endpoint.Filesystem
where
    `comment("Looks for specific file names known to be created by NOVABLIGHT for data staging.")`
    Filesystem.file_name IN (
        "System Info.txt",
        "TaskManagerInfo.txt",
        "Avdetails.txt",
        "Clipboard.txt",
        "WifiPasswords.txt",
        "Bighead.avi"
    )
`comment("This activity may be legitimate if tools with similar output names are used. Review the creating process and file path to assess legitimacy. The creation of multiple of these files on a single host is a strong indicator of compromise.")`
| stats
    count
    values(Filesystem.file_path) as file_paths
    values(Filesystem.file_name) as file_names
    by
    Filesystem.dest
    Filesystem.user
    Filesystem.process_name
| rename
    Filesystem.dest as host,
    Filesystem.user as user,
    Filesystem.process_name as creating_process
```

### Process Enumeration via Tasklist
---
```sql
`comment("This rule detects process enumeration using 'tasklist' with specific arguments, a technique used by malware like NOVABLIGHT to gather information about running processes for situational awareness (T1057).")`
from datamodel=Endpoint.Processes
where
    `comment("Looks for the execution of tasklist.exe with arguments for script-friendly, non-headered CSV output, as seen with NOVABLIGHT.")`
    Processes.process_name = "tasklist.exe"
    AND Processes.process = "* /FO CSV*"
    AND Processes.process = "* /NH*"
`comment("This command can be used by legitimate scripts or administrators. Review the parent process and user context to determine if the activity is malicious. High-frequency execution or execution from unusual parent processes (e.g., Word, Excel) increases suspicion.")`
| stats
    count
    values(Processes.process) as command_line
    by
    Processes.dest
    Processes.user
    Processes.parent_process_name
| rename
    Processes.dest as host,
    Processes.user as user,
    Processes.parent_process_name as parent_process
```

### Wi-Fi Password Exfiltration
---
```sql
`comment("This rule detects the use of netsh to export saved Wi-Fi profiles with cleartext passwords, a technique used by malware like NOVABLIGHT to steal credentials for lateral movement (T1552.001, T1555).")`
from datamodel=Endpoint.Processes
where
    `comment("Looks for the execution of netsh.exe with specific arguments to show Wi-Fi profile keys in cleartext.")`
    Processes.process_name = "netsh.exe"
    AND Processes.process = "*wlan*"
    AND Processes.process = "*show*"
    AND Processes.process = "*profile*"
    AND Processes.process = "*key=clear*"
`comment("This command can be used by legitimate administrators or helpdesk personnel. Review the parent process and user context to determine if the activity is malicious. Execution from an unusual parent process or by a non-administrative user increases suspicion.")`
| stats
    count
    values(Processes.process) as command_lines
    by
    Processes.dest
    Processes.user
    Processes.parent_process_name
| rename
    Processes.dest as host,
    Processes.user as user,
    Processes.parent_process_name as parent_process
```

### Electron Application Injection
---
```sql
`comment("This rule detects the manipulation of Electron application archives (ASAR files), a technique used by malware like NOVABLIGHT to inject malicious code into legitimate applications such as Discord, Mullvad VPN, or Exodus Wallet (T1188).")`
from datamodel=Endpoint.Processes
where
    `comment("Looks for 'asar' in the command line, which is the utility for manipulating Electron application archives.")`
    Processes.process = "*asar*"
    AND
    `comment("Looks for 'app.asar' in the command line, which is the standard name for an Electron application package.")`
    Processes.process = "*app.asar*"
    AND
    `comment("Focuses on commands that unpack or repack the archive, which are key steps in the injection process.")`
    (Processes.process = "*extract*" OR Processes.process = "*pack*")
`comment("This activity is common for developers working on Electron applications. It may also occur during legitimate application updates. Review the parent process, user, and host to determine if the activity is malicious. Execution by a non-developer user or from a suspicious parent process (e.g., cmd.exe, powershell.exe) is highly indicative of malicious activity. Consider excluding known developer workstations or legitimate updater processes (e.g., Update.exe) to reduce noise.")`
| stats
    count
    values(Processes.process) as command_lines
    by
    Processes.dest
    Processes.user
    Processes.parent_process_name
    Processes.process_name
| rename
    Processes.dest as host,
    Processes.user as user,
    Processes.parent_process_name as parent_process,
    Processes.process_name as process_name
```

### Chrome Data Decryption Tool Download
---
```sql
`comment("This rule detects the download of 'bin.zip' from GitHub, a behavior associated with the NOVABLIGHT infostealer which uses it to fetch a Chrome data decryption tool (T1105, T1555.003).")`
from datamodel=Network_Traffic
where
    `comment("Looks for network traffic involving the download of a file named 'bin.zip' from GitHub domains.")`
    (All_Traffic.url LIKE "%github.com/%/bin.zip" OR All_Traffic.url LIKE "%raw.githubusercontent.com/%/bin.zip")
`comment("While specific, this could trigger on legitimate developer activity if they use a similarly named file. Review the source host, user, and the specific GitHub repository URL to determine if the activity is malicious. The repository 'Hyutop/pandakmc-auto-vote' is a known indicator for NOVABLIGHT.")`
| stats
    count
    values(All_Traffic.url) as urls
    by
    All_Traffic.src
    All_Traffic.user
    All_Traffic.process_name
| rename
    All_Traffic.src as src_ip,
    All_Traffic.user as user,
    All_Traffic.process_name as process_name
```