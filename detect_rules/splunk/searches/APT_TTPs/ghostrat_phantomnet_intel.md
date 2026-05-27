### China-nexus APT Targets Tibetan Community
---

A China-nexus APT group launched two cyberattack campaigns, Operation GhostChat and Operation PhantomPrayers, targeting the Tibetan community by leveraging the Dalai Lama's 90th birthday to distribute Ghost RAT and PhantomNet backdoors through social engineering and strategic web compromises. These multi-stage attacks utilized DLL sideloading and advanced evasion techniques to maintain persistence and exfiltrate sensitive information.


Recent intelligence confirms that China-nexus APT groups continue to employ sophisticated evasion techniques, such as using low-level Windows APIs and manipulating ntdll.dll to bypass EDR solutions, which is a notable evolution in their tactics to achieve stealthier and more persistent access. This highlights a continuous arms race where attackers are constantly refining methods to avoid detection by security products.

### Actionable Threat Data
---

Monitor for the creation of new files in `%appdata%\Birthday\` and `%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\` directories, especially `VLC.exe`, `libvlc.dll`, `.tmp` files, and `Birthday Reminder.lnk`, as these are indicators of the PhantomPrayers infection chain.

Detect processes like `ImagingDevices.exe` or `Element.exe` loading unexpected DLLs (e.g., `ffmpeg.dll`, `libvlc.dll`) from non-standard or user-writable directories, which is indicative of DLL sideloading.

Look for outbound network connections from `ImagingDevices.exe` or `VLC.exe` to suspicious IP addresses and ports, specifically `104.234.15[.]90:19999` (Ghost RAT C2) and `45.154.12[.]93:2233` (PhantomNet C2), or any communication using custom binary protocols.

Identify modifications to the `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` registry key, particularly the addition of a value named "Element" pointing to an unusual or malicious executable path, used for persistence by Ghost RAT.

Monitor for the execution of `DalaiLamaCheckin.exe` and subsequent HTTP `GET` requests to `104.234.15[.]90:59999/api/checkins` with the custom HTTP header `X-API-KEY: m1baby007..`, indicating the PhantomPrayers social engineering and data collection activity.

### PhantomPrayers File Creation
---
```sql
`comment("This detection rule identifies the creation of specific files in directories associated with the PhantomPrayers malware campaign.")`
`comment("The rule leverages file creation events, typically from an EDR or Sysmon (EventCode 11), and is mapped to the 'Filesystem' data model.")`
`tstats` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where
    `comment("Look for files related to the VLC sideloading technique in the %appdata%\\Birthday directory or the persistence LNK file in the Startup folder.")`
    (Filesystem.file_path="*\\AppData\\Roaming\\Birthday\\*" AND (Filesystem.file_name="VLC.exe" OR Filesystem.file_name="libvlc.dll" OR Filesystem.file_name="*.tmp")) OR
    (Filesystem.file_path="*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*" AND Filesystem.file_name="Birthday Reminder.lnk")
    by Filesystem.file_name, Filesystem.dest, Filesystem.user
| `drop_dm_object_name("Filesystem")`
| `comment("Aggregate results by host and user to identify systems where multiple suspicious files were created.")`
| stats values(file_name) as suspicious_files, dc(file_name) as distinct_suspicious_files, min(firstTime) as firstTime, max(lastTime) as lastTime by dest, user
| `comment("To reduce potential false positives, this rule only triggers if at least two distinct suspicious files are detected on the same host. This threshold can be adjusted based on environmental noise.")`
| where distinct_suspicious_files >= 2
| `convert_ctime(firstTime)`
| `convert_ctime(lastTime)`
| `comment("The final output provides the affected host, user, a list of the suspicious files, and the timeframe of the activity.")`
| table firstTime, lastTime, dest, user, distinct_suspicious_files, suspicious_files
```

### DLL Sideloading Detection
---
```sql
`comment("This rule detects potential DLL sideloading activity associated with the GhostChat and PhantomPrayers campaigns, where a legitimate process loads a malicious DLL.")`
tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.ImageLoads where
    `comment("Filter for vulnerable processes (Element.exe, ImagingDevices.exe, VLC.exe) loading specific DLLs (ffmpeg.dll, libvlc.dll).")`
    (ImageLoads.process_name IN ("Element.exe", "ImagingDevices.exe", "VLC.exe")) AND
    (ImageLoads.file_name IN ("ffmpeg.dll", "libvlc.dll")) AND
    `comment("FP Note: Portable applications may legitimately load DLLs from their own directory. Exclude known safe paths for portable apps if necessary.")`
    NOT (ImageLoads.file_path IN ("C:\\Program Files\\*", "C:\\Windows\\System32\\*"))
    by ImageLoads.dest, ImageLoads.user, ImageLoads.process_name, ImageLoads.file_name, ImageLoads.file_path
| `drop_dm_object_name("ImageLoads")`
| `convert ctime(firstTime)`
| `convert ctime(lastTime)`
| `comment("The final output shows the host, user, process, and the potentially sideloaded DLL with its path.")`
| table firstTime, lastTime, dest, user, process_name, file_name, file_path, count
```

### Ghost RAT C2 Communication
---
```sql
`comment("This rule detects network traffic to a known Ghost RAT C2 server identified in the GhostChat campaign.")`
tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where
    `comment("Filter for the specific C2 IP and port combination.")`
    (Network_Traffic.dest_ip="104.234.15.90" AND Network_Traffic.dest_port="19999")
    by Network_Traffic.src_ip, Network_Traffic.dest_ip, Network_Traffic.dest_port, Network_Traffic.user, Network_Traffic.process_name
| `drop_dm_object_name("Network_Traffic")`
| `convert ctime(firstTime)`
| `convert ctime(lastTime)`
| `comment("The final output shows the internal host communicating with the malicious C2 server.")`
| table firstTime, lastTime, src_ip, dest_ip, dest_port, user, process_name, count
```

### PhantomNet C2 Communication
---
```sql
`comment("This rule detects network traffic to a known PhantomNet C2 server identified in the PhantomPrayers campaign.")`
tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where
    `comment("Filter for the specific C2 IP and port combination.")`
    (Network_Traffic.dest_ip="45.154.12.93" AND Network_Traffic.dest_port="2233")
    by Network_Traffic.src_ip, Network_Traffic.dest_ip, Network_Traffic.dest_port, Network_Traffic.user, Network_Traffic.process_name
| `drop_dm_object_name("Network_Traffic")`
| `convert ctime(firstTime)`
| `convert ctime(lastTime)`
| `comment("The final output shows the internal host communicating with the malicious C2 server.")`
| table firstTime, lastTime, src_ip, dest_ip, dest_port, user, process_name, count
```

### Ghost RAT Registry Persistence
---
```sql
`comment("This rule detects the creation of a specific registry key used by a Ghost RAT variant for persistence, as seen in the GhostChat campaign.")`
tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where
    `comment("Filter for the specific Run key path and the value name 'Element' used by the malware.")`
    (Registry.registry_path="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" AND Registry.registry_value_name="Element")
    `comment("This activity is typically logged by Sysmon EventCode 13 (RegistryValue Set) or equivalent EDR telemetry.")`
    AND (Registry.action = "created" OR Registry.action = "modified")
    by Registry.dest, Registry.user, Registry.process_name, Registry.registry_path, Registry.registry_value_name, Registry.registry_value_data
| `drop_dm_object_name("Registry")`
| `convert ctime(firstTime)`
| `convert ctime(lastTime)`
| `comment("The final output shows the host and user where the persistence was established, and the executable path that will be run at startup.")`
| table firstTime, lastTime, dest, user, process_name, registry_path, registry_value_name, registry_value_data, count
```

### PhantomPrayers Check-in Activity
---
```sql
`comment("This rule detects the specific network check-in activity associated with the PhantomPrayers malware campaign.")`
tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where
    `comment("Filter for HTTP GET requests to the specific C2 IP, port, and URI path used by the malware.")`
    (Web.http_method="GET") AND
    (Web.dest="104.234.15.90") AND
    (Web.dest_port="59999") AND
    (Web.url="*/api/checkins") AND
    `comment("The check-in request contains a unique, hardcoded API key in the HTTP header.")`
    (Web.http_header="*X-API-KEY: m1baby007..*")
    by Web.src, Web.dest, Web.url, Web.http_header, Web.user, Web.process_name
| `drop_dm_object_name("Web")`
| `convert ctime(firstTime)`
| `convert ctime(lastTime)`
| `comment("The final output shows the source host, user, and process (if available) making the malicious check-in request.")`
| table firstTime, lastTime, src, user, process_name, dest, url, http_header, count
```
