### Odyssey Infostealer: Evolving macOS Threat
---

The Odyssey Infostealer, a variant of Atomic Stealer (AMOS), is actively evolving its techniques to target macOS users, incorporating code-signed and notarized binaries, sophisticated social engineering via SwiftUI "Technician Panels," and dynamic AppleScript payloads for comprehensive data exfiltration and persistence. This new variant also includes a backdoor for persistent access and the ability to replace legitimate cryptocurrency applications, posing a significant threat to user data and system integrity.

A significant new finding is the integration of a persistent backdoor and the capability to replace legitimate applications like Ledger Live with malicious versions, which escalates the threat beyond data theft to full system compromise and ongoing control. This evolution, along with the use of signed and notarized binaries, indicates a deliberate effort to enhance stealth and effectiveness, mirroring tactics seen in advanced persistent threat (APT) campaigns.

Actionable Threat Data

    Monitor for the creation of new LaunchDaemons in /Library/LaunchDaemons/ with randomly generated names, especially those executing osascript or bash commands that download and execute additional scripts from external URLs.

    Detect attempts to modify or replace legitimate applications, particularly cryptocurrency wallets like Ledger Live, by monitoring file system events for changes in /Applications/ and downloads of unsigned application bundles from suspicious IP addresses.

    Look for network connections to known Odyssey/AMOS C2 infrastructure, specifically 45.146.130.131, and monitor for HTTP POST requests to /log, /otherassets/ledger.zip, /otherassets/plist, /api/v1/bot/joinsystem/, /api/v1/bot/actions/, /api/v1/bot/repeat/, and /otherassets/socks.

    Identify the creation of hidden files in user home directories such as ~/.pwd, ~/.chost, ~/.username, and ~/.botid, as these are used by the stealer for storing sensitive information and maintaining persistence.

    Implement behavioral detections for osascript executing shell commands that involve curl to download and execute remote scripts, or chmod +x followed by execution of newly downloaded binaries in temporary directories like /tmp/.

### Suspicious LaunchDaemon Creation
---
```sql
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created AND Filesystem.file_path="/Library/LaunchDaemons/*" AND Filesystem.file_name="*.plist" by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `comment("This detection identifies the creation of a new .plist file in the /Library/LaunchDaemons/ directory on macOS.")`
| `comment("This is a common persistence technique used by malware, including the Odyssey Infostealer, to ensure it runs automatically on system startup.")`
| `comment("Legitimate software installers and system administrators may also create LaunchDaemons. Filter by known legitimate process_name values or file_name patterns to reduce noise.")`
| rename process_name as creating_process
| eval details="A new LaunchDaemon plist was created. File Name: ".file_name.", Created by Process: ".creating_process
| fields firstTime, lastTime, dest, user, creating_process, file_name, file_path, details
```

### Legitimate Application Replacement
---
```sql
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.action=created OR Filesystem.action=modified OR Filesystem.action=deleted) AND (Filesystem.file_path="/Applications/Ledger Live.app/*" OR Filesystem.file_path="/Applications/Exodus.app/*" OR Filesystem.file_path="/Applications/Atomic Wallet.app/*" OR Filesystem.file_path="/Applications/Electrum.app/*") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `comment("This detection identifies modifications to known cryptocurrency wallet application bundles in the /Applications directory by suspicious processes.")`
| `comment("The Odyssey Infostealer is known to replace legitimate wallet apps with trojanized versions. This activity is often performed by script interpreters (sh, osascript) or command-line tools (rm, unzip) rather than legitimate installers.")`
| `comment("Filter out common legitimate processes that update or manage applications. This list may need to be tuned for your environment.")`
| search NOT (process_name IN ("Installer", "Finder", "softwareupdated", "AppStore"))
| rex field=file_path "/Applications/(?<app_name>[^/]+\.app)"
| rename process_name as modifying_process
| eval details="The application '".app_name."' was modified by the process '".modifying_process."'."
| fields firstTime, lastTime, dest, user, modifying_process, app_name, file_path, details
| `comment("name: macOS Odyssey Infostealer Application Replacement")`
| `comment("date: 2025-07-22")`
| `comment("version: 1.0")`
| `comment("description: Detects modification of cryptocurrency wallet applications by suspicious processes, a technique used by Odyssey Infostealer.")`
| `comment("mitre_attack_id: T1036.003, T1189")`
| `comment("references: https://www.jamf.com/blog/signed-and-stealing-uncovering-new-insights-on-odyssey-infostealer/")`
```

### Odyssey C2 Communication
---
```sql
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="45.146.130.131" by All_Traffic.src, All_Traffic.dest_ip, All_Traffic.user, All_Traffic.process_name, All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `comment("This detection identifies network traffic to a known C2 IP address (45.146.130.131) used by the Odyssey Infostealer.")`
| `comment("Communication with this IP is a strong indicator of a compromised macOS system.")`
| rename dest_ip as dest, process_name as process
| eval details="User '".user."' on host '".src."' initiated a connection to known Odyssey C2 '".dest."' via process '".process."' on port ".dest_port."."
| fields firstTime, lastTime, src, dest, user, process, dest_port, details
| `comment("name: macOS Odyssey Infostealer C2 Communication")`
| `comment("date: 2025-07-22")`
| `comment("version: 1.0")`
| `comment("description: Detects network traffic to a known C2 IP address (45.146.130.131) associated with the Odyssey Infostealer malware.")`
| `comment("mitre_attack_id: T1071.001, T1568.002")`
| `comment("references: https://www.jamf.com/blog/signed-and-stealing-uncovering-new-insights-on-odyssey-infostealer/")`
```

### Odyssey Hidden Files Creation
---
```sql
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action="created" AND (Filesystem.file_name=".pwd" OR Filesystem.file_name=".chost" OR Filesystem.file_name=".username" OR Filesystem.file_name=".botid") by Filesystem.dest, Filesystem.user, Filesystem.process_name, Filesystem.file_name, Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `comment("This detection identifies the creation of specific hidden files used by the Odyssey Infostealer to store configuration data and credentials.")`
| `comment("The presence of these files (.pwd, .chost, .username, .botid) in a user's home directory is a strong indicator of compromise.")`
| rename dest as host, process_name as process
| eval details="Suspicious hidden file '".file_name."' created by process '".process."' for user '".user."' on host '".host."'."
| fields firstTime, lastTime, host, user, process, file_name, file_path, details
| `comment("name: macOS Odyssey Infostealer Hidden File Creation")`
| `comment("date: 2025-07-22")`
| `comment("version: 1.0")`
| `comment("description: Detects the creation of hidden files (.pwd, .chost, .username, .botid) in user home directories, a technique used by the Odyssey Infostealer for persistence and data storage.")`
| `comment("mitre_attack_id: T1552.001, T1070.004")`
| `comment("references: https://www.jamf.com/blog/signed-and-stealing-uncovering-new-insights-on-odyssey-infostealer/")`
```

### Suspicious osascript Execution
---
```sql
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="osascript" AND ( (Processes.process="*curl*" AND (Processes.process="*|*sh*" OR Processes.process="*|*bash*")) OR (Processes.process="*chmod*+x*" AND (Processes.process="*/tmp/*" OR Processes.process="*/var/folders/*")) ) by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `comment("This detection looks for osascript executing suspicious command-line arguments, a technique used by Odyssey Infostealer.")`
| `comment("It specifically targets osascript downloading and executing scripts via curl, or making files in temporary directories executable.")`
| `comment("While highly suspicious, some legitimate installers or admin scripts may use similar patterns. Review the parent_process_name and full command line to assess legitimacy.")`
| rename dest as host, parent_process_name as parent_process
| eval details="Suspicious osascript execution by user '".user."' on host '".host."'. Parent Process: '".parent_process."'. Command: ".process
| fields firstTime, lastTime, host, user, parent_process, process_name, process, details
| `comment("name: macOS Odyssey Infostealer Suspicious Osascript Execution")`
| `comment("date: 2025-07-22")`
| `comment("version: 1.0")`
| `comment("description: Detects suspicious execution of osascript involving downloading and executing remote scripts or making files in temporary directories executable. This is a known TTP of the Odyssey Infostealer.")`
| `comment("mitre_attack_id: T1059.002, T1106")`
| `comment("references: https://www.jamf.com/blog/signed-and-stealing-uncovering-new-insights-on-odyssey-infostealer/")`
```