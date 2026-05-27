### Plague: A Newly Discovered PAM-Based Backdoor for Linux
---

"Plague" is a recently identified, stealthy Linux backdoor implemented as a malicious Pluggable Authentication Module (PAM) that allows attackers to bypass system authentication and gain persistent SSH access. This threat is particularly difficult to detect due to its deep integration into the authentication stack, evasion of traditional antivirus engines, and sophisticated obfuscation techniques.

Recent analysis of Plague samples reveals evolving string obfuscation techniques, including the adoption of more complex KSA and PRGA routines, and a new DRBG layer, indicating active development and adaptation by the threat actors to evade analysis and detection. The use of anti-debug checks and environment tampering to erase forensic traces further highlights the increasing sophistication of this PAM-based backdoor.

### Actionable Threat Data
---

T1556.003 - Pluggable Authentication Modules: Monitor for unauthorized modifications to PAM configuration files (e.g., `/etc/pam.d/*`) and shared objects under `/lib/security/` (e.g., `libselinux.so.8`, `pam_unix.so`).

T1070.004 - Indicator Removal: File Deletion: Detect attempts to unset environment variables like `SSH_CONNECTION` and `SSH_CLIENT`, and redirection of `HISTFILE` to `/dev/null`, which are tactics used by Plague to erase session artifacts and command history.

T1027 - Obfuscated Files or Information: Look for ELF binaries that contain the strings "`decrypt_phrase`" and "`init_phrases`", which are indicative of Plague's string deobfuscation routines.

T1036.005 - Masquerading: Match Legitimate Name: Monitor for the presence of suspicious files named `libselinux.so.8` or `libse.so` in unexpected directories, as Plague samples often masquerade as legitimate system libraries.

T1098 - Account Manipulation: Investigate successful SSH logins that occur without corresponding authentication logs or that use hardcoded backdoor passwords (e.g., "`Mvi4Odm6tld7`", "`IpV57KNK32Ih`", "`changeme`").

### Suspicious PAM File or Library Modification
---
```sql
`comment("This search uses the Endpoint datamodel to find file creation or modification events in critical PAM directories across various Linux distributions.")`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/etc/pam.d/*" OR Filesystem.file_path IN ("/lib/security/*", "/usr/lib/security/*", "/lib64/security/*")) AND Filesystem.action IN ("created", "modified") by Filesystem.action, Filesystem.dest, Filesystem.file_name, Filesystem.file_path, Filesystem.process_name, Filesystem.user
| `drop_dm_object_name(Filesystem)`

`comment("Filter out known legitimate processes that modify these files, such as package managers. This exclusion list may need to be tuned for your specific environment to reduce potential false positives.")`
| where NOT process_name IN ("yum", "apt", "apt-get", "dpkg", "rpm", "dnf", "pacman", "systemd", "chkconfig", "update-alternatives", "authconfig")

`comment("Format the results for review and investigation.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, process_name, file_path, file_name, action, count
```

### Malicious PAM Module
---
```sql
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/lib/security/*" OR Filesystem.file_path="*/lib64/security/*") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path Filesystem.file_hash
| rename "Filesystem.*" as *
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `comment("Filter out file modifications by common, legitimate package managers. This list may require tuning for your environment.")`
| search NOT (process_name IN (yum, apt, apt-get, dpkg, rpm, dnf, unattended-upgrade))
| `comment("Focus on known malicious filenames used by the Plague backdoor or any suspicious file creation in the sensitive PAM directories.")`
| search (file_name IN ("libselinux.so.8", "libse.so", "hijack") OR file_hash IN ("85c66835657e3ee6a478a2e0b1fd3d87119bebadc43a16814c30eb94c53766bb", "7c3ada3f63a32f4727c62067d13e40bcb9aa9cbec8fb7e99a319931fc5a9332e", "9445da674e59ef27624cd5c8ffa0bd6c837de0d90dd2857cf28b16a08fd7dba6", "5e6041374f5b1e6c05393ea28468a91c41c38dc6b5a5230795a61c2b60ed14bc", "6d2d30d5295ad99018146c8e67ea12f4aaa2ca1a170ad287a579876bf03c2950", "e594bca43ade76bbaab2592e9eabeb8dca8a72ed27afd5e26d857659ec173261", "14b0c90a2eff6b94b9c5160875fcf29aff15dcfdfd3402d953441d9b0dca8b39"))
| table firstTime, lastTime, dest, user, process_name, file_name, file_path, file_hash
| `lnx_malicious_pam_module_creation_filter`
```

### Linux SSH Session Artifact Removal
---
```sql
`comment("Search for process execution events that indicate attempts to clear SSH session artifacts or command history.")`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*unset SSH_CONNECTION*" OR Processes.process="*unset SSH_CLIENT*" OR Processes.process="*HISTFILE=/dev/null*") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process, Processes.process_id, Processes.parent_process_id
| `drop_dm_object_name(Processes)`

`comment("Legitimate administrative scripts may perform these actions. Filter out known benign processes or scripts to reduce false positives. This may require tuning for your specific environment.")`
| where NOT parent_process_name IN ("your_legit_script.sh", "config_manager_process")

`comment("Format the results for review and investigation.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, parent_process_name, process_name, process, process_id, parent_process_id, count
```

### Plague Backdoor Masquerading as System Library
---
```sql
`comment("This search uses the Endpoint datamodel to find file creation or modification events for specific library names associated with the Plague backdoor.")`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("libselinux.so.8", "libse.so") AND Filesystem.action IN ("created", "modified") by Filesystem.dest, Filesystem.user, Filesystem.process_name, Filesystem.file_path, Filesystem.file_name, Filesystem.action
| `drop_dm_object_name(Filesystem)`

`comment("Filter out legitimate library paths to identify files created in unexpected locations. This list of paths may need to be tuned for your environment, especially for non-standard Linux distributions or software installations.")`
| where NOT (match(file_path, "^/usr/lib(64)?/.*") OR match(file_path, "^/lib(64)?/.*"))

`comment("Format the results for review and investigation.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, process_name, file_path, file_name, action, count
```

### SSH Session without Corresponding Authentication Log
---
```sql
`comment("This search correlates two types of events: (1) an SSH daemon (sshd) spawning a shell, and (2) a successful SSH authentication log. It flags instances where a shell is spawned without a corresponding authentication event.")`
| tstats `security_content_summariesonly` count from datamodel=Endpoint.Processes where Processes.parent_process_name="sshd" AND Processes.process_name IN ("bash", "sh", "zsh", "csh", "tcsh", "ksh") by _time, Processes.dest, Processes.user
| `drop_dm_object_name(Processes)`
| bin _time span=2m
`comment("Tagging process events as 'ssh_session_started'. The time window (span) may need tuning based on logging delays in your environment.")`
| eval event_type="ssh_session_started"
| table _time, dest, user, event_type
| append [
    | tstats `security_content_summariesonly` count from datamodel=Endpoint.Authentication where Authentication.app="sshd" AND Authentication.action="success" by _time, Authentication.dest, Authentication.user
    | `drop_dm_object_name(Authentication)`
    | bin _time span=2m
    `comment("Tagging authentication events as 'ssh_auth_success'.")`
    | eval event_type="ssh_auth_success"
    | table _time, dest, user, event_type
    ]

`comment("Group events by time, host, and user. Identify sessions that started without a corresponding successful authentication event in the same time window.")`
| stats values(event_type) as event_types, min(_time) as firstTime, max(_time) as lastTime by _time, dest, user
| where mvcount(event_types)=1 AND event_types="ssh_session_started"

`comment("Format the results for review. This indicates a potential authentication bypass that requires investigation.")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user
```

### Authentication Bypass
---
```sql
`comment("This detection rule searches for hardcoded passwords used by the Plague backdoor. Successful detection is highly dependent on having data sources that might capture plaintext credentials, such as network traffic inspection (IDS/IPS), verbose debug logs, or specific EDR capabilities. Standard authentication logs (e.g., syslog, auth.log) do not typically contain passwords.")`
search (index=*)
`comment("Searching for known hardcoded passwords. The password 'changeme' is excluded due to its high potential for false positives.")`
("Mvi4Odm6tld7" OR "IpV57KNK32Ih")
`comment("Adding contextual keywords and sourcetypes to focus on authentication-related events and reduce noise from irrelevant data.")`
AND (sourcetype=linux:auth OR sourcetype=linux_secure OR sourcetype=suricata OR sourcetype=zeek:conn OR sourcetype=pan:traffic OR sshd OR login OR pam OR "authentication")
`comment("Grouping events to create a single alert per host and user combination.")`
| stats earliest(_time) as firstTime, latest(_time) as lastTime, count, values(sourcetype) as sourcetypes by dest, user, src, app
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `comment("Provide relevant fields for investigation.")`
| table firstTime, lastTime, dest, user, src, app, sourcetypes, count
| `lnx_plague_backdoor_authentication_bypass_filter`
```

