## ENS Rule Creation

Example's of how to construct threat hunting rules for Trellix ENS.

### Detect Suspicious AD Replication Process Behavior
---

This rule monitors lsass.exe (or other processes) attempting to create processes that might indicate replication activity.

```json
{
    "type": "expert",
    "name": "Detect Suspicious AD Replication Process Creation",
    "content": "Rule {\n   Reaction SCAN ACTOR_PROCESS ScanAction REPORT\n   Process {\n      Include OBJECT_NAME { -v \"lsass.exe\" }\n      Exclude OBJECT_NAME { -v \"C:\\\\Windows\\\\System32\\\\lsass.exe\" }\n   }\n   Target {\n      Match PROCESS {\n         Include OBJECT_NAME { -v \"**.exe\" }\n         Exclude OBJECT_NAME { -v \"C:\\\\Windows\\\\**\" }\n         Exclude OBJECT_NAME { -v \"C:\\\\Program Files\\\\**\" }\n         Exclude OBJECT_NAME { -v \"C:\\\\Program Files (x86)\\\\**\" }\n         Include -access \"CREATE\"\n      }\n   }\n}",
    "action": "Report",
    "severity": "High",
    "enabled": true
}
```

**Explanation:**

- Process: Targets lsass.exe but excludes the legitimate system path to avoid false positives from the default Windows process.
- Target: Matches any process creation (-access "CREATE") of executables outside trusted directories (e.g., C:\Windows, C:\Program Files).
- Reaction: Set to SCAN ACTOR_PROCESS with REPORT to log the event for analysis.
- Rationale: DCSync attacks often involve lsass.exe or similar processes being manipulated to initiate replication. This rule catches unexpected process creations that could indicate such behavior.
- Note: Administrators should fine-tune exclusions based on their environment, as recommended in the Trellix documentation.

### Detect Suspicious Network Connections to AD Ports
---

This rule monitors outbound connections to ports 135, 389, or 88 from non-system processes, which are indicative of DCSync network activity.

```json
{
    "type": "firewall",
    "name": "Detect Suspicious AD Replication Network Activity",
    "application": "**\\**.exe",
    "direction": "out",
    "protocol": "TCP",
    "port": "135,389,88",
    "action": "Report",
    "enabled": true
}
```

**Explanation:**

- Application: Uses a wildcard (**\\**.exe) to match any executable, as DCSync could be initiated by various processes.
- Direction and Protocol: Targets outbound TCP connections, as DCSync involves client-to-domain-controller communication.
- Port: Specifies ports 135 (RPC), 389 (LDAP), and 88 (Kerberos), which are used in AD replication and authentication.
- Action: Set to “Report” to log connections without blocking, allowing administrators to investigate potential false positives (e.g., legitimate AD traffic).
- Rationale: This rule captures the network component independently.
- Note: Exclusions for legitimate processes (e.g., system services) can be added via additional rules or fine-tuning, as Trellix firewall rules support application-specific filters.

### Detect Suspicious Process Behavior Initiating Network Activity
---

This rule monitors processes outside trusted paths (e.g., not in C:\Program Files) that might initiate suspicious network activity, such as proxying connections.

```json
{
    "type": "expert",
    "name": "Detect Suspicious Process Initiating Network Activity",
    "content": "Rule {\n   Reaction SCAN ACTOR_PROCESS ScanAction REPORT\n   Process {\n      Include OBJECT_NAME { -v \"**.exe\" }\n      Exclude OBJECT_NAME { -v \"C:\\\\Program Files\\\\**\" }\n      Exclude OBJECT_NAME { -v \"C:\\\\Program Files (x86)\\\\**\" }\n      Exclude OBJECT_NAME { -v \"C:\\\\Windows\\\\System32\\\\**\" }\n   }\n   Target {\n      Match NETWORK {\n         Include -protocol \"TCP\"\n         Include -port \"80,443\"\n         Include -direction \"OUTBOUND\"\n      }\n   }\n}",
    "action": "Report",
    "severity": "Medium",
    "enabled": true
}
```

**Explanation:**

- Process: Targets any executable (**.exe) but excludes trusted paths (C:\Program Files, C:\Windows\System32) to focus on potentially malicious processes.
- Target: Matches outbound TCP connections to ports 80 and 443.
- Reaction: Uses SCAN ACTOR_PROCESS with REPORT to log the process and network activity for analysis.
- Rationale: MiTM proxies often involve non-standard processes (e.g., not browsers like chrome.exe) initiating HTTP/HTTPS connections. This rule captures such behavior for further investigation.
- Note: The rule cannot filter by URL patterns or SSL issuers, so logs should be analyzed in ePO or a SIEM for these details.

### Detect Execution of Command-Line Utilities in Web Directories
---

This rule detects the execution of specified command-line utilities in the C:\inetpub\wwwroot directory, indicating potential web shell activity.

```json
{
    "type": "expert",
    "name": "Detect Web Shell Activity in Web Directories",
    "content": "Rule {\n   Reaction SCAN ACTOR_PROCESS ScanAction REPORT\n   Process {\n      Include OBJECT_NAME { -v \"wget.exe\" -v \"curl.exe\" -v \"nc.exe\" -v \"bash.exe\" -v \"python.exe\" -v \"perl.exe\" -v \"php.exe\" -v \"sh.exe\" }\n   }\n   Target {\n      Match FILE {\n         Include OBJECT_NAME { -v \"C:\\\\inetpub\\\\wwwroot\\\\**\" }\n         Include -access \"EXECUTE\"\n      }\n   }\n}",
    "action": "Report",
    "severity": "High",
    "enabled": true
}
```

**Explanation:**

- Process: Targets specific command-line utilities (wget.exe, curl.exe, nc.exe, bash.exe, python.exe, perl.exe, php.exe, sh.exe), as these are commonly used in web shell attacks.
- Target: Matches file execution (-access "EXECUTE") in the C:\inetpub\wwwroot directory, which is a common web server root on Windows systems.
- Reaction: Uses SCAN ACTOR_PROCESS with REPORT to log the event for analysis.
- Rationale: This rule captures the same behavior by monitoring process executions in C:\inetpub\wwwroot.
- Note: Administrators should analyze logs in ePO or a SIEM to check for command-line arguments or frequency of executions, as Trellix ENS cannot enforce these directly.

### Detect Suspicious Process Accessing Network Shares
---

This rule monitors processes initiating outbound SMB connections to port 445, focusing on non-system processes to detect potential misuse.

```json
{
    "type": "expert",
    "name": "Detect Suspicious Process Accessing SMB Shares",
    "content": "Rule {\n   Reaction SCAN ACTOR_PROCESS ScanAction REPORT\n   Process {\n      Include OBJECT_NAME { -v \"explorer.exe\" -v \"svchost.exe\" }\n      Exclude OBJECT_NAME { -v \"C:\\\\Windows\\\\System32\\\\explorer.exe\" -v \"C:\\\\Windows\\\\System32\\\\svchost.exe\" }\n   }\n   Target {\n      Match NETWORK {\n         Include -protocol \"TCP\"\n         Include -port \"445\"\n         Include -direction \"OUTBOUND\"\n      }\n   }\n}",
    "action": "Report",
    "severity": "Medium",
    "enabled": true
}
```

**Explanation:**

- Process: Targets explorer.exe and svchost.exe, which are commonly involved in SMB share access, but excludes their legitimate system paths (C:\Windows\System32) to reduce false positives.
- Target: Matches outbound TCP connections to port 445, indicating potential SMB share access.
- Reaction: Uses SCAN ACTOR_PROCESS with REPORT to log the process and network activity.
- Rationale: Adversaries may use valid accounts to access shares via processes like explorer.exe or svchost.exe. This rule detects such activity from non-standard locations, which could indicate compromise.
- Note: Administrators should analyze logs in ePO for share names and source addresses to exclude local access (::1) and confirm remote logins.

### Detect SQL Server Spawning Shells
---

This rule monitors sqlservr.exe spawning cmd.exe or powershell.exe, indicating potential malicious activity.

```json
{
    "type": "expert",
    "name": "Detect SQL Server Spawning Shells",
    "content": "Rule {\n   Reaction SCAN ACTOR_PROCESS ScanAction REPORT\n   Process {\n      Include OBJECT_NAME { -v \"sqlservr.exe\" }\n      Exclude OBJECT_NAME { -v \"C:\\\\Program Files\\\\Microsoft SQL Server\\\\**\\\\sqlservr.exe\" }\n   }\n   Target {\n      Match PROCESS {\n         Include OBJECT_NAME { -v \"cmd.exe\" -v \"powershell.exe\" }\n         Include -access \"CREATE\"\n      }\n   }\n}",
    "action": "Report",
    "severity": "High",
    "enabled": true
}
```

**Explanation:**

- Process: Targets sqlservr.exe but excludes trusted SQL Server paths to reduce false positives.
- Target: Matches creation (-access "CREATE") of cmd.exe or powershell.exe.
- Reaction: Uses SCAN ACTOR_PROCESS with REPORT to log events.
- Rationale: SQL Server spawning shells is highly suspicious and matches detection of shell execution.
- Note: Analyze logs in ePO for parent process details to confirm suspicious activity.

### Detect CLR Assembly Loading in SQL Directories
---

This rule monitors creation of .dll files in SQL Server directories, indicating potential CLR assembly loading.

```json
{
    "type": "expert",
    "name": "Detect Potential SQL CLR Assembly Loading",
    "content": "Rule {\n   Reaction SCAN ACTOR_PROCESS ScanAction REPORT\n   Process {\n      Include OBJECT_NAME { -v \"**.exe\" }\n      Exclude OBJECT_NAME { -v \"C:\\\\Program Files\\\\**\" -v \"C:\\\\Program Files (x86)\\\\**\" -v \"C:\\\\Windows\\\\System32\\\\**\" }\n   }\n   Target {\n      Match FILE {\n         Include OBJECT_NAME { -v \"**\\\\Microsoft SQL Server\\\\**\\\\MSSQL\\\\Binn\\\\**.dll\" }\n         Include -access \"WRITE\"\n      }\n   }\n}",
    "action": "Report",
    "severity": "High",
    "enabled": true
}
```

**Explanation:**

- Process: Targets any executable but excludes trusted paths to reduce false positives.
- Target: Matches file writes (-access "WRITE") to .dll files in SQL Server Binn directories.
- Reaction: Uses SCAN ACTOR_PROCESS with REPORT to log events.
- Rationale: Creation of .dll files in SQL Server directories may indicate malicious CLR assembly loading.
- Note: Analyze logs in ePO for specific file names and parent processes to confirm suspicious activity.