### Suspicious SharePoint Activity (ToolShell)

This rule detects the creation of a new process (cmd.exe) that is spawned by a w3wp.exe process, which itself is a child of svchost.exe, and where the command line of the w3wp.exe process contains the string "SharePoint". This chain of events could indicate suspicious activity within a SharePoint environment, potentially an attacker executing commands via a compromised IIS worker process.

S0106 - cmd

DS0009 - Process

T1059 - Command and Scripting Interpreter

T1059.001 - PowerShell

TA0002 - Execution

T1190 - Exploit Public-Facing Application

---

```sql
dataSource.name = 'SentinelOne' and endpoint.os = "windows" and event.type = "Process Creation" and
src.process.parent.name contains "svchost.exe" and src.process.name contains "w3wp.exe" and
tgt.process.name contains "cmd.exe" and src.process.cmdline contains "SharePoint"
```

---

```sql
initiating_process.image_name ILIKE "%w3wp.exe"
AND initiating_process.command_line NOT ILIKE "%DefaultAppPool%"
AND process.image_name ILIKE "%cmd.exe"
AND process.command_line ILIKE "%cmd.exe%"
AND process.command_line ILIKE "%powershell%"
AND (
  process.command_line ILIKE "%EncodedCommand%"
  OR process.command_line ILIKE "%-ec%"
)
AND process.command_line REGEX "([A-Za-z0-9+/=]{15,})"
```


