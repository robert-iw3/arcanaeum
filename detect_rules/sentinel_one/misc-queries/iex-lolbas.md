### LOLBAS - Powershell - W3WP Initiating Outbound Web Requests

Detects suspicious usage of PowerShell making outbound web requests initiated by the IIS Worker Process (w3wp.exe), which may indicate webshell activity or post-exploitation behavior through living-off-the-land techniques. This rule specifically looks for `Invoke-Expression`, `Invoke-WebRequest`, or `Invoke-RestMethod` patterns when launched from w3wp.exe and not by the NT AUTHORITY account.

TA0002 - Execution

TA0011 - Command and Control

```sql
src.process.parent.cmdline contains 'w3wp' and src.process.cmdline matches '(?i)powershell.*(invoke-(expression|webrequest|restmethod)|i(rm|ex|wr))' and !(src.process.user contains 'nt authority')
```
