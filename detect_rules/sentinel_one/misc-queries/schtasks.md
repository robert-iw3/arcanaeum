### Unsigned Process Creating Scheduled Tasks and DNS exfil

Identifies unsigned processes creating scheduled tasks, a common persistence mechanism for malware. **Validation**: Very High - Legitimate task creation is typically done by signed system utilities.

T1053 - Scheduled Task/Job

T1053.005 - Scheduled Task

TA0002 - Execution

TA0003 - Persistence

TA0004 - Privilege Escalation

```sql
src.process.name in:anycase ('schtasks.exe', 'at.exe') and src.process.signedStatus = 'unsigned' and src.process.cmdline contains:anycase '/create'
```

```sql
event.type = 'DNS Request' and dst.port.number != 53 and src.process.signedStatus = 'unsigned'
```