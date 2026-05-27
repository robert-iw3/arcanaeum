<p align="center">
  <img src="https://www.elastic.co/security-labs/grid.svg" />
</p>

### Hunting Scheduled Tasks

Scheduled tasks are a normal part of system operations, they help with updates, backups, and maintenance jobs.

But attackers love them too. They often use scheduled tasks to make their tools run repeatedly, stay hidden, or survive reboots.

Example cmds:

```pwsh
schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"

SharPersist -t schtask -c "C:\Windows|System32\cmd.exe" -a "/c calc.exe" -n "SharPersist" -m add
```

### Kibana:

```sql
process.parent.name : "taskeng.exe"
OR process.parent.name : "taskhostw.exe"
OR process.parent.command_line : "*svchost.exe -k netsvcs -p -s Schedule*"
```

Search: file.path : *\\Windows\\System32\\Tasks\\*

Search the following Windows Event ID (better have logging, sysmon, and event forwarding on!)

Event 4698 = “A scheduled task was created."

### ES|QL:

```sql
from logs-system.security-default-*
| where  @timestamp > now() - 7 day
| where host.os.family == "windows" and event.code == "4698" and event.action == "scheduled-task-created"
 /* parsing unstructured data from winlog message to extract a scheduled task Exec command */
| grok message "(?<Command><Command>.+</Command>)" | eval Command = replace(Command, "(<Command>|</Command>)", "")
| where Command is not null
 /* normalise task name by removing usersid and uuid string patterns */
| eval TaskName = replace(winlog.event_data.TaskName, """((-S-1-5-.*)|\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\})""", "")
 /* normalise task name by removing random patterns in a file path */
| eval Task_Command = replace(Command, """(ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "")
 /* normalize user home profile path */
| eval Task_Command = replace(Task_Command, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9\.\-\_\$~]+\\""", "C:\\\\users\\\\user\\\\")
| where Task_Command like "?*" and not starts_with(Task_Command, "C:\\Program Files") and not starts_with(Task_Command, "\"C:\\Program Files")
| stats tasks_count = count(*), hosts_count = count_distinct(host.id) by Task_Command, TaskName
| where hosts_count == 1
```