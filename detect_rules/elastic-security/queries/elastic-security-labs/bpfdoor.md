<p align="center">
  <img src="https://www.elastic.co/security-labs/grid.svg" />
</p>

## A peek behind the BPFDoor

BPFDoor is a backdoor payload specifically crafted for Linux. Its purpose is for long-term persistence in order to gain re-entry into a previously or actively compromised target environment. It notably utilizes BPF along with a number of other techniques to achieve this goal, taking great care to be as efficient and stealthy as possible. PWC researchers discovered this very interesting piece of malware in 2021. PWC attributes this back door to a specific group from China, Red Menshen, and detailed a number of interesting components in a high-level threat research post released last week.

PWC's findings indicated that ​​Red Menshen had focused their efforts on targeting specific Telecommunications, Government, Logistics, and Education groups across the Middle East and Asia. This activity has been across a Monday-to-Friday working period, between 01:00 UTC and 10:00 UTC, indicating that the operators of the malware were consistent in their attacks, and operation during a working week.

Perhaps most concerningly, the payload itself has been observed across the last 5 years in various phases of development and complexity, indicating that the threat actor responsible for operating the malware has been at it for some time, undetected in many environments.

## Hunting Queries

This EQL rule can be used to successfully identify BPFDoor reverse shell connections having been established within your environment:

##

EQL BPFDoor reverse shell hunt query

```sql
sequence by process.entity_id with maxspan=1m
[network where event.type == "start" and event.action == "connection_attempted" and user.id == "0" and not process.executable : ("/bin/ssh", "/sbin/ssh", "/usr/lib/systemd/systemd")]
[process where event.action == "session_id_change" and user.id == "0"]
```

##

EQL BPFDoor bind shell hunt query

```sql
sequence by process.entity_id with maxspan=1m
[process where event.type == "change" and event.action == "session_id_change" and user.id == 0 and not process.executable : ("/bin/ssh", "/sbin/ssh", "/usr/lib/systemd/systemd")]
[network where event.type == "start" and event.action == "connection_accepted" and user.id == 0]
[file where event.action == "creation" and user.id == 0 and file.path == "/dev/ptmx"]
[process where event.action == "end" and user.id == 0 and not process.executable : ("/bin/ssh", "/sbin/ssh", "/usr/lib/systemd/systemd")]
```