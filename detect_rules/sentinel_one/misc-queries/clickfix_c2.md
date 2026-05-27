### Browser Network Connections with Command Execution

Catches outgoing network connections to external IPs from command-line tools spawned by browsers, indicating potential command-and-control communication in ClickFix attacks.

T1059.001 - PowerShell

S0106 - cmd

T1218.011 - Rundll32

TA0011 - Command and Control

T1071.001 - Web Protocols

TA0002 - Execution

TA0005 - Defense Evasion

```sql
event.type = 'IP Connect' andevent.network.direction = 'OUTGOING' andsrc.process.parent.name in:anycase ('chrome.exe', 'firefox.exe', 'msedge.exe') andsrc.process.name in:anycase ('powershell.exe', 'cmd.exe', 'rundll32.exe') anddst.port.number in (80, 443, 8080, 8443) and!(dst.ip.address matches '^10\\.' or dst.ip.address matches '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.' or dst.ip.address matches '^192\\.168\\.' or dst.ip.address matches '^127\\.' or dst.ip.address matches '^169\\.254\\.' or dst.ip.address matches '^224\\.')
```