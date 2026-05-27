### Masquerade - Suspicious ScreenConnect Install

Generic rule content from file: Masquerade - Suspicious ScreenConnect Install

S0591 - ConnectWise

T1219.002 - Remote Desktop Software

T1546.016 - Installer Packages

T1036 - Masquerading

TA0011 - Command and Control

TA0004 - Privilege Escalation

TA0003 - Persistence

TA0005 - Defense Evasion

```sql
!(any(src.process.parent.cmdline, tgt.process.parent.cmdline) matches '(?i)(screenconnect|connectwise)') and
any(src.process.displayName, tgt.process.dispayName) matches '(?i)Windows® installer' and
any(tgt.process.cmdline, src.process.cmdline) matches '(?i)\/i.*appdata.*screenconnect'
```