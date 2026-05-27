### Initial Access - Probable Rogue ScreenConnect Session

Generic rule content from file: Initial Access - Probable Rogue ScreenConnect Session

S0591 - ConnectWise

T1219.002 - Remote Desktop Software

TA0001 - Initial Access

T1650 - Acquire Access

TA0006 - Credential Access

T1133 - External Remote Services

T1078 - Valid Accounts

T1021 - Remote Services

TA0011 - Command and Control

TA0042 - Resource Development

TA0003 - Persistence

TA0005 - Defense Evasion

TA0004 - Privilege Escalation

TA0008 - Lateral Movement

```sql
any(src.process.cmdline, tgt.process.cmdline) matches 'e=.*&y=.*&h=.*&p=.*' and !(any(src.process.cmdline, tgt.process.cmdline) matches 'h=.*(com|ca|net|co|org|me|support|au|uk|it|tech)&') and event.type = 'Process Creation'
```