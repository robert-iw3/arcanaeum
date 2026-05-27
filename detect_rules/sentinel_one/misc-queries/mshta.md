### LOLBAS - Execution - MSHTA Executing Command and Scripting Interpreters

Generic rule content from file: LOLBAS - Execution - MSHTA Executing Command and Scripting Interpreters

T1218.005 - Mshta

T1059.001 - PowerShell

T1059 - Command and Scripting Interpreter

T1059.005 - Visual Basic

T1059.007 - JavaScript

TA0005 - Defense Evasion

TA0002 - Execution

```sql
event.type = 'Process Creation' and (any(src.process.parent.displayName, src.process.displayName) matches 'Microsoft.*HTML Application Host') and any(src.process.cmdline, tgt.process.cmdline) matches '(?i)\\b(powershell|wscript|jscript|cscript|vbscript|pwsh|cmd)\\b.*\\b(charcode|createdecryptor|chr|cryptography|invoke-webrequest|iwr|invoke-restmethod|irm|invoke-expression|iex|frombase64string|http|https|encoding|curl|convert|getstring\\b)'
```