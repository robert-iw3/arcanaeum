### Script Host Execution with Suspicious Extensions

Detects Windows Script Host execution of suspicious file types from browsers, often used in FileFix attacks to execute malicious VBScript or JScript files.

T1059 - Command and Scripting Interpreter

T1059.007 - JavaScript

T1059.005 - Visual Basic

T1204 - User Execution

T1204.002 - Malicious File

TA0002 - Execution

```sql
src.process.name in:anycase ('wscript.exe', 'cscript.exe') and
src.process.parent.name in:anycase ('chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe') and
(src.process.cmdline contains:anycase '.vbs' or src.process.cmdline contains:anycase '.js' or src.process.cmdline contains:anycase '.jse' or src.process.cmdline contains:anycase '.wsf') and
(src.process.cmdline contains:anycase 'Downloads' or src.process.cmdline contains:anycase 'Temp')
```