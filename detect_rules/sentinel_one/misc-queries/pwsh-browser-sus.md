### PowerShell Execution from Browser with Suspicious Arguments

This rule detects the execution of PowerShell with suspicious command-line arguments (such as base64 encoded strings, Invoke-Expression, or encoded commands) when the parent process is a web browser. This behavior is often indicative of drive-by downloads, malicious advertisements, or exploitation of browser vulnerabilities leading to the execution of malicious PowerShell scripts.

T1059.001 - PowerShell

T1071.001 - Web Protocols

TA0002 - Execution

TA0011 - Command and Control

```sql
src.process.name in:anycase ('powershell.exe', 'pwsh.exe') and
(src.process.cmdline contains:anycase 'FromBase64String' or
 src.process.cmdline contains:anycase 'iex' or
 src.process.cmdline contains:anycase 'Invoke-Expression' or
 src.process.cmdline contains:anycase '-enc' or
 src.process.cmdline contains:anycase '-encoded') and
src.process.parent.name in:anycase ('chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe', 'opera.exe')
```