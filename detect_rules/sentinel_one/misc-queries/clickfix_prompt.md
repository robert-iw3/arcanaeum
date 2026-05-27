### Command Prompt Chain from Browser

Identifies command prompt execution from browsers with suspicious parameters, indicating potential ClickFix attacks where users are tricked into running malicious commands.

T1059.003 - Windows Command Shell

T1204.001 - Malicious Link

DS0017 - Command

TA0002 - Execution

```sql
src.process.name = 'cmd.exe' and src.process.parent.name in:anycase ('chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe') and(src.process.cmdline contains:anycase '/c start' or src.process.cmdline contains:anycase '/c powershell' or src.process.cmdline contains:anycase '/c echo' or src.process.cmdline contains:anycase '/c copy' or src.process.cmdline contains:anycase 'clip')
```