### WMIC Execution from Browser Context

Detects Windows Management Instrumentation Command-line (WMIC) execution from browsers, often used in ClickFix attacks for remote process creation or system manipulation.

T1047 - Windows Management Instrumentation

T1059 - Command and Scripting Interpreter

T1204 - User Execution

T1189 - Drive-by Compromise

TA0002 - Execution

TA0001 - Initial Access

```sql
src.process.name = 'wmic.exe' and
src.process.parent.name in:anycase ('chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe') and
(src.process.cmdline contains:anycase 'process call create' or src.process.cmdline contains:anycase 'product install' or src.process.cmdline contains:anycase 'startup')
```