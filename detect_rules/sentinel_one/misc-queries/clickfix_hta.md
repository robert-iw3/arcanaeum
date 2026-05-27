### Suspicious HTA File Execution

Identifies HTML Application (HTA) file execution from browsers, commonly used in ClickFix attacks to execute malicious scripts while appearing as legitimate web content.

T1204.004 - Malicious Copy and Paste

TA0002 - Execution

```sql
src.process.name = 'mshta.exe' and src.process.parent.name in:anycase ('chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe') and (src.process.cmdline contains:anycase 'Downloads' or src.process.cmdline contains:anycase 'Temp' or src.process.cmdline matches 'https?://')
```