### Clipboard Access from Browser Context

Detects clipboard manipulation from browser processes, often used in ClickFix attacks where malicious content is copied to the clipboard for users to paste into terminals.

T1115 - Clipboard Data

TA0009 - Collection

```sql
src.process.parent.name in:anycase ('chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe') and (src.process.cmdline contains:anycase 'Set-Clipboard' or src.process.cmdline contains:anycase 'Get-Clipboard' or src.process.cmdline contains:anycase 'clip.exe' or src.process.cmdline contains:anycase 'clipboard') and !(src.process.name in:anycase ('notepad.exe', 'code.exe', 'winword.exe', 'excel.exe'))
```