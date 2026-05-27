### Fake Error Dialog Pattern Detection

Identifies processes creating fake error messages with social engineering text, commonly used in ClickFix to convince users they need to “fix” something by running malicious code.

T1204.004 - Malicious Copy and Paste

T1566 - Phishing

T1204 - User Execution

TA0002 - Execution

TA0001 - Initial Access

```sql
src.process.parent.name in:anycase ('chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe') and(src.process.cmdline contains:anycase 'msg.exe' or  src.process.cmdline contains:anycase 'Windows cannot' or  src.process.cmdline contains:anycase 'Error occurred' or  src.process.cmdline contains:anycase 'System error' or  src.process.cmdline contains:anycase 'Press Ctrl+C' or  src.process.cmdline contains:anycase 'Right-click and copy' or src.process.cmdline contains:anycase 'To fix this issue')
```