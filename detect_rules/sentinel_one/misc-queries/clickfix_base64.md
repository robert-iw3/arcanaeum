### PowerShell with Base64 and Network Activity

Catches PowerShell processes with both Base64 decoding and network download capabilities, indicating potential remote payload execution typical of advanced ClickFix attacks.

T1059.001 - PowerShell

T1105 - Ingress Tool Transfer

TA0002 - Execution

TA0011 - Command and Control

```sql
src.process.name in:anycase ('powershell.exe', 'pwsh.exe') and(src.process.cmdline contains:anycase 'FromBase64String' or src.process.cmdline contains:anycase '-enc' or src.process.cmdline contains:anycase '-encoded') and(src.process.cmdline contains:anycase 'DownloadString' or src.process.cmdline contains:anycase 'WebClient' or src.process.cmdline contains:anycase 'Invoke-WebRequest' or src.process.cmdline contains:anycase 'curl' or src.process.cmdline contains:anycase 'wget')
```