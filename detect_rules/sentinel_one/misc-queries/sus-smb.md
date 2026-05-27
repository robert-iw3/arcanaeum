### SMBExec was Used

Detects potential attempts to access administrative shares using cmd.exe or powershell.exe, which could indicate lateral movement or unauthorized access attempts.

T1021.002 - SMB/Windows Admin Shares

TA0008 - Lateral Movement

```sql
src.process.name contains:anycase ('cmd.exe' ,'powershell.exe') AND src.process.cmdline contains:anycase "2" AND src.process.cmdline contains:anycase "&1" AND (src.process.cmdline contains:anycase ( "C$", "ADMIN$","IPC$", "PRINT$", "FAX$"))
```