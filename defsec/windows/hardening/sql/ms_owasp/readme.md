# SQL Server Security Hardening Toolkit
OWASP + Microsoft Best Practices

**Last updated:** January 2026

A collection of PowerShell scripts to audit, harden, backup configuration, and rollback changes
for Microsoft SQL Server following both **OWASP Database Security Cheat Sheet** recommendations
and **Microsoft SQL Server Security Best Practices**.

## Features

- Automated auditing (reports in CSV + JSON + log)
- Hardening with before/after reporting
- Automatic configuration backup before any changes (Microsoft version)
- Rollback capability using backup files
- Clear separation between OWASP-focused and Microsoft-focused security controls

## Scripts Overview

| Script                              | Purpose                                      | Scope                | Automatic Backup? | Rollback Available? |
|-------------------------------------|----------------------------------------------|----------------------|-------------------|---------------------|
| `OWASP-Audit-SQLServer.ps1`               | OWASP-based security audit                   | OWASP                | -                | —                   |
| `OWASP-Harden-SQLServer.ps1`              | Apply OWASP hardening recommendations        | OWASP                | **Yes**                | Yes                 |
| `MSSec-Audit-SQLServer.ps1`            | Microsoft best practices audit               | Microsoft            | -                | —                   |
| `MSSec-Harden-SQLServer.ps1`           | Apply Microsoft best practices + auto backup | Microsoft            | **Yes**           | Yes                 |
| `MSSec-Backup-SQLConfig.ps1`           | Backup current config (Microsoft focus)      | Microsoft            | —                 | —                   |
| `MSSec-Rollback-SQLHardening.ps1`      | Restore from Microsoft backup                | Microsoft            | —                 | —                   |
| `OWASP-Backup-SQLConfig.ps1`        | Backup current config (OWASP focus)          | OWASP                | —                 | —                   |
| `OWASP-Rollback-Hardening.ps1`      | Restore from OWASP backup                    | OWASP                | —                 | —                   |

## Requirements

- PowerShell 5.1 or later (Windows PowerShell or PowerShell 7 recommended)
- SQL Server PowerShell module
  ```powershell
  Install-Module -Name SqlServer -Scope CurrentUser -AllowClobber
  ```
- **Administrative privileges** on the target server (for services/registry)
- **sysadmin** role on SQL Server for most operations
- Read/write access to the folders where results/backups are stored

## Quick Start – Recommended Workflow

```pwsh
# 1. Audit current state from sql server locally
.\OWASP-Audit-SQLServer.ps1 -ServerName "localhost" -OutputPath "C:\SQLAudit\OWASP"
.\MSSec-Audit-SQLServer.ps1 -ServerName "localhost" -OutputPath "C:\SQLAudit\MS"

# 2. Harden (automatically creates backup first!)
.\OWASP-Harden-SQLServer.ps1 -ServerName "localhost" -ConfigPath "C:\Configs\OWASP-HardeningConfig.json" -BackupOutputDir "C:\SQLBackups\OWASP"
.\MSSec-Harden-SQLServer.ps1 -ServerName "localhost" -ConfigPath "C:\Configs\MSSec-HardeningConfig.json" -BackupOutputDir "C:\SQLBackups\MS"

# 3. If something goes wrong → rollback
.\OWASP-Rollback-Hardening.ps1 -ServerName "localhost" ` -BackupFile ".\ConfigBackupOWASP\CurrentConfigBackup_OWASP_20260117_214530.json"
.\MSSec-Rollback-SQLHardening-MS.ps1 -ServerName "localhost" ` -BackupFile ".\ConfigBackupMS\CurrentConfigBackup_20260117_221500.json"
```

## Important Safety Notes

- **Always test first** in a non-production environment
- Many Microsoft-recommended features require manual intervention:
    - Transparent Data Encryption (TDE)
    - Group Managed Service Accounts (gMSA)
    - TLS 1.0/1.1 disable + TLS 1.2 enforcement
    - Data classification / sensitivity labels
    - Full Extended Protection configuration

- Some changes require **SQL Server service restart** (Force Encryption, authentication mode, Extended Protection)
- **Backups are critical** — the Microsoft hardening script now enforces automatic backup