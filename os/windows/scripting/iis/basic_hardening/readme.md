# IIS Auditing & Hardening Toolkit

A complete PowerShell-based solution for auditing and hardening IIS 10/11 servers according to modern security best practices (CIS, DISA STIG, OWASP 2025–2026 recommendations).

## Included Scripts

| Script                                   | Purpose                                                                 |
|------------------------------------------|-------------------------------------------------------------------------|
| `Audit-IIS.ps1`                          | Audits current IIS configuration, outputs CSV report + failed config.ini |
| `Harden-IIS.ps1`                         | Applies hardening settings based on config.ini                          |
| `Backup-IIS-ConfigBeforeHarden.ps1`      | Creates detailed pre-hardening backup (configs, registry, headers)      |
| `Rollback-IIS-Hardening.ps1`             | Restores IIS from backup in case of issues                              |

## Requirements

- Windows Server 2016 / 2019 / 2022 / 2025 with IIS installed
- PowerShell 5.1+ (default on Windows Server)
- **Administrator privileges** required
- WebAdministration module (comes with IIS Management Tools)

## Recommended Workflow

```powershell
# 1. Audit current state
.\Audit-IIS.ps1

# Review IIS_Audit_Results_*.csv and generated config.ini
# Edit config.ini to choose which fixes to apply (true/false)

# 2. Create backup & harden
.\Harden-IIS.ps1

# 3. If something breaks:
.\Rollback-IIS-Hardening.ps1 -BackupPath ".\IIS_BACKUP_BEFORE_20260118-1125xx"
```

## Important Safety Notes

- Test in **non-production** environment first
- After hardening: run `iisreset` or restart server (especially for TLS/cipher changes)
- Some items (e.g. moving web content, host headers) require **manual action**
- CSP header applied is **very generic** — customize per application!

## Main Features

- **Audit**: 30+ global checks + 18+ site-specific checks (including modern headers)
- **Headers covered**: HSTS, X-XSS-Protection, CSP, X-Frame-Options, Referrer-Policy, X-Content-Type-Options, Permissions-Policy
- **TLS hardening**: Disables SSL 2/3, TLS 1.0/1.1, weak ciphers, strong suite order
- **Safety net**: Full backup (configs, registry, headers) + rollback capability
- **Ultra-defensive**: Granular try/catch, pre-flight checks, detailed logging

## Quick Start (Recommended)

1. Place all scripts in the same folder
2. Run audit: `.\Audit-IIS.ps1`
3. Review/edit `config.ini`
4. Apply hardening safely: `.\Harden-IIS.ps1`
5. Test applications thoroughly
6. If needed → rollback using the generated backup folder

## Troubleshooting

- **"WebAdministration module not found"** → Install IIS Management Tools
- **Permission denied** → Run PowerShell as Administrator
- **appcmd.exe errors** → Check IIS service is running (`Get-Service W3SVC`)
- **Rollback failed** → Manual restore using backup files + iisreset