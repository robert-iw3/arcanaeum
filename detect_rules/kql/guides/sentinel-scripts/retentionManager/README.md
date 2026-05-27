# retentionManager.ps1 (v1.0)
### 💡 PowerShell tool to configure total retention & interactive retention for Sentinel/Log Analytics tables

### Usage

.\retentionManager.ps1 **-TenantID** xxxx-xxxx-xxxx-xxxx [-All]

- If not provided in command line, tool will ask your tenant id.
- By default, only used tables are listed. If you really want to see them all, use -All switch.
- Tool will ask to update Az Modules.
- Log in using your azure credentials + potential conditional access requirements apply.
- Choose subscription.
- Choose Sentinel / Log analytics workspace.
- Work with your tables & retentions ⚙️

### Why?
Because this (https://techcommunity.microsoft.com/blog/microsoftsentinelblog/configuring-archive-period-for-tables-at-mass-for-data-retention-within-log-anal/4118220) is too difficult.
