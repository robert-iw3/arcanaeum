**SuperAgent Policies + HA Clustering**

### SuperAgent Policy Configurations – Full Details

SuperAgent offloads AH traffic for large branch offices. Here are **all configurable settings** (Policy Catalog → Agent → SuperAgent):

| Setting                              | Recommended Value          | Description / Impact |
|--------------------------------------|----------------------------|----------------------|
| **Use this computer as a SuperAgent** | Enabled                   | Core flag – turns the agent into a SuperAgent |
| **SuperAgent Wake-up Interval**      | 60 minutes                | How often SuperAgent checks for tasks |
| **Maximum number of concurrent tasks** | 50–100 (based on hardware) | Prevents overload |
| **Allow SuperAgent to push tasks**   | Enabled                   | Critical for large sites |
| **SuperAgent Communication Port**    | 8443 (or custom)          | Same as AH port |
| **Use SuperAgent for Repository Pulls** | Enabled                | Reduces WAN traffic |
| **SuperAgent Priority**              | High                      | For critical sites |

**PowerShell to apply SuperAgent policy via REST API** (add to the script above):
```powershell
$policyBody = @{
    policyName = "SuperAgent-Prod-Policy"
    settings   = @{
        "superAgentEnabled"          = $true
        "wakeUpIntervalMinutes"      = 60
        "maxConcurrentTasks"         = 75
        "allowPushTasks"             = $true
        "useForRepositoryPulls"      = $true
    }
} | ConvertTo-Json

Invoke-RestMethod -Uri "$EpoUrl/api/2.0/policy/assign" -Method Post -Credential $cred -Headers $headers -Body $policyBody
```

### High Availability ePO Clustering (Full Guide + Automation)

The guide (pages 66–73) outlines **Windows Failover Cluster** setup. Here is the exact workflow with PowerShell:

#### Cluster Prerequisites
- Windows Server 2022/2025 Failover Clustering feature
- Shared storage (CSV or SOFS) for ePO data drive
- Dedicated Client Access Point (CAP)

#### Automated Cluster Setup Script (`ePO-Cluster-Setup.ps1`)
```powershell
# ePO-Cluster-Setup.ps1 - Run on one cluster node as Domain Admin
Install-WindowsFeature Failover-Clustering -IncludeManagementTools

New-Cluster -Name "EPO-CLUSTER" -Node "node1","node2" -StaticAddress 10.0.0.50

# Create Application Role
Add-ClusterGroup -Name "ePO-AppRole"
Add-ClusterResource -Name "ePO-ClientAccessPoint" -Type "Client Access Point" -Group "ePO-AppRole"
Add-ClusterResource -Name "ePO-DataDrive" -Type "Physical Disk" -Group "ePO-AppRole"   # Add your CSV disk

# Install ePO on BOTH nodes (use our earlier FIPS script)
# Then create Generic Service resources
Add-ClusterResource -Name "ePO-Service" -Type "Generic Service" -Group "ePO-AppRole"
Set-ClusterResource -Name "ePO-Service" -Parameters @{ServiceName="Trellix ePO Server"}

# Multi-Subnet Failover (page 73)
Set-ClusterResource -Name "ePO-ClientAccessPoint" -Parameters @{RegisterAllProvidersIP=1; HostRecordTTL=300}
```

**Key HA Best Practices**
- Use **Multi-Subnet** failover (Windows 2022+).
- Set **RegisterAllProvidersIP=1** for DNS.
- Backup the entire `C:\Program Files (x86)\Trellix\ePolicy Orchestrator` folder + DB before failover testing.
- Test failover with `Move-ClusterGroup "ePO-AppRole"`.