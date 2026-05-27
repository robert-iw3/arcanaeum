**Trellix ePO 5.10.0 Agent Handler Optimization Guide** (based on official Installation Guide v5.10.0, Feb 2026)

### 1. Official Sizing Recommendations (Straight from Guide)
**Rule of thumb (Tip on p14):**
**1 Agent Handler per 50,000 systems** (no hard limit — SQL IOPS is the real bottleneck).

| Node Count       | Number of Agent Handlers | CPU Cores (per AH) | RAM (per AH) | Storage (per AH) | Notes |
|------------------|---------------------------|--------------------|--------------|------------------|-------|
| < 10,000        | 0 (use built-in)         | —                  | —            | —                | Single server OK |
| 10k–25k         | 0–1                      | 4                  | 8 GB         | 150 GB           | — |
| 25k–75k         | 0–1                      | 4                  | 8 GB         | 150 GB           | — |
| 75k–150k        | 1–3                      | 4                  | 8 GB         | 150 GB           | Recommended |
| 150k+           | 3+                       | 4                  | 8 GB         | 150 GB           | Scale horizontally |

**SQL-side impact per Agent Handler (p24):**
Each AH adds:
- Heartbeat updates every minute
- Work queue checks every 10 seconds
- Open DB connections: **2 per CPU (Event Parser)** + **4 per CPU (Apache)**

**For very large environments (>75k systems):**
Do **not** co-locate AH with ePO server or DXL Broker. Dedicated AH servers maximize console performance.

### 2. Performance Factors & Bottlenecks (p23–24)
The guide explicitly lists what kills performance:
- **Primary bottleneck**: SQL database **disk IOPS** (not CPU/RAM on AH).
- Number of managed clients + products installed.
- Number of Agent Handlers (each adds fixed DB load).
- Network latency between AH ↔ ePO ↔ SQL.

**Optimization priority order:**
1. **SQL storage** (fastest disks, 64-KB sector size, >90k IOPS for 150k+ nodes).
2. **Dedicated Agent Handlers** (offload agent communication).
3. **Load balancing** (Azure ELB / AWS / GCP).
4. **Distributed repositories** + SuperAgents for large sites.

### 3. Best Practices for Maximum Optimization
- **Dedicated AH servers** (recommended >25k nodes).
- **Load Balancer** in front of multiple AHs (Azure ELB, AWS ALB, GCP). Update **Published DNS Name** in ePO console → Configuration → Agent Handlers.
- **DMZ / Internet-facing AH** for agents behind firewalls (use VPN or DXL as fallback for push tasks).
- **FIPS mode**: AH inherits FIPS from ePO server (`FipsMode=1` in `server.ini`). Verify after install (p137–138).
- **Certificate & DNS**: Always use FQDN. Update host file / DNS if restoring or moving AH (p131–132).
- **Monitoring**: Watch `AH5100-Install-MSI.log` and Apache logs for connection spikes.

### 4. Cloud-Specific Optimizations
- **Azure / AWS / GCP**: Use Elastic Load Balancer + Auto Scaling Groups.
- Update **Published DNS Name** and **IP** in ePO console after provisioning.
- Port requirements for LB: 80, 443, 8443 (same as ePO).

### 5. PowerShell Automation Snippets (Ready to Drop into Your Scripts)

#### Quick AH Health Check (run on any AH server)
```powershell
# AH Health & Optimization Check
$ahPath = "C:\Program Files (x86)\Trellix\ePolicy Orchestrator\Agent Handler"
Get-Content "$ahPath\server.ini" | Select-String "FipsMode|Port|ServerName"

# Count active connections (Apache)
Get-Process -Name httpd | Measure-Object | Select-Object Count
netstat -ano | Select-String ":8443" | Measure-Object | Select-Object Count
```

#### Automated AH Group Creation (run on ePO server after installing new AHs)
```powershell
# Example: Create AH Group with Load Balancer (run via ePO console or REST if scripted)
Write-Host "Create new AH Group in ePO console → Configuration → Agent Handlers"
# Use Published DNS = your load balancer FQDN
```

#### Full Post-Install AH Optimization Script (add to your ePO script)
```powershell
# After ePO install - optimize Agent Handler
Write-Host "=== Agent Handler Optimization ===" -ForegroundColor Cyan

# 1. Restart services cleanly
Restart-Service -Name "Trellix Agent Handler" -Force
Restart-Service -Name "Trellix Event Parser" -Force

# 2. Verify FIPS (if enabled)
$ini = Get-Content "C:\Program Files (x86)\Trellix\ePolicy Orchestrator\DB\server.ini"
if ($ini -match "FipsMode=1") { Write-Host "FIPS ENABLED on AH ✓" -ForegroundColor Green }

# 3. Log rotation & performance tweaks (optional)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Trellix\ePolicy Orchestrator\Agent Handler" -Name "MaxLogSizeMB" -Value 512
```

### Summary Recommendation for Your Environment
- **<50k systems** → 1 dedicated AH (4c/8GB) is perfect.
- **50k–150k** → 2–3 AHs + Load Balancer.
- **>150k** → 4+ AHs with dedicated SQL IOPS scaling.
- Always monitor **SQL IOPS** first — AHs are lightweight once SQL is tuned.

### Agent Handler Load Balancing Details

**Official Trellix recommendations (Installation Guide p. 53–59, 62–64):**

- **Use an external Load Balancer** (Azure ELB, AWS ALB, F5, etc.).
- **Ports to load-balance**: 80, 443, 8443.
- **Health probe**: `/ePOHealthCheck` (returns HTTP 200 if healthy).
- **Sticky sessions**: **Disabled** (AHs are stateless).
- **After creating the AH Group** (via REST script above), set **Published DNS Name** = your load-balancer FQDN and **Published IP** = LB VIP.

**PowerShell to update LB settings via REST (add to any script):**
```powershell
$lbBody = @{
    groupId          = $groupId
    publishedDNSName = "ah-lb.contoso.local"
    publishedIP      = "10.0.0.100"
    failoverEnabled  = $true
} | ConvertTo-Json

Invoke-RestMethod -Uri "$EpoUrl/api/2.0/ah/group/update" -Method Put -Credential $cred -Body $lbBody
```