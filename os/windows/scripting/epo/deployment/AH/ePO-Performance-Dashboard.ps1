# ePO-Performance-Dashboard.ps1
$epoUrl = "https://epo.contoso.local:8443"
$creds = Get-Credential   # ePO admin

# Get all Agent Handlers + stats
$ahList = Invoke-RestMethod -Uri "$epoUrl/api/2.0/ah/list" -Method Get -Credential $creds -ContentType "application/json"

$dashboard = foreach ($ah in $ahList) {
    $stats = Invoke-RestMethod -Uri "$epoUrl/api/2.0/ah/$($ah.id)/stats" -Method Get -Credential $creds
    [pscustomobject]@{
        HandlerName     = $ah.name
        SystemsConnected= $stats.connectedSystems
        CPUUsage        = $stats.cpuPercent
        MemoryMB        = $stats.memoryUsedMB
        AvgResponseMs   = $stats.avgResponseTimeMs
        Health          = $stats.healthStatus
    }
}

$dashboard | Format-Table -AutoSize
$dashboard | Export-Csv "ePO-AH-Dashboard-$(Get-Date -f yyyyMMdd).csv" -NoTypeInformation