<#
.SYNOPSIS
    Full REST API automation for Agent Handler Groups + Load Balancer (ePO 5.10.0)

.DESCRIPTION
    This script demonstrates how to use the ePO REST API to automate the creation of Agent Handler
    groups and assign Agent Handlers to them, along with configuring a load balancer for high availability.
    It connects to the ePO server, retrieves existing Agent Handlers, creates a new group, adds specified
    Agent Handlers to the group, and assigns a load balancer with a published DNS name and IP address.
    This is useful for large deployments where you want to programmatically manage your Agent Handlers and
    ensure high availability through load balancing.

.PARAMETER EpoUrl
    The base URL of the ePO server (e.g., https://epo.contoso.local:8443)
.PARAMETER GroupName
    The name of the Agent Handler group to create or update.
.PARAMETER AHNames
    An array of Agent Handler names to add to the group.
.PARAMETER LoadBalancerDNS
    The published DNS name of the load balancer that will distribute traffic to the Agent Handlers.
.PARAMETER LoadBalancerIP
    The published IP address of the load balancer.
.PARAMETER Username
    The ePO admin username for authentication.
.PARAMETER Password
    The ePO admin password for authentication (will be prompted if not provided).

.EXAMPLE
    .\ePO-REST-AH-Automation.ps1 -EpoUrl "https://epo.contoso.local:8443" -GroupName "Production-AH-Group"
    -AHNames @("ah01.contoso.local", "ah02.contoso.local")
    -LoadBalancerDNS "ah-lb.contoso.local" -LoadBalancerIP "10.0.0.100" -Username "epoadmin"

.NOTES
    Author: Robert Weber
    Ensure you have the necessary permissions and that PowerShell remoting is enabled if running remotely.
    Test in a non-production environment first to validate functionality and avoid disruptions.
    The ePO REST API endpoints and payloads may vary based on your ePO version; refer to the official API documentation for details.
#>

param (
    [string]$EpoUrl          = "https://epo.contoso.local:8443",
    [string]$GroupName       = "Production-AH-Group",
    [string[]]$AHNames       = @("ah01.contoso.local", "ah02.contoso.local"),
    [string]$LoadBalancerDNS = "ah-lb.contoso.local",      # Your Azure/AWS/GCP load balancer FQDN
    [string]$LoadBalancerIP  = "10.0.0.100",
    [string]$Username        = "epoadmin",
    [SecureString]$Password
)

if (-not $Password) { $Password = Read-Host "Enter ePO admin password" -AsSecureString }

$cred = New-Object PSCredential($Username, $Password)
$headers = @{ "Content-Type" = "application/json" }

# 1. List all Agent Handlers
Write-Host "Fetching all Agent Handlers..." -ForegroundColor Cyan
$ahList = Invoke-RestMethod -Uri "$EpoUrl/api/2.0/ah/list" -Method Get -Credential $cred -Headers $headers

# 2. Create AH Group (if it doesn't exist)
Write-Host "Creating/Updating AH Group: $GroupName" -ForegroundColor Cyan
$groupBody = @{
    name        = $GroupName
    description = "Automated Production AH Group with Load Balancer"
    enabled     = $true
} | ConvertTo-Json

$groupResponse = Invoke-RestMethod -Uri "$EpoUrl/api/2.0/ah/group/create" -Method Post -Credential $cred -Headers $headers -Body $groupBody

$groupId = $groupResponse.id

# 3. Add AHs to the group
foreach ($ahName in $AHNames) {
    $ah = $ahList | Where-Object { $_.name -eq $ahName }
    if ($ah) {
        $addBody = @{ ahId = $ah.id; groupId = $groupId } | ConvertTo-Json
        Invoke-RestMethod -Uri "$EpoUrl/api/2.0/ah/group/add" -Method Post -Credential $cred -Headers $headers -Body $addBody | Out-Null
        Write-Host "Added $ahName to group" -ForegroundColor Green
    }
}

# 4. Assign Load Balancer (Published DNS + IP)
$lbBody = @{
    groupId          = $groupId
    publishedDNSName = $LoadBalancerDNS
    publishedIP      = $LoadBalancerIP
    failoverEnabled  = $true
} | ConvertTo-Json

Invoke-RestMethod -Uri "$EpoUrl/api/2.0/ah/group/update" -Method Put -Credential $cred -Headers $headers -Body $lbBody | Out-Null

Write-Host "`nAH Group '$GroupName' created with Load Balancer $LoadBalancerDNS" -ForegroundColor Green
Write-Host "Log into ePO console → Configuration → Agent Handlers to verify." -ForegroundColor Yellow