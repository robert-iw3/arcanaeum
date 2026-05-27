<#
.SYNOPSIS
    Mass-deploy SuperAgent to thousands of endpoints via ePO REST API

.DESCRIPTION
    This script creates a SuperAgent policy in ePO and then creates a deployment task targeting a
    list of systems (from a CSV or array) to install SuperAgent. It uses the ePO REST API to automate
    the entire process, including policy creation and task execution. This is ideal for large-scale deployments
    where you want to quickly roll out SuperAgent to many endpoints without manual intervention.
    The script assumes you have already prepared a list of target systems (e.g., in a CSV file) and that you have
    the necessary permissions to create policies and tasks in ePO.

.PARAMETER EpoUrl
    The base URL of the ePO server (e.g., https://epo.contoso.local:8443)
.PARAMETER Username
    The ePO admin username for authentication.
.PARAMETER Password
    The ePO admin password for authentication (will be prompted if not provided).
.PARAMETER PolicyName
    The name of the SuperAgent policy to create or use.
.PARAMETER SystemNames
    An array of system names to target for SuperAgent deployment. Alternatively, you can use a CSV file with a "Name" column.

.EXAMPLE
    .\Deploy-SuperAgent-Mass.ps1 -EpoUrl "https://epo.contoso.local:8443" -Username "epoadmin" -PolicyName "SuperAgent-Production" -SystemNames @("host1.contoso.local", "host2.contoso.local")
    .\Deploy-SuperAgent-Mass.ps1 -EpoUrl "https://epo.contoso.local:8443" -Username "epoadmin" -PolicyName "SuperAgent-Production" -SystemNames (Import-Csv -Path "C:\Temp\systems-to-superagent.csv" | Select-Object -ExpandProperty Name)

.NOTES
    Author: Robert Weber
    Ensure you have the necessary permissions and that PowerShell remoting is enabled if running remotely.
    Test in a non-production environment first to validate functionality and avoid disruptions.
    The ePO REST API endpoints and payloads may vary based on your ePO version; refer to the official API documentation for details.
#>

param (
    [string]$EpoUrl          = "https://epo.contoso.local:8443",
    [string]$Username        = "epoadmin",
    [SecureString]$Password,
    [string]$PolicyName      = "SuperAgent-Production",
    [string[]]$SystemNames   = @()   # OR use a CSV: Import-Csv -Path systems.csv | Select -Expand Name
)

if (-not $Password) { $Password = Read-Host "Enter ePO password" -AsSecureString }
$cred = New-Object PSCredential($Username, $Password)

# 1. Create SuperAgent Policy (if it doesn't exist)
$policyBody = @{
    name = $PolicyName
    settings = @{
        superAgentEnabled      = $true
        wakeUpIntervalMinutes  = 60
        maxConcurrentTasks     = 75
        allowPushTasks         = $true
        useForRepositoryPulls  = $true
    }
} | ConvertTo-Json

Invoke-RestMethod -Uri "$EpoUrl/api/2.0/policy/create" -Method Post -Credential $cred -Body $policyBody -ContentType "application/json" | Out-Null

# 2. Get list of systems (or use your CSV)
if ($SystemNames.Count -eq 0) {
    $systems = Import-Csv -Path "C:\Temp\systems-to-superagent.csv" | Select-Object -ExpandProperty Name
} else {
    $systems = $SystemNames
}

# 3. Create deployment task
$taskBody = @{
    name           = "Mass SuperAgent Deployment"
    type           = "AgentDeployment"
    targets        = $systems
    policy         = $PolicyName
    forceInstall   = $true
    rebootIfNeeded = $false
} | ConvertTo-Json

$taskId = (Invoke-RestMethod -Uri "$EpoUrl/api/2.0/task/create" -Method Post -Credential $cred -Body $taskBody -ContentType "application/json").id

# 4. Execute the task immediately
Invoke-RestMethod -Uri "$EpoUrl/api/2.0/task/execute" -Method Post -Credential $cred -Body (@{taskId=$taskId} | ConvertTo-Json) -ContentType "application/json"

Write-Host "SuperAgent deployment task created and started for $($systems.Count) systems!" -ForegroundColor Green
Write-Host "Monitor progress in ePO console → Automation → Task Log" -ForegroundColor Yellow