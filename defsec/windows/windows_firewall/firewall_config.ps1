<#
    Windows Firewall PowerShell Script
    switches: dry-run, backup/restore, validation (with IPv6), profiles, template gen, interactive wizard, netsh fallback, parallel checks (configurable).
    Usage Examples:
    .\firewall_config.ps1 -CsvPath "firewall_rules.csv" -DryRun -MaxJobs 5
    .\firewall_config.ps1 -Interactive -GenerateTemplate
    .\firewall_config.ps1 -RestoreBackup

    Updated 9/28/2025: Handles -RemotePort for Outbound rules (integrates with baseline monitoring CSV).

#>

param (
    [string]$CsvPath = "firewall_rules.csv",
    [switch]$DryRun,
    [switch]$SkipDenyDefault,
    [switch]$RestoreBackup,
    [switch]$GenerateTemplate,
    [switch]$Interactive,
    [string]$BackupPath = "firewall_backup.xml",
    [string]$LogPath = "firewall_log.txt",
    [int]$MaxJobs = 10
)

function Log-Message {
    param ([string]$Message, [string]$Color = "White")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -Append -FilePath $LogPath
    Write-Host $Message -ForegroundColor $Color
}

# Check admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Log-Message "Run as Administrator." "Red"
    exit
}

# OS detection for compatibility
$osVersion = [System.Environment]::OSVersion.Version
$useNetsh = $osVersion.Major -lt 6 -or ($osVersion.Major -eq 6 -and $osVersion.Minor -lt 2)  # Pre-Win8

if ($RestoreBackup) {
    if (Test-Path $BackupPath) {
        Log-Message "Restoring from $BackupPath" "Cyan"
        if (!$useNetsh) {
            Import-NetFirewallRule -Path $BackupPath
        } else {
            netsh advfirewall import "$BackupPath"
        }
        Log-Message "Restore complete." "Green"
    } else {
        Log-Message "No backup found." "Red"
    }
    exit
}

if ($GenerateTemplate) {
    $template = @"
rule_name,direction,port,protocol,remote_address,action,profile
00_FW_HTTP_INBOUND_ALLOW,Inbound,80,TCP,192.168.100.0/24,Allow,Any
01_FW_HTTPS_INBOUND_ALLOW,Inbound,443,TCP,192.168.100.0/24,Allow,Any
02_FW_SSH_INBOUND_ALLOW,Inbound,22,TCP,192.168.100.0/24,Allow,Any
"@
    $template | Out-File -FilePath $CsvPath
    Log-Message "Template generated at $CsvPath" "Green"
    exit
}

if ($Interactive) {
    Log-Message "Interactive mode: Enter rules (blank rule_name to exit)."
    $newRules = @()
    while ($true) {
        $ruleName = Read-Host "Rule Name (e.g., FW_HTTP_IN)"
        if (!$ruleName) { break }
        $direction = Read-Host "Direction (Inbound/Outbound)"
        $port = Read-Host "Port (e.g., 80)"
        $protocol = Read-Host "Protocol (TCP/UDP/Any)"
        $remoteAddr = Read-Host "Remote Address (IP or subnet, IPv4/IPv6)"
        $action = Read-Host "Action (Allow/Block)"
        $profile = Read-Host "Profile (Any/Domain/Private/Public)"
        $newRules += "$ruleName,$direction,$port,$protocol,$remoteAddr,$action,$profile"
    }
    if ($newRules.Count -gt 0) {
        $newRules -join "`n" | Add-Content -Path $CsvPath
        Log-Message "Added $($newRules.Count) rules to $CsvPath" "Green"
    }
}

# Backup current rules
Log-Message "Backing up rules to $BackupPath" "Cyan"
if (!$useNetsh) {
    Export-NetFirewallRule -Path $BackupPath
} else {
    netsh advfirewall export "$BackupPath"
}

# Load and validate rules
$rules = Import-Csv -Path $CsvPath
$requiredHeaders = @('rule_name', 'direction', 'port', 'protocol', 'remote_address', 'action', 'profile')
if (-not ($requiredHeaders | ForEach-Object { $rules[0].PSObject.Properties.Name -contains $_ })) {
    Log-Message "Invalid CSV headers. Required: $($requiredHeaders -join ', ')" "Red"
    exit
}

$validProtocols = @("TCP", "UDP", "Any")
$validActions = @("Allow", "Block")
$validProfiles = @("Any", "Domain", "Private", "Public")
# Updated regex for IPv4 and basic IPv6
$ipRegex = '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(/(3[0-2]|[12]?[0-9]))?$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(/([0-9]|[1-9][0-9]|1[0-2][0-8]))?$'

$jobs = @()
foreach ($rule in $rules) {
    # Validation
    if ($rule.port -ne "Any" -and ([int]$rule.port -lt 1 -or [int]$rule.port -gt 65535)) { Log-Message "Invalid port: $($rule.port)" "Red"; continue }
    if ($validProtocols -notcontains $rule.protocol) { Log-Message "Invalid protocol: $($rule.protocol)" "Red"; continue }
    if ($validActions -notcontains $rule.action) { Log-Message "Invalid action: $($rule.action)" "Red"; continue }
    if ($validProfiles -notcontains $rule.profile) { Log-Message "Invalid profile: $($rule.profile)" "Red"; continue }
    if ($rule.remote_address -ne "Any" -and $rule.remote_address -notmatch $ipRegex) { Log-Message "Invalid IP/subnet (IPv4/IPv6): $($rule.remote_address)" "Red"; continue }

    $jobs += Start-Job -ScriptBlock {
        param($displayName, $useNetsh)
        if (!$useNetsh) {
            return (Get-NetFirewallRule -DisplayName $displayName -ErrorAction SilentlyContinue) -ne $null
        } else {
            $output = netsh advfirewall firewall show rule name="`"$displayName`""
            # Regex for localized robustness
            return $output -match "(?i)Rule Name:\s+$([regex]::Escape($displayName))"
        }
    } -ArgumentList $rule.rule_name, $useNetsh
    if ($jobs.Count -ge $MaxJobs) {
        Wait-Job -Job $jobs | Out-Null  # Throttle
    }
}

# Wait for remaining jobs
Wait-Job -Job $jobs | Out-Null

$existingRules = @{}
$i = 0
foreach ($job in $jobs) {
    try {
        $result = Receive-Job -Job $job
        $existingRules[$rules[$i].rule_name] = $result
    } catch {
        Log-Message "Job error: $_" "Red"
    }
    Remove-Job -Job $job
    $i++
}

foreach ($rule in $rules) {
    $displayName = $rule.rule_name
    if ($existingRules[$displayName]) {
        Log-Message "Skipping existing: $displayName" "Yellow"
        continue
    }

    if ($DryRun) {
        Log-Message "[DryRun] Would create: $displayName Direction=$($rule.direction) Port=$($rule.port) Protocol=$($rule.protocol) Remote=$($rule.remote_address) Action=$($rule.action) Profile=$($rule.profile)" "Magenta"
        continue
    }

    try {
        if (!$useNetsh) {
            $portParam = if ($rule.direction -eq "Outbound") { @{RemotePort = $rule.port} } else { @{LocalPort = $rule.port} }
            New-NetFirewallRule -DisplayName $displayName -Direction $rule.direction @portParam -Protocol $rule.protocol -RemoteAddress $rule.remote_address -Action $rule.action -Profile $rule.profile
        } else {
            $dir = if ($rule.direction -eq "Inbound") {"in"} else {"out"}
            $act = $rule.action.ToLower()
            $prof = $rule.profile.ToLower()
            $portType = if ($rule.direction -eq "Outbound") {"remoteport"} else {"localport"}
            netsh advfirewall firewall add rule name="`"$displayName`"" dir=$dir protocol=$($rule.protocol) $portType=$($rule.port) remoteip=$($rule.remote_address) action=$act profile=$prof
        }
        Log-Message "Created: $displayName" "Green"
    } catch {
        Log-Message "Error: $_" "Red"
    }
}

if (!$SkipDenyDefault -and !$DryRun) {
    $denyInboundName = "Deny All Inbound"
    if (!$existingRules[$denyInboundName]) {
        if (!$useNetsh) {
            New-NetFirewallRule -DisplayName $denyInboundName -Direction Inbound -Action Block -Profile Any
        } else {
            netsh advfirewall firewall add rule name="`"$denyInboundName`"" dir=in action=block profile=any
        }
        Log-Message "Deny Inbound created." "Green"
    }
    $denyOutboundName = "Deny All Outbound"
    if (!$existingRules[$denyOutboundName]) {
        if (!$useNetsh) {
            New-NetFirewallRule -DisplayName $denyOutboundName -Direction Outbound -Action Block -Profile Any
        } else {
            netsh advfirewall firewall add rule name="`"$denyOutboundName`"" dir=out action=block profile=any
        }
        Log-Message "Deny Outbound created." "Green"
    }
}

Log-Message "Script complete." "Blue"