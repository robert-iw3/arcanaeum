<#
.SYNOPSIS
    Automates CHECK and REMEDIATION for ALL rules in Microsoft Windows Defender Firewall with Advanced Security STIG V2R2
    (Benchmark Date: 09 Nov 2023 - Release 2)

    - 100% native PowerShell / .NET only
    - NO external modules, NO Import-Module, NO third-party tools
    - Uses only Get-ItemProperty / Set-ItemProperty (registry) + netsh.exe (built-in)
    - Automatically prefers the POLICY registry path (as recommended by STIG)
    - Falls back to the legacy local path if no policy key exists
    - Handles Domain-joined vs. Non-Domain NA conditions
    - Provides full compliance report + optional remediation

.PARAMETER Remediate
    If supplied, the script will automatically fix every non-compliant item.

.PARAMETER ReportOnly
    Only show the report (default behavior if -Remediate is not used).

.EXAMPLE
    .\WindowsDefenderFirewall-STIG-V2R2.ps1 -Remediate

.NOTES
    Author: Robert Weber
#>

param(
    [switch]$Remediate,
    [switch]$ReportOnly
)

$Host.UI.RawUI.WindowTitle = "Windows Defender Firewall STIG V2R2 Automation - Native PowerShell"

# =============================================
# HELPER FUNCTIONS
# =============================================
function Test-DomainJoined {
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        return $cs.PartOfDomain
    }
    catch { return $false }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        if (Test-Path $Path) {
            $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
            return $item.$Name
        }
    }
    catch {}
    return $null
}

function Set-RegValue {
    param([string]$Path, [string]$Name, [int]$Value)
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -Type DWord -Force
        return $true
    }
    catch {
        Write-Warning "Failed to set $Name at $Path"
        return $false
    }
}

function Run-Netsh {
    param([string]$Command)
    try {
        $output = & netsh.exe advfirewall $Command 2>&1
        return ($output -join "`n")
    }
    catch { return "ERROR: $($_.Exception.Message)" }
}

# =============================================
# STIG RULE DEFINITIONS
# =============================================
$rules = @(
    # V-241989 - Domain Profile Enabled
    [pscustomobject]@{
        VID           = "V-241989"
        Version       = "WNFWA-000001"
        Title         = "Windows Defender Firewall with Advanced Security must be enabled when connected to a domain."
        Profile       = "Domain"
        PolicyPath    = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
        LocalPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"
        ValueName     = "EnableFirewall"
        Expected      = 1
        NAIfNotDomain = $true
        NetshFix      = "set domainprofile state on"
    },
    # V-241990 - Private Profile Enabled
    [pscustomobject]@{
        VID           = "V-241990"
        Version       = "WNFWA-000002"
        Title         = "Windows Defender Firewall with Advanced Security must be enabled when connected to a private network."
        Profile       = "Private"
        PolicyPath    = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
        LocalPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"
        ValueName     = "EnableFirewall"
        Expected      = 1
        NAIfNotDomain = $false
        NetshFix      = "set privateprofile state on"
    },
    # V-241991 - Public Profile Enabled
    [pscustomobject]@{
        VID           = "V-241991"
        Version       = "WNFWA-000003"
        Title         = "Windows Defender Firewall with Advanced Security must be enabled when connected to a public network."
        Profile       = "Public"
        PolicyPath    = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
        LocalPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"
        ValueName     = "EnableFirewall"
        Expected      = 1
        NAIfNotDomain = $false
        NetshFix      = "set publicprofile state on"
    },
    # V-241992 - Domain Inbound Block (Default)
    [pscustomobject]@{
        VID           = "V-241992"
        Version       = "WNFWA-000004"
        Title         = "Windows Defender Firewall with Advanced Security must block unsolicited inbound connections when connected to a domain."
        Profile       = "Domain"
        PolicyPath    = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
        LocalPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"
        ValueName     = "DefaultInboundAction"
        Expected      = 1
        NAIfNotDomain = $true
        NetshFix      = "set domainprofile firewallpolicy blockinbound,allowoutbound"
    },
    # V-241993 - Domain Outbound Allow (Default)
    [pscustomobject]@{
        VID           = "V-241993"
        Version       = "WNFWA-000005"
        Title         = "Windows Defender Firewall with Advanced Security must allow outbound connections, unless a rule explicitly blocks the connection when connected to a domain."
        Profile       = "Domain"
        PolicyPath    = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
        LocalPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"
        ValueName     = "DefaultOutboundAction"
        Expected      = 0
        NAIfNotDomain = $true
        NetshFix      = "set domainprofile firewallpolicy blockinbound,allowoutbound"
    },
    # V-241994 - Domain Log Size >= 16KB
    [pscustomobject]@{
        VID           = "V-241994"
        Version       = "WNFWA-000009"
        Title         = "Windows Defender Firewall with Advanced Security log size must be configured for domain connections."
        Profile       = "Domain"
        PolicyPath    = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
        LocalPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging"
        ValueName     = "LogFileSize"
        Expected      = 16384   # minimum; greater is also compliant
        NAIfNotDomain = $true
        NetshFix      = "set domainprofile logging maxfilesize 16384"
    },
    # V-241995 - Domain Log Dropped Packets
    [pscustomobject]@{
        VID           = "V-241995"
        Version       = "WNFWA-000010"
        Title         = "Windows Defender Firewall with Advanced Security must log dropped packets when connected to a domain."
        Profile       = "Domain"
        PolicyPath    = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
        LocalPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging"
        ValueName     = "LogDroppedPackets"
        Expected      = 1
        NAIfNotDomain = $true
        NetshFix      = "set domainprofile logging droppedconnections enable"
    },
    # V-241996 - Domain Log Successful Connections
    [pscustomobject]@{
        VID           = "V-241996"
        Version       = "WNFWA-000011"
        Title         = "Windows Defender Firewall with Advanced Security must log successful connections when connected to a domain."
        Profile       = "Domain"
        PolicyPath    = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
        LocalPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging"
        ValueName     = "LogSuccessfulConnections"
        Expected      = 1
        NAIfNotDomain = $true
        NetshFix      = "set domainprofile logging allowedconnections enable"
    },
    # V-241997 - Private Inbound Block
    [pscustomobject]@{
        VID           = "V-241997"
        Version       = "WNFWA-000012"
        Title         = "Windows Defender Firewall with Advanced Security must block unsolicited inbound connections when connected to a private network."
        Profile       = "Private"
        PolicyPath    = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
        LocalPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"
        ValueName     = "DefaultInboundAction"
        Expected      = 1
        NAIfNotDomain = $false
        NetshFix      = "set privateprofile firewallpolicy blockinbound,allowoutbound"
    },
    # V-241998 - Private Outbound Allow
    [pscustomobject]@{
        VID           = "V-241998"
        Version       = "WNFWA-000013"
        Title         = "Windows Defender Firewall with Advanced Security must allow outbound connections, unless a rule explicitly blocks the connection when connected to a private network."
        Profile       = "Private"
        PolicyPath    = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
        LocalPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"
        ValueName     = "DefaultOutboundAction"
        Expected      = 0
        NAIfNotDomain = $false
        NetshFix      = "set privateprofile firewallpolicy blockinbound,allowoutbound"
    },
    # V-241999 - Private Log Size
    [pscustomobject]@{
        VID           = "V-241999"
        Version       = "WNFWA-000017"
        Title         = "Windows Defender Firewall with Advanced Security log size must be configured for private network connections."
        Profile       = "Private"
        PolicyPath    = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
        LocalPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging"
        ValueName     = "LogFileSize"
        Expected      = 16384
        NAIfNotDomain = $false
        NetshFix      = "set privateprofile logging maxfilesize 16384"
    },
    # V-242000 - Private Log Dropped
    [pscustomobject]@{
        VID           = "V-242000"
        Version       = "WNFWA-000018"
        Title         = "Windows Defender Firewall with Advanced Security must log dropped packets when connected to a private network."
        Profile       = "Private"
        PolicyPath    = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
        LocalPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging"
        ValueName     = "LogDroppedPackets"
        Expected      = 1
        NAIfNotDomain = $false
        NetshFix      = "set privateprofile logging droppedconnections enable"
    },
    # V-242001 - Private Log Successful
    [pscustomobject]@{
        VID           = "V-242001"
        Version       = "WNFWA-000019"
        Title         = "Windows Defender Firewall with Advanced Security must log successful connections when connected to a private network."
        Profile       = "Private"
        PolicyPath    = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
        LocalPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging"
        ValueName     = "LogSuccessfulConnections"
        Expected      = 1
        NAIfNotDomain = $false
        NetshFix      = "set privateprofile logging allowedconnections enable"
    },
    # V-242002 - Public Inbound Block
    [pscustomobject]@{
        VID           = "V-242002"
        Version       = "WNFWA-000020"
        Title         = "Windows Defender Firewall with Advanced Security must block unsolicited inbound connections when connected to a public network."
        Profile       = "Public"
        PolicyPath    = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
        LocalPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"
        ValueName     = "DefaultInboundAction"
        Expected      = 1
        NAIfNotDomain = $false
        NetshFix      = "set publicprofile firewallpolicy blockinbound,allowoutbound"
    },
    # V-242003 - Public Outbound Allow
    [pscustomobject]@{
        VID           = "V-242003"
        Version       = "WNFWA-000021"
        Title         = "Windows Defender Firewall with Advanced Security must allow outbound connections, unless a rule explicitly blocks the connection when connected to a public network."
        Profile       = "Public"
        PolicyPath    = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
        LocalPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"
        ValueName     = "DefaultOutboundAction"
        Expected      = 0
        NAIfNotDomain = $false
        NetshFix      = "set publicprofile firewallpolicy blockinbound,allowoutbound"
    },
    # V-242004 - Public Do NOT merge local firewall rules
    [pscustomobject]@{
        VID           = "V-242004"
        Version       = "WNFWA-000024"
        Title         = "Windows Defender Firewall with Advanced Security local firewall rules must not be merged with Group Policy settings when connected to a public network."
        Profile       = "Public"
        PolicyPath    = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
        LocalPath     = $null
        ValueName     = "AllowLocalPolicyMerge"
        Expected      = 0
        NAIfNotDomain = $true   # STIG says NA for non-domain
        NetshFix      = $null
    },
    # V-242005 - Public Do NOT merge local IPsec rules
    [pscustomobject]@{
        VID           = "V-242005"
        Version       = "WNFWA-000025"
        Title         = "Windows Defender Firewall with Advanced Security local connection rules must not be merged with Group Policy settings when connected to a public network."
        Profile       = "Public"
        PolicyPath    = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
        LocalPath     = $null
        ValueName     = "AllowLocalIPsecPolicyMerge"
        Expected      = 0
        NAIfNotDomain = $true
        NetshFix      = $null
    },
    # V-242006 - Public Log Size
    [pscustomobject]@{
        VID           = "V-242006"
        Version       = "WNFWA-000027"
        Title         = "Windows Defender Firewall with Advanced Security log size must be configured for public network connections."
        Profile       = "Public"
        PolicyPath    = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
        LocalPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging"
        ValueName     = "LogFileSize"
        Expected      = 16384
        NAIfNotDomain = $false
        NetshFix      = "set publicprofile logging maxfilesize 16384"
    },
    # V-242007 - Public Log Dropped
    [pscustomobject]@{
        VID           = "V-242007"
        Version       = "WNFWA-000028"
        Title         = "Windows Defender Firewall with Advanced Security must log dropped packets when connected to a public network."
        Profile       = "Public"
        PolicyPath    = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
        LocalPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging"
        ValueName     = "LogDroppedPackets"
        Expected      = 1
        NAIfNotDomain = $false
        NetshFix      = "set publicprofile logging droppedconnections enable"
    },
    # V-242008 - Public Log Successful
    [pscustomobject]@{
        VID           = "V-242008"
        Version       = "WNFWA-000029"
        Title         = "Windows Defender Firewall with Advanced Security must log successful connections when connected to a public network."
        Profile       = "Public"
        PolicyPath    = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
        LocalPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging"
        ValueName     = "LogSuccessfulConnections"
        Expected      = 1
        NAIfNotDomain = $false
        NetshFix      = "set publicprofile logging allowedconnections enable"
    },
    # V-242009 - Inbound exceptions limited to authorized hosts (manual review + netsh dump)
    [pscustomobject]@{
        VID           = "V-242009"
        Version       = "WNFWA-000100"
        Title         = "Inbound exceptions to the firewall on domain workstations must only allow authorized remote management hosts."
        Profile       = "N/A"
        PolicyPath    = $null
        LocalPath     = $null
        ValueName     = $null
        Expected      = $null
        NAIfNotDomain = $false
        NetshFix      = $null
    }
)

# =============================================
# MAIN EXECUTION
# =============================================
$isDomainJoined = Test-DomainJoined
Write-Host "Domain Joined: $isDomainJoined" -ForegroundColor Cyan
Write-Host "Remediation Mode: $($Remediate.IsPresent)`n" -ForegroundColor Yellow

$report = @()

foreach ($rule in $rules) {
    $status = "N/A"
    $details = ""

    # Special handling for V-242009 (manual + dump inbound rules)
    if ($rule.VID -eq "V-242009") {
        Write-Host "[$($rule.VID)] $($rule.Title)" -ForegroundColor White
        Write-Host "   Dumping all inbound rules for manual review (STIG requires authorized management hosts only)..." -ForegroundColor Gray
        $inboundRules = Run-Netsh -Command "firewall show rule name=all dir=in"
        $report += [pscustomobject]@{
            RuleID  = $rule.VID
            Version = $rule.Version
            Title   = $rule.Title
            Status  = "MANUAL REVIEW REQUIRED"
            Details = "Review output below. Ensure inbound exceptions are limited to authorized remote management hosts."
        }
        Write-Host $inboundRules -ForegroundColor DarkGray
        continue
    }

    # Skip Domain rules on non-domain systems
    if ($rule.NAIfNotDomain -and -not $isDomainJoined) {
        $report += [pscustomobject]@{
            RuleID  = $rule.VID
            Version = $rule.Version
            Title   = $rule.Title
            Status  = "N/A (Non-domain)"
            Details = "Domain Profile rule - system is not domain-joined"
        }
        continue
    }

    # Get current value (policy path first, then local fallback)
    $current = Get-RegValue -Path $rule.PolicyPath -Name $rule.ValueName
    $source = "POLICY"
    if ($null -eq $current -and $rule.LocalPath) {
        $current = Get-RegValue -Path $rule.LocalPath -Name $rule.ValueName
        $source = "LOCAL"
    }

    # Log size rules are ">= Expected"
    if ($rule.ValueName -eq "LogFileSize") {
        $compliant = ($current -ge $rule.Expected)
    }
    else {
        $compliant = ($current -eq $rule.Expected)
    }

    if ($compliant) {
        $status = "Compliant"
        $details = "$source value = $current (expected $($rule.Expected))"
    }
    else {
        $status = "Non-Compliant"
        $details = "$source value = $current (expected $($rule.Expected))"

        if ($Remediate) {
            if ($rule.PolicyPath) {
                $fixed = Set-RegValue -Path $rule.PolicyPath -Name $rule.ValueName -Value $rule.Expected
                if ($fixed) {
                    $status = "REMEDIATED (Policy key set)"
                    $details += " → Fixed via registry policy path"
                }
            }
            if (-not $fixed -and $rule.NetshFix) {
                $netshOut = Run-Netsh -Command $rule.NetshFix
                $status = "REMEDIATED (netsh)"
                $details += " → Fixed via netsh: $($rule.NetshFix)"
            }
        }
    }

    $report += [pscustomobject]@{
        RuleID  = $rule.VID
        Version = $rule.Version
        Title   = $rule.Title
        Status  = $status
        Details = $details
    }
}

# =============================================
# FINAL REPORT
# =============================================
Write-Host "`n" + "="*80 -ForegroundColor Green
Write-Host "WINDOWS DEFENDER FIREWALL STIG V2R2 COMPLIANCE REPORT" -ForegroundColor Green
Write-Host "="*80 -ForegroundColor Green

$report | Sort-Object RuleID | Format-Table -AutoSize -Property RuleID, Version, Status, Details

if ($Remediate) {
    Write-Host "`nREMEDIATION COMPLETE" -ForegroundColor Yellow
    Write-Host "Some changes require a reboot or firewall service restart." -ForegroundColor Yellow
    Write-Host "Run 'Restart-Service -Name mpssvc' to apply immediately." -ForegroundColor Yellow
}

Write-Host "`nScript finished at $(Get-Date)" -ForegroundColor Cyan