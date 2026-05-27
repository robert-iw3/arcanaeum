<#
.SYNOPSIS
    Expanded Server-Side Diagnostics (Bindings + Hardening Breakage Detector)
.DESCRIPTION
    This script performs expanded server-side diagnostics for IIS/SSL issues, including:
    1. Port 443 ownership and http.sys binding checks
    2. Scanning HTTP.sys error logs for signs of legitimate traffic being dropped due to hardened request limits
    3. Auditing Application Pool identities for security best practices
    4. Checking System Event Logs for recent Schannel or HttpEvent errors and verifying strict cipher suite registry settings
    The script provides detailed output and logs all results to a timestamped log file for further analysis.
.NOTES
    Author: RW
#>

$logPath = ".\ServerSide_Diag_Expanded_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param ([string]$Message, [ConsoleColor]$Color = "Gray")
    Write-Host $Message -ForegroundColor $Color
    Add-Content -Path $logPath -Value "[$((Get-Date).ToString('HH:mm:ss'))] $Message"
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] Must run as Administrator." -ForegroundColor Red; exit
}

Write-Log "===========================================================" "Cyan"
Write-Log " Starting Expanded Server-Side Diagnostics" "Cyan"
Write-Log "===========================================================" "Cyan"

# 1. Port 443 & Binding Checks
Write-Log "`n[Step 1] Checking Port 443 & http.sys bindings..." "Yellow"
$port443 = Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue
if ($port443.OwningProcess -contains 4) { Write-Log "[SUCCESS] Port 443 owned by System (http.sys)." "Green" }
else { Write-Log "[CRITICAL] Port 443 is hijacked or not listening!" "Red" }

$netshOutput = netsh http show sslcert
if ($netshOutput -match "Certificate Hash") { Write-Log "[SUCCESS] Kernel SSL bindings found." "Green" }
else { Write-Log "[CRITICAL] No SSL bindings found in http.sys!" "Red" }

# 2. Check HTTP.sys Error Logs for Request Filtering Drops
Write-Log "`n[Step 2] Scanning HTTP.sys Logs for blocked legitimate traffic (Last 1000 entries)..." "Yellow"
$latestLog = Get-ChildItem -Path "C:\Windows\System32\LogFiles\HTTPERR" -Filter "httperr*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($latestLog) {
    $errors = Get-Content $latestLog.FullName -Tail 1000 | Where-Object { $_ -match "UrlLength|FieldLength|MaxRequestBytes" }
    if ($errors) {
        Write-Log "[WARNING] IIS kernel is dropping traffic due to Hardened Request Limits!" "Red"
        $errors | Select-Object -Last 3 | ForEach-Object { Write-Log "  -> Blocked: $_" "Magenta" }
    } else { Write-Log "[PASS] No recent traffic dropped by HTTP.sys limitations." "Green" }
}

# 3. Check AppPool Identities
Write-Log "`n[Step 3] Auditing Application Pool Identities..." "Yellow"
Import-Module WebAdministration
foreach ($pool in Get-ChildItem IIS:\AppPools) {
    if ($pool.processModel.identityType -ne "ApplicationPoolIdentity") {
        Write-Log "[WARNING] AppPool '$($pool.Name)' runs as '$($pool.processModel.identityType)'. Hardening expects ApplicationPoolIdentity." "Yellow"
    } else { Write-Log "[PASS] AppPool '$($pool.Name)' secured via ApplicationPoolIdentity." "Green" }
}

# 4. Check Event Logs & Registry
Write-Log "`n[Step 4] Checking System Event Log & Cipher Registry..." "Yellow"
$events = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Schannel','Microsoft-Windows-HttpEvent'; Level=2,3; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue | Select-Object -First 5
if ($events) { Write-Log "[WARNING] Found recent SSL/TLS kernel errors (Check Event ID 36870 or 15021)." "Red" }
else { Write-Log "[PASS] No recent Schannel or HttpEvent errors." "Green" }

$ciphers = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name Functions -ErrorAction SilentlyContinue).Functions
if ($ciphers -match "TLS_ECDHE") { Write-Log "[PASS] Strict Cipher Suite ordering is enforced in Registry." "Green" }
else { Write-Log "[FAIL] Custom cipher suite ordering not found." "Red" }

Write-Log "`n=== Server Diagnostics Complete ===" "Cyan"