<#
.SYNOPSIS
    Server-Side Diagnostics for IIS/SSL Issues with Remediation Guidance
.DESCRIPTION
    This script performs server-side diagnostics for IIS/SSL issues and provides remediation guidance.
    It checks for:
    1. Port 443 ownership (looking for http.sys / PID 4)
    2. Kernel-level SSL bindings using netsh
    3. Orphaned certificate bindings
    4. Recent Schannel and HttpEvent errors in the System Event Log
    Each step includes detailed remediation instructions if issues are detected.
.NOTES
    Author: RW
#>

# --- Configuration ---
$logPath = ".\IIS_ServerSide_Diag_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# --- Logging Function ---
function Write-Log {
    param (
        [string]$Message,
        [ConsoleColor]$Color = "Gray"
    )
    Write-Host $Message -ForegroundColor $Color
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logPath -Value "[$timestamp] $Message"
}

# --- Admin Check ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] This script requires Administrator privileges. Please restart PowerShell as Admin and try again." -ForegroundColor Red
    exit
}

Write-Log "===========================================================" "Cyan"
Write-Log " Starting Server-Side IIS/SSL Diagnostics with Remediation" "Cyan"
Write-Log " Log File: $logPath" "Cyan"
Write-Log "===========================================================" "Cyan"

# 1. Port 443 Ownership Check
Write-Log "`n[Step 1] Checking Port 443 Ownership (Looking for http.sys / PID 4)..." "Yellow"
$port443 = Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue

if ($port443) {
    foreach ($conn in $port443) {
        $pidOwner = $conn.OwningProcess
        if ($pidOwner -eq 4) {
            Write-Log "[SUCCESS] Port 443 on $($conn.LocalAddress) is listening and owned by PID 4 (System/http.sys)." "Green"
        } else {
            try {
                $processName = (Get-Process -Id $pidOwner).ProcessName
                Write-Log "[CRITICAL] Port 443 is hijacked by PID $pidOwner ($processName)!" "Red"
                Write-Log "  [REMEDIATION]: IIS cannot serve HTTPS because '$processName' is using port 443." "Cyan"
                Write-Log "  -> Fix: Open Services.msc or Task Manager, stop the '$processName' service/process. If it is required (e.g., VMware, Skype), reconfigure it to use a different port, then restart IIS by running 'iisreset' in an admin prompt." "Cyan"
            } catch {
                Write-Log "[CRITICAL] Port 443 is owned by an unknown process (PID $pidOwner). Not IIS!" "Red"
            }
        }
    }
} else {
    Write-Log "[FAILURE] No process is currently listening on Port 443." "Red"
    Write-Log "  [REMEDIATION]: Open IIS Manager. Select your Site -> click 'Bindings...' on the right. Ensure there is an 'https' binding assigned to port 443 and that the Site is 'Started'." "Cyan"
}

# 2. Kernel-Level SSL Bindings (netsh)
Write-Log "`n[Step 2] Querying http.sys for SSL Bindings..." "Yellow"
$netshOutput = netsh http show sslcert

$bindingsFound = $false
foreach ($line in $netshOutput) {
    if ($line -match "Hostname:port" -or $line -match "IP:port") {
        Write-Log "  -> Binding Found: $($line.Trim())" "DarkGray"
        $bindingsFound = $true
    }
    if ($line -match "Certificate Hash") {
        Write-Log "     $($line.Trim())" "DarkGray"
    }
}

if (-not $bindingsFound) {
    Write-Log "[CRITICAL] No SSL bindings found at the kernel level!" "Red"
    Write-Log "  [REMEDIATION]: IIS might show a binding, but the Windows kernel (http.sys) doesn't have it." "Cyan"
    Write-Log "  -> Fix: Open IIS Manager -> Sites -> Select your Website -> 'Bindings...'. Edit the port 443 binding, re-select your SSL certificate from the dropdown, and click OK. This forces IIS to push the config back to the kernel." "Cyan"
}

# 3. Check for Orphaned Certificates
Write-Log "`n[Step 3] Cross-referencing HTTP.sys bindings with Local Certificate Store..." "Yellow"
$storeCerts = Get-ChildItem -Path Cert:\LocalMachine\My | Select-Object Thumbprint, Subject

$boundHashes = $netshOutput | Where-Object { $_ -match "Certificate Hash\s+:\s+([a-fA-F0-9]+)" } | ForEach-Object { $matches[1] }

if ($boundHashes) {
    foreach ($hash in $boundHashes) {
        $match = $storeCerts | Where-Object { $_.Thumbprint -eq $hash }
        if ($match) {
            Write-Log "[SUCCESS] Certificate Hash $hash exists in Local Machine store. Subject: $($match.Subject)" "Green"
        } else {
            Write-Log "[CRITICAL] Orphaned Binding! Hash $hash is bound to a port, but the certificate is MISSING from the store!" "Red"
            Write-Log "  [REMEDIATION]: The kernel is trying to use a deleted certificate, causing an instant ERR_CONNECTION_RESET." "Cyan"
            Write-Log "  -> Fix: Open IIS Manager -> Sites -> Select your Website -> 'Bindings...'. Delete the broken HTTPS binding entirely, then recreate it using a valid certificate currently installed on the server." "Cyan"
        }
    }
}

# 4. Check Event Logs for Fatal Handshake Errors
Write-Log "`n[Step 4] Scanning System Event Log for Schannel & HttpEvent errors (Last 24 Hours)..." "Yellow"
$startTime = (Get-Date).AddHours(-24)
$events = Get-WinEvent -FilterHashtable @{
    LogName='System'
    ProviderName='Schannel','Microsoft-Windows-HttpEvent'
    Level=2,3 # Errors and Warnings
    StartTime=$startTime
} -ErrorAction SilentlyContinue | Select-Object -First 15

if ($events) {
    Write-Log "[WARNING] Found recent SSL/TLS kernel errors:" "Yellow"
    foreach ($event in $events) {
        Write-Log "  -> [$($event.TimeCreated)] [$($event.ProviderName) - ID $($event.Id)]: $($event.Message)" "Magenta"

        # Specific Remediation based on Event ID
        if ($event.Id -eq 36870) {
            Write-Log "     [REMEDIATION for Schannel 36870 - Permission Denied]:" "Cyan"
            Write-Log "     -> Fix: Open MMC -> File -> Add/Remove Snap-in -> Certificates -> Computer Account -> Local Computer. Go to Personal -> Certificates. Right-click your SSL cert -> All Tasks -> Manage Private Keys. Grant 'Read' access to 'IIS_IUSRS' and 'NETWORK SERVICE'." "Cyan"
        }
        if ($event.Id -eq 15021) {
            Write-Log "     [REMEDIATION for HttpEvent 15021 - Corrupt Binding]:" "Cyan"
            Write-Log "     -> Fix: Open IIS Manager, edit the site's HTTPS binding, select a different (dummy) certificate, hit OK. Then edit it again and select the correct certificate. This rewrites the corrupted binding in the kernel." "Cyan"
        }
    }
} else {
    Write-Log "[SUCCESS] No recent Schannel or HttpEvent errors found in the System log." "Green"
}

Write-Log "`n===========================================================" "Cyan"
Write-Log " Diagnostics & Remediation Complete. Review log at: $logPath" "Cyan"
Write-Log "===========================================================" "Cyan"