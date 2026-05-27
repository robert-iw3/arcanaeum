<#
.SYNOPSIS
    Expanded Client-Side Diagnostics (Connectivity + Hardening Audit)
.DESCRIPTION
    This script performs expanded client-side diagnostics for IIS applications, including:
    1. DNS resolution and basic TCP connectivity checks
    2. A raw SSL/TLS handshake test to detect if the server is responding to SSL requests or if connections are being dropped due to hardening
    3. An audit of HTTP security headers to verify hardening best practices
    4. A probe for IIS request filtering by attempting a TRACE request
    The script provides detailed output and logs all results to a timestamped log file for further analysis.
.NOTES
    Author: RW
#>

$targetHost = "your-private-app-hostname" # Replace with your app's URL or IP
$ports = @(80, 443)
$logPath = ".\Client_Diag_Expanded_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param ([string]$Message, [ConsoleColor]$Color = "Gray")
    Write-Host $Message -ForegroundColor $Color
    Add-Content -Path $logPath -Value "[$((Get-Date).ToString('HH:mm:ss'))] $Message"
}

Write-Log "===========================================================" "Cyan"
Write-Log " Starting Expanded Client-Side Diagnostics for $targetHost" "Cyan"
Write-Log "===========================================================" "Cyan"

# 0. DNS & TCP Checks
Write-Log "`n[Step 0 & 1] Checking DNS & TCP Connectivity..." "Yellow"
try {
    $ipAddresses = [System.Net.Dns]::GetHostAddresses($targetHost)
    Write-Log "[SUCCESS] Resolved $targetHost." "Green"
} catch {
    Write-Log "[ERROR] Could not resolve $targetHost." "Red"; exit
}
foreach ($port in $ports) {
    if (Test-NetConnection -ComputerName $targetHost -Port $port -InformationLevel Quiet) {
        Write-Log "[SUCCESS] TCP Port $port is OPEN." "Green"
    } else { Write-Log "[FAILURE] TCP Port $port is CLOSED/BLOCKED." "Red" }
}

# 2. Raw SSL/TLS Handshake & Hardening Verification
Write-Log "`n[Step 2] Testing Raw SSL/TLS Strictness..." "Yellow"
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
$tcpClient = New-Object System.Net.Sockets.TcpClient
try {
    $tcpClient.Connect($targetHost, 443)
    $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, {param($s, $c, $ch, $e) return $true})
    $sslStream.AuthenticateAsClient($targetHost)
    Write-Log "[SUCCESS] Handshake complete. Negotiated: $($sslStream.SslProtocol) / $($sslStream.CipherAlgorithm)" "Green"
} catch {
    Write-Log "[CRITICAL] SSL Handshake Failed! Connection Reset or Protocol Mismatch." "Red"
    Write-Log "  -> If the hardening script was applied, legacy clients may be blocked due to AES128 or TLS 1.0/1.1 disabled." "Magenta"
} finally { if ($tcpClient.Connected) { $tcpClient.Close() } }

# 3. Security Header Audit
Write-Log "`n[Step 3] Auditing HTTP Security Headers..." "Yellow"
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $webRequest = Invoke-WebRequest -Uri "https://$targetHost" -UseBasicParsing -TimeoutSec 10
    $headers = $webRequest.Headers

    $expectedHeaders = @("Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy", "Referrer-Policy")
    foreach ($h in $expectedHeaders) {
        if ($headers.ContainsKey($h)) { Write-Log "[PASS] Found $h" "Green" }
        else { Write-Log "[FAIL] Missing Hardened Header: $h" "Red" }
    }
    if ($headers.ContainsKey("Server") -or $headers.ContainsKey("X-Powered-By")) {
         Write-Log "[FAIL] Information Disclosure: Server or X-Powered-By headers are exposed." "Red"
    } else { Write-Log "[PASS] Server and X-Powered-By headers are hidden." "Green" }
} catch { Write-Log "[ERROR] HTTP request failed: $($_.Exception.Message)" "Yellow" }

# 4. Request Filtering Probe
Write-Log "`n[Step 4] Probing IIS Request Filtering (TRACE verb block)..." "Yellow"
try {
    $traceRequest = Invoke-WebRequest -Uri "https://$targetHost" -Method Trace -UseBasicParsing -ErrorAction Stop
    Write-Log "[FAIL] TRACE verb was allowed! Request filtering is misconfigured." "Red"
} catch {
    if ($_.Exception.Response.StatusCode -match "MethodNotAllowed|NotFound") {
        Write-Log "[PASS] TRACE verb successfully blocked by IIS ($($_.Exception.Response.StatusCode))." "Green"
    } else { Write-Log "[WARNING] TRACE failed with unexpected error: $($_.Exception.Message)" "Yellow" }
}

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
Write-Log "`n=== Diagnostics Complete. Review $logPath ===" "Cyan"