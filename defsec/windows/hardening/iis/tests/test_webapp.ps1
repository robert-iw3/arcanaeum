<#
.SYNOPSIS
    Advanced IIS Connectivity Diagnostics
.DESCRIPTION
    This script performs advanced connectivity diagnostics for IIS applications.
    It checks for:
    1. DNS resolution of the target hostname
    2. Basic TCP connectivity on ports 80 and 443
    3. A raw SSL/TLS handshake test on port 443 to detect if the server is responding to SSL requests or if the connection is being dropped by http.sys.
    The script provides detailed output and logs all results to a timestamped log file for further analysis.
.NOTES
    Author: RW
#>

# --- Configuration ---
$targetHost = "your-private-app-hostname" # Replace with your app's URL or IP
$ports = @(80, 443)
$logPath = ".\IIS_Connectivity_Diag_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# --- Logging Function ---
function Write-Log {
    param (
        [string]$Message,
        [ConsoleColor]$Color = "Gray"
    )
    # 1. Output to console with the specified color
    Write-Host $Message -ForegroundColor $Color

    # 2. Output to the log file with a timestamp (stripping color metadata)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logPath -Value "[$timestamp] $Message"
}

Write-Log "===========================================================" "Cyan"
Write-Log " Starting Advanced IIS Connectivity Diagnostics" "Cyan"
Write-Log " Target: $targetHost" "Cyan"
Write-Log " Log File: $logPath" "Cyan"
Write-Log "===========================================================" "Cyan"

# 0. DNS Resolution Check
Write-Log "`n[Step 0] Checking DNS Resolution..." "Yellow"
try {
    $ipAddresses = [System.Net.Dns]::GetHostAddresses($targetHost)
    Write-Log "[SUCCESS] Resolved $targetHost to: $($ipAddresses.IPAddressToString -join ', ')" "Green"
} catch {
    Write-Log "[ERROR] Could not resolve $targetHost. Check DNS or hosts file." "Red"
    exit
}

# 1. Basic TCP Port Check
Write-Log "`n[Step 1] Testing Basic TCP Connectivity..." "Yellow"
foreach ($port in $ports) {
    $check = Test-NetConnection -ComputerName $targetHost -Port $port -InformationLevel Quiet
    if ($check) {
        Write-Log "[SUCCESS] TCP Port $port is OPEN." "Green"
    } else {
        Write-Log "[FAILURE] TCP Port $port is CLOSED/BLOCKED or dropped." "Red"
    }
}

# 2. Raw SSL/TLS Handshake Test
Write-Log "`n[Step 2] Testing Raw SSL/TLS Handshake on Port 443..." "Yellow"

# Trust all certificates to prevent false-positive validation errors
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

$tcpClient = New-Object System.Net.Sockets.TcpClient
try {
    # 2a. Test raw TCP socket first
    $tcpClient.Connect($targetHost, 443)
    Write-Log "  -> TCP Socket to 443 opened successfully." "Gray"

    # 2b. Attempt to wrap the socket in an SSL Stream
    $networkStream = $tcpClient.GetStream()
    $sslStream = New-Object System.Net.Security.SslStream($networkStream, $false, {param($sender, $cert, $chain, $errors) return $true})

    Write-Log "  -> Initiating SSL Handshake (sending ClientHello)..." "Gray"

    # Force the authentication, passing the target host for SNI
    $sslStream.AuthenticateAsClient($targetHost)

    Write-Log "[SUCCESS] SSL Handshake completed successfully!" "Green"
    Write-Log "  -> Protocol: $($sslStream.SslProtocol)" "Green"
    Write-Log "  -> Cipher: $($sslStream.CipherAlgorithm)" "Green"

    $serverCert = $sslStream.RemoteCertificate
    if ($serverCert) {
        Write-Log "  -> Server Cert Subject: $($serverCert.Subject)" "Green"
    }

} catch [System.Management.Automation.MethodInvocationException] {
    $ex = $_.Exception.InnerException
    Write-Log "[ERROR] SSL Handshake Failed!" "Red"
    Write-Log "  -> Exception: $($ex.Message)" "Red"

    if ($ex.Message -match "forcibly closed" -or $ex.Message -match "connection was closed") {
        Write-Log "`n  [IIS DIAGNOSIS]: The server kernel (http.sys) explicitly tore down the connection." "Magenta"
        Write-Log "  Likely Causes on the IIS Server:" "Magenta"
        Write-Log "  1. Missing Binding: No SSL Certificate is assigned to port 443 in IIS Manager." "Magenta"
        Write-Log "  2. SNI Mismatch: The IIS binding has 'Require Server Name Indication' checked, but there is no binding explicitly matching '$targetHost'." "Magenta"
        Write-Log "  3. Orphaned Binding: The certificate was deleted from the Windows Certificate Store, but IIS still thinks it's bound." "Magenta"
    }
} catch {
    Write-Log "[ERROR] Socket connection failed: $($_.Exception.Message)" "Red"
} finally {
    if ($tcpClient.Connected) { $tcpClient.Close() }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
}

Write-Log "`n===========================================================" "Cyan"
Write-Log " Diagnostics Complete. Review log at: $logPath" "Cyan"
Write-Log "===========================================================" "Cyan"