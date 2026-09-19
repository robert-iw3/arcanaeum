<#
.SYNOPSIS
    Removes the Default Web Site, creates a new HTTPS-only site, applies permissions, and binds a certificate.
    Universal AppPool, Basic Security, Unit Tests, and Rollback Logging.

.PARAMETER SiteName
    The name of the new IIS site to create.
.PARAMETER DriveLetter
    The drive letter (e.g., "C", "D") where the site root folder will be created.

.EXAMPLE
    .\Setup-IISSite.ps1 -SiteName "TheSiteNameHere" -DriveLetter "F"

.NOTES
    - Requires administrative privileges to run.
    - IIS 10+ is required for the certificate binding method used in this script.
    - The script will search for a valid SSL certificate in the local machine's 'My' store that matches the server's name.
    - Ensure a suitable certificate is installed before running.
    - Basic security hardening is applied (HSTS, X-Frame-Options, etc.) for demonstration purposes.

    Author: Robert Weber
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$SiteName,

    [Parameter(Mandatory=$true)]
    [ValidatePattern("^[a-zA-Z]$")]
    [string]$DriveLetter
)

$ErrorActionPreference = "Stop"
$AppCmd = "$env:systemroot\system32\inetsrv\appcmd.exe"

# --- HELPER FUNCTIONS ---
function Write-Log {
    param($Msg, $Color="White")
    Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] $Msg" -ForegroundColor $Color
}

function Run-AppCmd {
    param([string]$CommandArgs, [bool]$IgnoreError=$false)
    # Using Start-Process ensures we wait for the lock file to release before moving to the next command
    $p = Start-Process -FilePath $AppCmd -ArgumentList $CommandArgs -Wait -NoNewWindow -PassThru
    if ($p.ExitCode -ne 0 -and -not $IgnoreError) {
        Throw "AppCmd failed with Exit Code $($p.ExitCode). Command: $CommandArgs"
    }
}

function Write-Rollback-Instructions {
    Write-Host "`n=======================================================" -ForegroundColor Yellow
    Write-Host "           ROLLBACK / UNINSTALL INSTRUCTIONS           " -ForegroundColor Yellow
    Write-Host "=======================================================" -ForegroundColor Yellow
    Write-Host "To undo these changes, run the following in Admin CMD/PowerShell:" -ForegroundColor Gray

    Write-Host "`n1. Remove the Site:" -ForegroundColor White
    Write-Host "   $AppCmd delete site `"$SiteName`"" -ForegroundColor Cyan

    Write-Host "`n2. Remove the AppPool:" -ForegroundColor White
    Write-Host "   $AppCmd delete apppool `"$SiteName`"" -ForegroundColor Cyan

    Write-Host "`n3. (Optional) Clear SSL Binding:" -ForegroundColor White
    Write-Host "   netsh http delete sslcert ipport=0.0.0.0:443" -ForegroundColor Cyan

    Write-Host "`n4. Revert Security Headers (If testing requires it):" -ForegroundColor White
    Write-Host "   $AppCmd set config `"$SiteName`" /section:httpProtocol /~customHeaders.[name='Strict-Transport-Security']" -ForegroundColor Cyan
    Write-Host "   $AppCmd set config `"$SiteName`" /section:httpProtocol /~customHeaders.[name='X-Frame-Options']" -ForegroundColor Cyan

    Write-Host "`n5. Re-enable Directory Browsing:" -ForegroundColor White
    Write-Host "   $AppCmd set config `"$SiteName`" /section:directoryBrowse /enabled:true" -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor Yellow
}

# --- MAIN EXECUTION ---
try {
    Write-Log "=== STARTING NATIVE DEPLOYMENT ($SiteName) ===" "Cyan"

    # 0. PRE-FLIGHT CHECK
    if (-not (Test-Path $AppCmd)) {
        Throw "AppCmd.exe not found at $AppCmd. Is IIS installed?"
    }

    # 1. CLEANUP (Idempotency)
    # Remove 'Default Web Site' to free port 80/443
    if (& $AppCmd list site "Default Web Site") {
        Write-Log "Removing 'Default Web Site'..." "Yellow"
        Run-AppCmd "delete site `"Default Web Site`"" $true
    }

    # Remove target site/pool if they exist (allows re-running script safely)
    if (& $AppCmd list site "$SiteName") {
        Write-Log "Removing existing site '$SiteName'..." "Yellow"
        Run-AppCmd "delete site `"$SiteName`"" $true
    }
    if (& $AppCmd list apppool "$SiteName") {
        Run-AppCmd "delete apppool `"$SiteName`"" $true
    }

    # 2. FILESYSTEM
    $sitePath = "$($DriveLetter):\Inetpub\$SiteName"
    if (-not (Test-Path $sitePath)) {
        Write-Log "Creating directory: $sitePath"
        New-Item -ItemType Directory -Path $sitePath | Out-Null
        "<h1>$SiteName Live</h1><p>Deployed via Native PowerShell</p>" | Out-File "$sitePath\index.html"
    }

    Write-Log "Granting IIS_IUSRS permissions..."
    # (OI)(CI)M = Object Inherit, Container Inherit, Modify
    $null = icacls $sitePath /grant "IIS_IUSRS:(OI)(CI)M"
    if ($LASTEXITCODE -ne 0) { Throw "ICACLS permission assignment failed." }

    # 3. CERTIFICATE
    $serverName = $env:COMPUTERNAME
    Write-Log "Locating SSL Certificate for $serverName..."
    $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
        ($_.Subject -like "*CN=$serverName*" -or $_.DnsNameList -contains $serverName) -and
        $_.NotAfter -gt (Get-Date)
    } | Sort-Object NotAfter -Descending | Select-Object -First 1

    if (-not $cert) { Throw "No valid SSL Certificate found for hostname $serverName." }
    Write-Log "Selected Certificate: $($cert.Thumbprint)" "Green"

    # 4. APP POOL (Universal & High Performance)
    Write-Log "Configuring AppPool..."
    # Create Pool with v4.0 runtime (Safe default for compatibility)
    Run-AppCmd "add apppool /name:`"$SiteName`" /managedRuntimeVersion:`"v4.0`""
    # Set to AlwaysRunning and AppPoolIdentity
    Run-AppCmd "set apppool /apppool.name:`"$SiteName`" /processModel.idleTimeout:00:00:00 /startMode:AlwaysRunning /processModel.identityType:ApplicationPoolIdentity"

    # 5. SITE CREATION
    Write-Log "Creating Site bound to Port 443..."
    # Note: Bindings format is protocol/IP:port:HostHeader. We use * for IP.
    Run-AppCmd "add site /name:`"$SiteName`" /id:100 /physicalPath:`"$sitePath`" /bindings:https/*:443:"

    # Link AppPool
    Run-AppCmd "set site /site.name:`"$SiteName`" /[path='/'].applicationPool:`"$SiteName`""
    # Enable Preload
    Run-AppCmd "set site /site.name:`"$SiteName`" /applicationDefaults.preloadEnabled:true"

    # 6. SSL BINDING (Kernel Level)
    Write-Log "Binding Certificate via NETSH..."
    # Delete existing binding for 0.0.0.0:443 to avoid conflicts (suppress error if none exists)
    $null = netsh http delete sslcert ipport=0.0.0.0:443 2>$null

    $guid = [Guid]::NewGuid().ToString("B")
    $argsNetsh = "http add sslcert ipport=0.0.0.0:443 certhash=$($cert.Thumbprint) appid=$guid"
    Start-Process "netsh" -ArgumentList $argsNetsh -Wait -NoNewWindow
    if ($LASTEXITCODE -ne 0) { Throw "NETSH SSL binding failed." }

    # 7. SECURITY HARDENING
    Write-Log "Applying Security Headers..."

    # Disable Directory Browsing
    Run-AppCmd "set config `"$SiteName`" /section:directoryBrowse /enabled:false"

    # Remove X-Powered-By (Information Disclosure)
    Run-AppCmd "set config `"$SiteName`" /section:httpProtocol /-customHeaders.[name='X-Powered-By']" $true

    # Add HSTS (Force HTTPS)
    Run-AppCmd "set config `"$SiteName`" /section:httpProtocol /+customHeaders.[name='Strict-Transport-Security',value='max-age=31536000']"

    # Add Anti-Clickjacking & Sniffing
    Run-AppCmd "set config `"$SiteName`" /section:httpProtocol /+customHeaders.[name='X-Frame-Options',value='SAMEORIGIN']"
    Run-AppCmd "set config `"$SiteName`" /section:httpProtocol /+customHeaders.[name='X-Content-Type-Options',value='nosniff']"

    Write-Log "Configuration Complete. Validating..." "Cyan"

} catch {
    Write-Error "CRITICAL FAILURE: $($_.Exception.Message)"
    Write-Rollback-Instructions
    exit 1
}

# --- UNIT TESTS ---
Write-Log "`n=== RUNNING VALIDATION TESTS ===" "Magenta"
$FailCount = 0

# Test 1: AppPool Started?
if ((& $AppCmd list apppool "$SiteName") -match "state:Started") {
    Write-Log "[PASS] AppPool is Started." "Green"
} else { Write-Log "[FAIL] AppPool is Stopped." "Red"; $FailCount++ }

# Test 2: Port 80 Closed?
if (-not (netstat -an | Select-String ":80 ")) {
    Write-Log "[PASS] Port 80 is Closed." "Green"
} else {
    # Check if OUR site is the one listening
    if ((& $AppCmd list site "$SiteName") -notmatch "http/") {
        Write-Log "[PASS] Site is not listening on HTTP." "Green"
    } else { Write-Log "[FAIL] Site has HTTP binding." "Red"; $FailCount++ }
}

# Test 3: SSL Bound?
if (netsh http show sslcert ipport=0.0.0.0:443 | Select-String $cert.Thumbprint) {
    Write-Log "[PASS] SSL Certificate confirmed in Kernel." "Green"
} else { Write-Log "[FAIL] SSL Certificate mismatch." "Red"; $FailCount++ }

# Test 4: Headers Configured?
$conf = & $AppCmd list config "$SiteName" /section:httpProtocol
if ($conf -match "Strict-Transport-Security") {
    Write-Log "[PASS] Security Headers present." "Green"
} else { Write-Log "[FAIL] Security Headers missing." "Red"; $FailCount++ }

if ($FailCount -eq 0) {
    Write-Host "`nSUCCESS: Deployment Verified." -ForegroundColor Green
    Write-Rollback-Instructions
} else {
    Write-Host "`nWARNING: $FailCount validation checks failed." -ForegroundColor Red
    Write-Rollback-Instructions
}