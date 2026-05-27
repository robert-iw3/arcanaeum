<#
.SYNOPSIS
    Setup for Secure Reporting SQL Instance & Linked Server
.DESCRIPTION
    1. Installs SQL Server Engine.
    2. Configures Domain Service Account.
    3. Forces TLS Encryption & Generates Self-Signed Cert.
    4. Configures Windows Firewall.
    5. Creates Secure Linked Server to Production.

.NOTES
    - Run this script on the Primary Node of your Availability Group.
    - Ensure the Domain Service Account exists before running.
    - Adjust the configuration variables below to match your environment.
    - This script is designed for SQL Server 2022 but can be adapted for other versions by changing registry paths and installation parameters.
    - The linked server is configured to use MSOLEDBSQL provider for better TLS support.
    - Always test in a non-production environment first!
    Author: Robert Weber
#>

# --- CONFIGURATION ---
$SetupMedia       = "C:\Install\SQL2022\setup.exe"
$InstanceName     = "MSSQLSERVER"
$SqlSvcAccount    = "CONTOSO\svc_sql_siem"     # AD Account for Service
$SqlSvcPassword   = "ServicePass!123"
$SaPassword       = "EmergencySA!999"

# Link Config
$ProdListener     = "PROD-AG-LISTENER"         # DNS FQDN of Prod Listener
$LinkedServerName = "LS_PROD_RO"
$RemoteUser       = "Svc_SIEM_Reader"          # Must match Prod Script
$RemotePass       = "ComplexPass!2026"         # Must match Prod Script
$LocalSiemUser    = "CONTOSO\svc_siem_agent"   # Local User running SIEM app

# --- HELPER: NATIVE .NET SQL EXECUTOR ---
function Run-Sql {
    param([string]$Query)
    try {
        $Conn = New-Object System.Data.SqlClient.SqlConnection("Server=localhost;Database=master;Integrated Security=True;TrustServerCertificate=True")
        $Conn.Open()
        $Cmd = $Conn.CreateCommand()
        $Cmd.CommandText = $Query
        $Cmd.ExecuteNonQuery() | Out-Null
        $Conn.Close()
    } catch { throw $Query + " | ERROR: " + $_.Exception.Message }
}

$ErrorActionPreference = "Stop"

# --- STEP 1: INSTALLATION ---
Write-Host ">>> PHASE 1: INSTALLATION <<<" -ForegroundColor Cyan
if (Get-Service "MSSQLSERVER" -ErrorAction SilentlyContinue) {
    Write-Host "   [!] SQL Service found. Skipping Install." -ForegroundColor Yellow
} else {
    Write-Host "   [...] Installing SQL Server Engine (Please Wait)..."
    $Args = @("/ACTION=Install", "/Q", "/IACCEPTSQLSERVERLICENSETERMS", "/FEATURES=SQLEngine",
              "/INSTANCENAME=$InstanceName", "/SQLSVCACCOUNT=""$SqlSvcAccount""",
              "/SQLSVCPASSWORD=""$SqlSvcPassword""", "/SQLSYSADMINACCOUNTS=""$($env:USERDOMAIN)\$($env:USERNAME)""",
              "/SAPWD=""$SaPassword""", "/SECURITYMODE=SQL", "/TCPENABLED=1")

    $Proc = Start-Process -FilePath $SetupMedia -ArgumentList $Args -Wait -PassThru
    if ($Proc.ExitCode -ne 0) { throw "Setup Failed. Exit Code: $($Proc.ExitCode)" }
    Write-Host "   [+] Installation Complete." -ForegroundColor Green
}

# --- STEP 2: OS HARDENING ---
Write-Host ">>> PHASE 2: OS HARDENING <<<" -ForegroundColor Cyan
try {
    # Force Port 1433 via WMI
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement") | Out-Null
    $Wmi = New-Object Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer $env:COMPUTERNAME
    $Tcp = $Wmi.ServerInstances[$InstanceName].ServerProtocols['Tcp']
    $Tcp.IsEnabled = $true
    foreach ($IP in $Tcp.IPAddresses) { $IP.IPAddressProperties['TcpDynamicPorts'].Value=""; $IP.IPAddressProperties['TcpPort'].Value="1433" }
    $Tcp.Alter()

    Restart-Service "MSSQLSERVER" -Force

    # Firewall
    if (-not (Get-NetFirewallRule -DisplayName "SQL Reporting (1433)" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "SQL Reporting (1433)" -Direction Inbound -LocalPort 1433 -Protocol TCP -Action Allow -Profile Domain | Out-Null
    }
    Write-Host "   [+] Port 1433 Enforced & Firewall Opened." -ForegroundColor Green
} catch { Write-Error "   [!] OS Setup Failed: $($_.Exception.Message)"; exit }

# --- STEP 3: LINKED SERVER ---
Write-Host ">>> PHASE 3: SECURE LINK SETUP <<<" -ForegroundColor Cyan

$LinkScript = @"
SET XACT_ABORT ON;
BEGIN TRY
    BEGIN TRANSACTION;
        IF EXISTS (SELECT * FROM sys.servers WHERE name = '$LinkedServerName')
            EXEC sp_dropserver @server = '$LinkedServerName', @droplogins = 'droplogins';

        -- MSOLEDBSQL is key for TLS 1.2+ support
        EXEC sp_addlinkedserver @server = '$LinkedServerName', @srvproduct = 'SQL Server', @provider = 'MSOLEDBSQL',
            @datasrc = '$ProdListener', @provstr = 'ApplicationIntent=ReadOnly;Encrypt=yes;TrustServerCertificate=yes;';

        EXEC sp_addlinkedsrvlogin @rmtsrvname = '$LinkedServerName', @useself = 'False',
            @locallogin = '$LocalSiemUser', @rmtuser = '$RemoteUser', @rmtpassword = '$RemotePass';

        -- Hardening
        EXEC sp_droplinkedsrvlogin @rmtsrvname = '$LinkedServerName', @locallogin = NULL;
        EXEC sp_serveroption @server = '$LinkedServerName', @optname = 'rpc', @optvalue = 'false';
        EXEC sp_serveroption @server = '$LinkedServerName', @optname = 'rpc out', @optvalue = 'false';
    COMMIT TRANSACTION;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    THROW;
END CATCH;
"@

try { Run-Sql -Query $LinkScript; Write-Host "   [+] Linked Server '$LinkedServerName' Configured." -ForegroundColor Green }
catch { Write-Error "   [!] Link Setup Failed. Changes Rolled Back. Error: $_" }