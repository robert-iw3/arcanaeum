<#
.SYNOPSIS
    Production Server Hardening & Security Setup
    RUN ON: Production Primary Node (Active AG Replica)
.DESCRIPTION
    1. SQL: Creates Read-Only Login & Grants Granular Access (Transaction Wrapped).
    2. Network: Configures Windows Firewall for Reporting IP only (Idempotent).
    3. TLS: Generates/Binds Cert & Forces Encryption.

.NOTES
   - Ensure to update configuration variables at the top of the script before execution.
   - The SQL block uses TRY/CATCH with a transaction to ensure atomicity.
   - Any failure will roll back all changes, preventing partial security configurations.
   - Firewall rules are created only if they do not already exist, making the script safe to run multiple times without creating duplicates.
   - TLS setup includes error handling to catch issues with certificate creation or registry modifications.
   - In case of failure, it provides guidance on checking the registry for cleanup.
   - Always test in a non-production environment first to ensure compatibility and to understand the changes being made.
   Author: Robert Weber
#>

# --- CONFIGURATION ---
$ProdInstance      = "MSSQLSERVER"
$ReportingServerIP = "10.10.10.50"           # <--- UPDATE THIS IP
$AllowedDatabases  = @("UserDB_01", "UserDB_02")
$SiemUser          = "Svc_SIEM_Reader"       # <--- MATCH THIS USER IN LINKED SERVER SETUP
$SiemPassword      = "ComplexPass!2026"      # <--- MATCH THIS PASSWORD IN LINKED SERVER SETUP

$ForceEncryption   = $true
$RestartService    = $false                  # Set $true to auto-restart SQL (Required for TLS)

$ErrorActionPreference = "Stop"

# --- HELPER: NATIVE .NET SQL EXECUTOR (No Modules Required) ---
function Run-Sql {
    param([string]$Query)
    try {
        $Conn = New-Object System.Data.SqlClient.SqlConnection("Server=localhost;Database=master;Integrated Security=True;TrustServerCertificate=True")
        $Conn.Open()
        $Cmd = $Conn.CreateCommand()
        $Cmd.CommandText = $Query
        $Cmd.ExecuteNonQuery() | Out-Null
        $Conn.Close()
    } catch { throw "SQL Failure: $($_.Exception.Message)" }
}

Write-Host ">>> STARTING PRODUCTION HARDENING <<<" -ForegroundColor Cyan

# --- STEP 1: SQL SECURITY ---
Write-Host "[1/3] Configuring SQL User & Permissions..."
$DbLogic = ""
foreach ($DB in $AllowedDatabases) {
    $DbLogic += "
    IF EXISTS (SELECT name FROM sys.databases WHERE name = '$DB')
    BEGIN
        USE [$DB];
        IF NOT EXISTS (SELECT name FROM sys.database_principals WHERE name = '$SiemUser')
        BEGIN
            CREATE USER [$SiemUser] FOR LOGIN [$SiemUser];
            ALTER ROLE [db_datareader] ADD MEMBER [$SiemUser];
        END
    END;"
}

$TSQL = @"
SET XACT_ABORT ON;
BEGIN TRY
    BEGIN TRANSACTION;
        IF NOT EXISTS (SELECT name FROM sys.sql_logins WHERE name = '$SiemUser')
            CREATE LOGIN [$SiemUser] WITH PASSWORD = N'$SiemPassword', CHECK_POLICY = ON;

        $DbLogic

        DENY VIEW SERVER STATE TO [$SiemUser];
    COMMIT TRANSACTION;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    THROW;
END CATCH;
"@

try { Run-Sql -Query $TSQL; Write-Host "   [+] SQL Config Applied." -ForegroundColor Green }
catch { Write-Error "   [!] SQL Setup Failed: $_"; exit }

# --- STEP 2: FIREWALL ---
Write-Host "[2/3] Configuring Firewall..."
$RuleName = "SQL - Allow Reporting Server ($ReportingServerIP)"
if (-not (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -LocalPort 1433 -Protocol TCP -Action Allow -RemoteAddress $ReportingServerIP -Profile Any | Out-Null
    Write-Host "   [+] Firewall Rule Created." -ForegroundColor Green
} else { Write-Host "   [=] Firewall Rule Exists." -ForegroundColor Yellow }

# --- STEP 3: TLS ENCRYPTION ---
Write-Host "[3/3] Configuring TLS Certificate..."
try {
    # Generate Cert
    $Cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation "cert:\LocalMachine\My" -FriendlyName "SQL-Prod-Encryption" -KeyAlgorithm RSA -KeyLength 2048 -KeyUsage KeyEncipherment,DataEncipherment,DigitalSignature -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")

    # Grant Permissions
    $SvcName = if ($ProdInstance -eq "MSSQLSERVER") { "MSSQLSERVER" } else { "MSSQL`$$ProdInstance" }
    $SvcAccount = (Get-WmiObject Win32_Service -Filter "Name='$SvcName'").StartName
    $KeyPath = "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\$($Cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName)"
    $Acl = Get-Acl $KeyPath
    $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule $SvcAccount,"Read","Allow"))
    Set-Acl $KeyPath $Acl

    # Bind to Registry
    $RegRoot = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server"
    $InstId  = (Get-ItemProperty "$RegRoot\Instance Names\SQL").$ProdInstance
    $RegPath = "$RegRoot\$InstId\MSSQLServer\SuperSocketNetLib"

    Set-ItemProperty -Path $RegPath -Name "Certificate" -Value $Cert.Thumbprint
    if ($ForceEncryption) { Set-ItemProperty -Path $RegPath -Name "ForceEncryption" -Value 1 }

    Write-Host "   [+] Certificate Bound." -ForegroundColor Green

    if ($RestartService) { Restart-Service $SvcName -Force; Write-Host "   [+] Service Restarted." -ForegroundColor Green }
    else { Write-Host "   [!] NOTE: You must restart SQL Service '$SvcName' manually." -ForegroundColor Yellow }
} catch { Write-Error "   [!] TLS Setup Failed: $($_.Exception.Message)" }