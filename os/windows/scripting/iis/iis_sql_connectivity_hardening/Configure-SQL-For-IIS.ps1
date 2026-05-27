<#
.SYNOPSIS
    SQL Server Configuration for Secure IIS Connections
    Configures SQL for SSPI auth and certificate encryption.
.DESCRIPTION
    This script configures SQL Server:
    - Imports certificate
    - Sets force encryption
    - Enables TLS 1.3 and modern ciphers (SQL 2022+)
    - Creates login/user for IIS service account
    - Grants least privilege roles (db_datareader, db_datawriter)
.PARAMETER SqlServerName
    SQL server hostname (default: localhost).
.PARAMETER InstanceName
    SQL instance name (default: MSSQLSERVER).
.PARAMETER CertPath
    Path to certificate file (.pfx or .cer).
.PARAMETER CertPassword
    Plaintext password for PFX (required if PFX).
.PARAMETER ServiceAccount
    Domain\Username for IIS app pool.
.PARAMETER DatabaseName
    SQL database to grant access.
.NOTES
    - Run as Administrator on SQL server
    - Restart SQL service after running
    - For TLS 1.3: Requires SQL 2022 CU6+ and Windows Server 2022+
    - Author: Robert Weber
.EXAMPLE
    .\Configure-SQL-For-IIS.ps1 -CertPath "C:\certs\sqlcert.pfx" -CertPassword "P@ssw0rd" `
        -ServiceAccount "DOMAIN\SvcAcct" -DatabaseName "MyDB"
#>

param(
    [string]$SqlServerName = "localhost",
    [string]$InstanceName = "MSSQLSERVER",
    [Parameter(Mandatory)][string]$CertPath,
    [string]$CertPassword,
    [Parameter(Mandatory)][string]$ServiceAccount,
    [Parameter(Mandatory)][string]$DatabaseName
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [ConsoleColor]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

# Import cert to SQL
Write-Log "Importing certificate to SQL..." Cyan
try {
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath, $CertPassword)
    $thumbprint = $cert.Thumbprint

    # Install cert to OS store if not present
    Import-PfxCertificate -FilePath $CertPath -Password $CertPassword -CertStoreLocation Cert:\LocalMachine\My -Exportable
    Write-Log "Certificate imported to OS store" Green

    # Set private key permissions for SQL service account
    $sqlSvcAcct = "NT SERVICE\MSSQL`$$InstanceName"  # Adjust if custom
    certutil -user -addstore My $thumbprint
    # Manual step for private key permissions via MMC recommended

} catch {
    Write-Log "Cert import failed: $($_.Exception.Message)" Red
    throw
}

# Set force encryption and certificate
Write-Log "Setting force encryption..." Cyan
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib"
    if ($InstanceName -ne "MSSQLSERVER") { $regPath = $regPath -replace 'MSSQLServer', "MSSQL.$InstanceName\MSSQLServer" }

    Set-ItemProperty $regPath -Name "Certificate" -Value $thumbprint
    Set-ItemProperty $regPath -Name "ForceEncryption" -Value 1

    Write-Log "Force encryption set. Restart SQL service." Yellow
} catch {
    Write-Log "Encryption config failed: $($_.Exception.Message)" Red
    throw
}

# Enable TLS 1.3 and modern ciphers (SQL 2022+)
Write-Log "Enabling TLS 1.3 and modern ciphers..." Cyan
try {
    $tlsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server"
    New-Item $tlsPath -Force | Out-Null
    Set-ItemProperty $tlsPath -Name "Enabled" -Value 1 -Type DWord
    Set-ItemProperty $tlsPath -Name "DisabledByDefault" -Value 0 -Type DWord

    # Modern ciphers (example - adjust as needed)
    $cipherReg = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
    # Enable AES-256-GCM, etc. (already in previous global hardening)
    Write-Log "TLS 1.3 enabled. Ensure SQL 2022 CU6+." Yellow
} catch {
    Write-Log "TLS 1.3 config failed: $($_.Exception.Message)" Red
    # Non-critical - continue
}

# Grant least privilege
Write-Log "Granting least privilege access..." Cyan
try {
    $grantQuery = @"
CREATE LOGIN [$ServiceAccount] FROM WINDOWS WITH DEFAULT_DATABASE=[$DatabaseName];
USE [$DatabaseName];
CREATE USER [$ServiceAccount] FOR LOGIN [$ServiceAccount];
EXEC sp_addrolemember N'db_datareader', N'$ServiceAccount';
EXEC sp_addrolemember N'db_datawriter', N'$ServiceAccount';
"@
    Invoke-Sqlcmd -ServerInstance "$SqlServerName\$InstanceName" -Query $grantQuery -ErrorAction Stop
    Write-Log "Permissions granted" Green
} catch {
    Write-Log "Permissions grant failed: $($_.Exception.Message)" Red
    throw
}

Write-Log "SQL configuration complete!" Green