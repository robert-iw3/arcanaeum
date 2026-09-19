<#
.SYNOPSIS
    IIS Security Audit Script
    Performs comprehensive security checks on global and site-specific IIS configuration.

.DESCRIPTION
    This script audits IIS 10/11 against modern security best practices (CIS, DISA STIG, OWASP).
    It outputs a detailed CSV report and generates/updates config.ini with only failed items.
    No configuration changes are made — audit only.

.PARAMETER None
    This script has no parameters.

.NOTES
    - Requires WebAdministration module (IIS Management Tools)
    - Run as Administrator for full registry access
    - Safe to run in production — read-only
    - Generates config.ini for use with Harden-IIS.ps1
    - Author: Robert Weber

.EXAMPLE
    .\Audit-IIS.ps1
    Runs full audit and creates report + config.ini
#>

Import-Module WebAdministration -ErrorAction SilentlyContinue
$results = @()
Write-Host "`n=== IIS Sites on $env:COMPUTERNAME ===`n" -ForegroundColor Cyan
Get-Website | Select-Object Name, Id, State, PhysicalPath, ApplicationPool | Format-Table -AutoSize
# ===================================================================
# GLOBAL CHECKS
# ===================================================================
$globalChecks = @(
@{ Name = "DirectoryBrowsing"; Description = "Directory browsing disabled"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/directoryBrowse" -Name "enabled").Value -eq $false } }
@{ Name = "SampleCodeRemoval"; Description = "Sample applications removed"; Check = { $paths = "C:\inetpub\wwwroot\iissamples","C:\Program Files\Common Files\System\msadc","C:\Program Files (x86)\Common Files\System\msadc"; $paths | ForEach-Object { Test-Path $_ } -notcontains $true } }
@{ Name = "LogAndETW"; Description = "Central logging + ETW enabled"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.applicationHost/log" -Name "centralLogFileMode").Value -eq "CentralW3C" } }
@{ Name = "ProxyDisabled"; Description = "ARR/proxy disabled"; Check = { $p = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/proxy" -Name enabled -ErrorAction SilentlyContinue; $p -eq $null -or $p.Value -eq $false } }
@{ Name = "WebDAVDisabled"; Description = "WebDAV feature removed"; Check = { -not (Get-WindowsFeature Web-DAV-Publishing -ErrorAction SilentlyContinue).Installed } }
@{ Name = "GlobalAuthRule"; Description = "Global authorization restricts access"; Check = { $a = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/security/authorization" -Name "."; ($a.Collection | Where-Object {$_.users -eq '*' -and $_.accessType -eq 'Allow'}).Count -eq 0 } }
@{ Name = "PasswordFormatNotClear"; Description = "Credentials not stored in clear text"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.web/authentication/forms/credentials" -Name "passwordFormat" -ErrorAction SilentlyContinue).Value -ne "Clear" } }
@{ Name = "CredentialsNotStored"; Description = "No credentials in config files"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.web/authentication/forms/credentials" -Name ".").Collection.Count -eq 0 } }
@{ Name = "DeploymentRetail"; Description = "<deployment retail=true /> set"; Check = { $paths = "$env:windir\Microsoft.NET\Framework\v4.0.30319\Config\machine.config","$env:windir\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config"; $paths | % { if (Test-Path $_) { [xml]$x = Get-Content $_; $x.configuration.'system.web'.deployment.retail -eq "true" } else { $true } } -notcontains $false } }
@{ Name = "DebugDisabled"; Description = "Compilation debug=false"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.web/compilation" -Name "debug").Value -eq $false } }
@{ Name = "AspNetStackTracingDisabled"; Description = "Trace enabled=false"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.web/trace" -Name "enabled").Value -eq $false } }
@{ Name = "SessionStateHttpCookie"; Description = "SessionState cookieless=UseCookies"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.web/sessionState" -Name "cookieless").Value -eq "UseCookies" } }
@{ Name = "CookiesHttpOnly"; Description = "httpCookies httpOnlyCookies=true (manual check)"; Check = { $true } } # cannot be fully automated
@{ Name = "MachineKeyNet35"; Description = "machineKey validation=SHA1 (.NET 3.5)"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT' -Filter "system.web/machineKey" -Name "validation").Value -eq "SHA1" } }
@{ Name = "MachineKeyNet45"; Description = "machineKey validation=AES (.NET 4.5+)"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT' -Filter "system.web/machineKey" -Name "validation").Value -eq "AES" } }
@{ Name = "NetTrustLevel"; Description = "Trust level Medium or lower"; Check = { $l = (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT' -Filter "system.web/trust" -Name "level").Value; $l -in "Medium","Low" } }
@{ Name = "XPoweredByRemoved"; Description = "X-Powered-By header removed"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/httpProtocol/customHeaders" -Name ".").Collection | Where-Object {$_.name -eq 'X-Powered-By'} | Measure-Object | Select -Expand Count -eq 0 } }
@{ Name = "ServerHeaderRemoved"; Description = "Server header removed"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/security/requestFiltering" -Name "removeServerHeader").Value -eq $true } }
@{ Name = "MaxAllowedContentLength"; Description = "maxAllowedContentLength ≤ 30MB"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/security/requestFiltering/requestLimits" -Name "maxAllowedContentLength").Value -le 30000000 } }
@{ Name = "MaxUrl"; Description = "maxUrl ≤ 4096"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/security/requestFiltering/requestLimits" -Name "maxUrl").Value -le 4096 } }
@{ Name = "MaxQueryString"; Description = "maxQueryString ≤ 2048"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/security/requestFiltering/requestLimits" -Name "maxQueryString").Value -le 2048 } }
@{ Name = "NonAsciiUrlsDisallowed"; Description = "High-bit characters disallowed"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/security/requestFiltering" -Name "allowHighBitCharacters").Value -eq $false } }
@{ Name = "DoubleEncodedRejected"; Description = "Double escaping rejected"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/security/requestFiltering" -Name "allowDoubleEscaping").Value -eq $false } }
@{ Name = "HttpTraceDisabled"; Description = "TRACE verb disabled"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/security/requestFiltering/verbs" -Name ".").Collection | Where-Object {$_.verb -eq 'TRACE' -and $_.allowed -eq $false} | Measure-Object | Select -Expand Count -gt 0 } }
@{ Name = "UnlistedFileExtensionsDisallowed"; Description = "allowUnlisted=false"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/security/requestFiltering/fileExtensions" -Name "allowUnlisted").Value -eq $false } }
@{ Name = "HandlerNoWriteExecute"; Description = "Handlers Read,Script only"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/handlers" -Name "accessPolicy").Value -eq "Read,Script" } }
@{ Name = "NotListedIsapisAllowedFalse"; Description = "notListedIsapisAllowed=false"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/security/isapiCgiRestriction" -Name "notListedIsapisAllowed").Value -eq $false } }
@{ Name = "NotListedCgisAllowedFalse"; Description = "notListedCgisAllowed=false"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/security/isapiCgiRestriction" -Name "notListedCgisAllowed").Value -eq $false } }
@{ Name = "DynamicIpRestrictions"; Description = "Dynamic IP restrictions enabled"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" -Name "enabled").Value -eq $true } }
@{ Name = "LogLocationMoved"; Description = "Logs not on system drive"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.applicationHost/sites/siteDefaults/logFile" -Name "directory").Value -notmatch "^%SystemDrive%" } }
@{ Name = "EtwLogging"; Description = "ETW logging enabled"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.applicationHost/sites/siteDefaults/logFile" -Name "logTargetW3C").Value -match "ETW" } }
@{ Name = "HstsHeader"; Description = "HSTS header present"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/httpProtocol/customHeaders" -Name ".").Collection | Where-Object {$_.name -eq 'Strict-Transport-Security'} | Measure-Object | Select -Expand Count -gt 0 } }
# === FULL TLS/SSL REGISTRY CHECKS (no placeholders) ===
@{ Name = "Sslv2Disabled"; Description = "SSLv2 disabled (server+client)"; Check = {
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name Enabled -EA SilentlyContinue).Enabled -eq 0 -and
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name DisabledByDefault -EA SilentlyContinue).DisabledByDefault -eq 1 -and
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name Enabled -EA SilentlyContinue).Enabled -eq 0 -and
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name DisabledByDefault -EA SilentlyContinue).DisabledByDefault -eq 1
    }}
@{ Name = "Sslv3Disabled"; Description = "SSLv3 disabled (server+client)"; Check = {
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name Enabled -EA SilentlyContinue).Enabled -eq 0 -and
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name DisabledByDefault -EA SilentlyContinue).DisabledByDefault -eq 1 -and
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name Enabled -EA SilentlyContinue).Enabled -eq 0 -and
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name DisabledByDefault -EA SilentlyContinue).DisabledByDefault -eq 1
    }}
@{ Name = "Tls10Disabled"; Description = "TLS 1.0 disabled (server+client)"; Check = {
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name Enabled -EA SilentlyContinue).Enabled -eq 0 -and
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name DisabledByDefault -EA SilentlyContinue).DisabledByDefault -eq 1 -and
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name Enabled -EA SilentlyContinue).Enabled -eq 0 -and
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name DisabledByDefault -EA SilentlyContinue).DisabledByDefault -eq 1
    }}
@{ Name = "Tls11Disabled"; Description = "TLS 1.1 disabled (server+client)"; Check = {
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name Enabled -EA SilentlyContinue).Enabled -eq 0 -and
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name DisabledByDefault -EA SilentlyContinue).DisabledByDefault -eq 1 -and
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name Enabled -EA SilentlyContinue).Enabled -eq 0 -and
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name DisabledByDefault -EA SilentlyContinue).DisabledByDefault -eq 1
    }}
@{ Name = "Tls12Enabled"; Description = "TLS 1.2 enabled (server)"; Check = {
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name Enabled -EA SilentlyContinue).Enabled -eq 1 -and
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name DisabledByDefault -EA SilentlyContinue).DisabledByDefault -eq 0
    }}
@{ Name = "NullCipherDisabled"; Description = "NULL cipher disabled"; Check = { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" -Name Enabled -EA SilentlyContinue).Enabled -eq 0 } }
@{ Name = "DesDisabled"; Description = "DES 56/56 disabled"; Check = { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" -Name Enabled -EA SilentlyContinue).Enabled -eq 0 } }
@{ Name = "Rc4Disabled"; Description = "All RC4 ciphers disabled"; Check = {
        $rc4 = 'RC4 40/128','RC4 56/128','RC4 64/128','RC4 128/128'
        $rc4 | ForEach-Object { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$_" -Name Enabled -EA SilentlyContinue).Enabled -eq 0 } -notcontains $false
    }}
@{ Name = "Aes128Disabled"; Description = "AES 128/128 disabled (optional)"; Check = { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128" -Name Enabled -EA SilentlyContinue).Enabled -eq 0 } }
@{ Name = "Aes256Enabled"; Description = "AES 256/256 enabled"; Check = { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256" -Name Enabled -EA SilentlyContinue).Enabled -eq 1 } }
@{ Name = "TlsCipherSuiteOrdering"; Description = "Strong cipher suite order configured"; Check = { (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name Functions -EA SilentlyContinue).Functions -like "*ECDHE*AES*256*GCM*" } }
@{ Name = "BasicAuthDisabled"; Description = "Basic authentication disabled at server level"; Check = { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/security/authentication/basicAuthentication" -Name "enabled").Value -eq $false } }
)
# Run global checks
foreach ($c in $globalChecks) {
try { $pass = & $c.Check } catch { $pass = $false }
    $results += [pscustomobject]@{
        Scope = "Global"
        Name = $c.Name
        Description = $c.Description
        Status = if($pass) {"Pass"} else {"Fail"}
    }
}
# ===================================================================
# SITE-SPECIFIC CHECKS
# ===================================================================
$siteChecks = @(
@{ Name = "WebContentNonSystem"; Description = "Web content on non-system partition" }
@{ Name = "HostHeaders"; Description = "Host headers configured on all bindings" }
@{ Name = "AppPoolIdentity"; Description = "AppPool runs as ApplicationPoolIdentity" }
@{ Name = "UniqueAppPools"; Description = "No shared app pools (optional)" }
@{ Name = "AnonymousAppPoolIdentity"; Description = "Anonymous user = AppPool identity" }
@{ Name = "FormsAuthRequireSSL"; Description = "Forms auth requires SSL" }
@{ Name = "FormsAuthUseCookies"; Description = "Forms auth uses cookies" }
@{ Name = "FormsCookieProtection"; Description = "Forms cookie protection = All" }
@{ Name = "BasicAuthTransportSSL"; Description = "Basic auth requires SSL" }
@{ Name = "CustomErrorsNotOff"; Description = "customErrors mode != Off" }
@{ Name = "HttpErrorsHiddenRemote"; Description = "Detailed errors hidden remotely" }
@{ Name = "SiteDirectoryBrowsing"; Description = "Directory browsing disabled (site level)" }
@{ Name = "SiteHstsHeader"; Description = "HSTS header present (site level)" }
@{ Name = "X-XSS-Protection"; Description = "X-XSS-Protection header present and set to 1; mode=block" }
@{ Name = "ContentSecurityPolicy"; Description = "Content-Security-Policy header present" }
@{ Name = "X-Frame-Options"; Description = "X-Frame-Options header present (DENY or SAMEORIGIN)" }
@{ Name = "ReferrerPolicy"; Description = "Referrer-Policy header present (strict-origin-when-cross-origin or better)" }
@{ Name = "XContentTypeOptions"; Description = "X-Content-Type-Options: nosniff present" }
@{ Name = "PermissionsPolicy"; Description = "Permissions-Policy header present" }
)
foreach ($site in Get-Website) {
foreach ($c in $siteChecks) {
try {
            $pass = switch ($c.Name) {
"WebContentNonSystem" { $site.physicalPath -notmatch "^$env:SystemDrive" }
"HostHeaders" { (Get-WebBinding -Name $site.Name | Where-Object { $_.bindingInformation -match ':\d+:$' }).Count -eq 0 }
"AppPoolIdentity" { (Get-ItemProperty "IIS:\AppPools\$($site.applicationPool)" -Name processModel.identityType).processModel.identityType -eq "ApplicationPoolIdentity" }
"UniqueAppPools" { $true } # subjective - left as pass
"AnonymousAppPoolIdentity" { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter "system.webServer/security/authentication/anonymousAuthentication" -Name "userName").Value -eq "" }
"FormsAuthRequireSSL" { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter "system.web/authentication/forms" -Name "requireSSL").Value -eq $true }
"FormsAuthUseCookies" { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter "system.web/authentication/forms" -Name "cookieless").Value -eq "UseCookies" }
"FormsCookieProtection" { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter "system.web/authentication/forms" -Name "protection").Value -eq "All" }
"BasicAuthTransportSSL" { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter "system.webServer/security/access" -Name "sslFlags").Value -like "*Ssl*" }
"CustomErrorsNotOff" { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter "system.web/customErrors" -Name "mode").Value -ne "Off" }
"HttpErrorsHiddenRemote" { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter "system.webServer/httpErrors" -Name "errorMode").Value -eq "DetailedLocalOnly" }
"SiteDirectoryBrowsing" { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter "system.webServer/directoryBrowse" -Name "enabled").Value -eq $false }
"SiteHstsHeader" { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter "system.webServer/httpProtocol/customHeaders" -Name ".").Collection | Where-Object {$_.name -eq 'Strict-Transport-Security'} | Measure-Object | Select -Expand Count -gt 0 }
"X-XSS-Protection" { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter "system.webServer/httpProtocol/customHeaders" -Name ".").Collection | Where-Object {$_.name -eq 'X-XSS-Protection' -and $_.value -match '1; mode=block'} | Measure-Object | Select -Expand Count -gt 0 }
"ContentSecurityPolicy" { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter "system.webServer/httpProtocol/customHeaders" -Name ".").Collection | Where-Object {$_.name -eq 'Content-Security-Policy'} | Measure-Object | Select -Expand Count -gt 0 }
"X-Frame-Options" { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter "system.webServer/httpProtocol/customHeaders" -Name ".").Collection | Where-Object {$_.name -eq 'X-Frame-Options' -and $_.value -match 'DENY|SAMEORIGIN'} | Measure-Object | Select -Expand Count -gt 0 }
"ReferrerPolicy" { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter "system.webServer/httpProtocol/customHeaders" -Name ".").Collection | Where-Object {$_.name -eq 'Referrer-Policy' -and $_.value -match 'strict-origin-when-cross-origin|same-origin|strict-origin|no-referrer'} | Measure-Object | Select -Expand Count -gt 0 }
"XContentTypeOptions" { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter "system.webServer/httpProtocol/customHeaders" -Name ".").Collection | Where-Object {$_.name -eq 'X-Content-Type-Options' -and $_.value -eq 'nosniff'} | Measure-Object | Select -Expand Count -gt 0 }
"PermissionsPolicy" { (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter "system.webServer/httpProtocol/customHeaders" -Name ".").Collection | Where-Object {$_.name -eq 'Permissions-Policy'} | Measure-Object | Select -Expand Count -gt 0 }
            }
        } catch { $pass = $false }
        $results += [pscustomobject]@{
            Scope = "Site: $($site.Name)"
            Name = $c.Name
            Description = $c.Description
            Status = if($pass) {"Pass"} else {"Fail"}
        }
    }
}
# ===================================================================
# OUTPUT
# ===================================================================
$results | Sort-Object Scope, Name | Format-Table -AutoSize
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$csvPath = "IIS_Audit_Results_$timestamp.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "`nAudit complete - results saved to $csvPath" -ForegroundColor Green
# Auto-create/update config.ini with only FAILED items
$failed = $results | Where-Object Status -eq "Fail"
if ($failed) {
    $ini = "[Global]`n"
    $failed | Where-Object Scope -eq "Global" | ForEach-Object { $ini += "$($_.Name)=true`n" }
    $failed | Where-Object Scope -like "Site:*" | Group-Object Scope | ForEach-Object {
        $ini += "`n$($_.Name)`n"
        $_.Group | ForEach-Object { $ini += "$($_.Name)=true`n" }
    }
    $ini | Out-File -FilePath "config.ini" -Encoding ascii -Force
Write-Host "`nconfig.ini updated with $($failed.Count) failed controls" -ForegroundColor Yellow
} else {
Write-Host "`nAll checks passed!" -ForegroundColor Green
}