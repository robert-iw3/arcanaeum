<#
.SYNOPSIS
    Applies a strong-but-balanced security policy set to every browser on the machine - Edge,
    Chrome (Chromium, via HKLM policy), and Firefox (via HKLM\...\Policies\Mozilla\Firefox) -
    hardening the single biggest initial-access surface a non-technical user has.

.DESCRIPTION
    BrowserScamGuard covers the scam-popup path (notification prompts + Safe Browsing). This
    module is the broader "lock the browser down" layer, chosen so a normal user (grandpa
    reading email, buying things, watching videos) notices nothing, while the routes an attacker
    needs are closed:

    Default set (near-zero user impact, all browsers unless noted):
    - DownloadRestrictions = block malicious/dangerous downloads outright (Safe Browsing verdict).
    - RemoteDebuggingAllowed = 0: closes the remote-debugging port that infostealer malware
      attaches to in order to read cookies/session tokens straight out of a running browser.
    - BlockExternalExtensions = 1: stops other programs silently registering browser extensions
      (a common adware/infostealer install path). The user can still add extensions from the store.
    - InsecurePrivateNetworkRequestsAllowed = 0: stops a malicious web page probing/attacking the
      home router and other LAN devices from inside the browser.
    - BasicAuthOverHttpEnabled = 0, SSLVersionMin = TLS 1.2: no cleartext/legacy-crypto auth.
    - DnsOverHttpsMode = automatic: encrypted DNS where available (falls back cleanly).
    - Edge only: SmartScreen on + PUA + can't-click-through, and Enhanced Security Mode = balanced
      (disables the JIT JavaScript engine on sites you don't visit often, killing a whole class
      of drive-by RCE) - the Edge counterpart to Chrome's Safe Browsing.
    - Firefox: disable telemetry, TLS 1.2 floor, DNS-over-HTTPS on.

    Strict set (opt in with the Strict option - real but minor friction):
    - BlockThirdPartyCookies = 1 (may sign you out of some embedded logins).
    - PromptForDownloadLocation = 1 (asks where to save every download, so an unexpected one is
      obvious).

    Deliberately NOT done (balance): does not disable the password manager (pushes users to worse
    habits), does not force HTTPS-Only (breaks http-only home-router/printer pages), does not
    disable DevTools, and does not block extension installs from the store.

    Setting a policy for a browser that isn't installed is harmless - it applies if/when the
    browser is installed. Firefox reads these HKLM registry policies in addition to the
    policies.json BrowserScamGuard writes, so the two modules coexist without conflict.
#>

$script:ChromiumTargets = @(
    @{ Browser = 'Edge';   Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' },
    @{ Browser = 'Chrome'; Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome' }
)

# Applied to BOTH Edge and Chrome (identical policy names).
$script:CommonValues = [ordered]@{
    DownloadRestrictions                  = @{ Value = 1;           Type = 'DWord' }
    RemoteDebuggingAllowed                = @{ Value = 0;           Type = 'DWord' }
    BlockExternalExtensions               = @{ Value = 1;           Type = 'DWord' }
    InsecurePrivateNetworkRequestsAllowed = @{ Value = 0;           Type = 'DWord' }
    BasicAuthOverHttpEnabled              = @{ Value = 0;           Type = 'DWord' }
    SSLVersionMin                         = @{ Value = 'tls1.2';    Type = 'String' }
    DnsOverHttpsMode                      = @{ Value = 'automatic'; Type = 'String' }
}
# Edge-only (Chrome's equivalent protection is Safe Browsing, set by BrowserScamGuard).
$script:EdgeOnlyValues = [ordered]@{
    SmartScreenEnabled               = @{ Value = 1; Type = 'DWord' }
    SmartScreenPuaEnabled            = @{ Value = 1; Type = 'DWord' }
    PreventSmartScreenPromptOverride = @{ Value = 1; Type = 'DWord' }
    EnhanceSecurityMode              = @{ Value = 1; Type = 'DWord' }
}
# Added to both Chromium browsers only when -Strict.
$script:StrictValues = [ordered]@{
    BlockThirdPartyCookies    = @{ Value = 1; Type = 'DWord' }
    PromptForDownloadLocation = @{ Value = 1; Type = 'DWord' }
}

$script:FirefoxKey = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'
$script:FirefoxValues = [ordered]@{
    DisableTelemetry = @{ Value = 1;        Type = 'DWord' }
    SSLVersionMin    = @{ Value = 'tls1.2'; Type = 'String' }
}
$script:FirefoxDohKey = "$script:FirefoxKey\DNSOverHTTPS"
$script:FirefoxCookiesKey = "$script:FirefoxKey\Cookies"   # strict only

function Set-BrowserPolicyValue {
    # Resilient single-value write: ensures the key, writes the value, never throws - so one
    # locked key reports and the run continues (same pattern as Debloat).
    param([string]$Path, [string]$Name, $Value, [string]$Type)
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -ErrorAction Stop
        $null
    } catch {
        "SKIPPED ${Path}\${Name}: $($_.Exception.Message)"
    }
}

function Get-BrowserHardeningStatus {
    $out = @()
    foreach ($t in $script:ChromiumTargets) {
        $dl  = (Get-ItemProperty -Path $t.Path -Name 'DownloadRestrictions' -ErrorAction SilentlyContinue).DownloadRestrictions
        $rdp = (Get-ItemProperty -Path $t.Path -Name 'RemoteDebuggingAllowed' -ErrorAction SilentlyContinue).RemoteDebuggingAllowed
        $tls = (Get-ItemProperty -Path $t.Path -Name 'SSLVersionMin' -ErrorAction SilentlyContinue).SSLVersionMin
        $out += "$($t.Browser): dangerous-download block $(if ($dl) { 'on' } else { 'default' }), remote-debug $(if ($rdp -eq 0) { 'blocked' } else { 'default (cookie-theft surface)' }), TLS floor $(if ($tls) { $tls } else { 'default' })."
    }
    $ffTel = (Get-ItemProperty -Path $script:FirefoxKey -Name 'DisableTelemetry' -ErrorAction SilentlyContinue).DisableTelemetry
    $out += "Firefox: policy hardening $(if ($ffTel -eq 1) { 'applied' } else { 'not applied' })."
    $out
}

function Invoke-BrowserHardeningHardening {
    param(
        [switch]$Remediate,
        [switch]$Strict
    )
    $out = @()
    $errs = @()

    if (-not $Remediate) {
        $out += "(dry run) Would apply balanced security policies to Edge and Chrome (block dangerous downloads, disable remote-debugging, block external extensions, block LAN probing, TLS 1.2 floor, DNS-over-HTTPS)."
        $out += "(dry run) Would apply Edge SmartScreen + Enhanced Security Mode (balanced)."
        $out += "(dry run) Would harden Firefox policy (disable telemetry, TLS 1.2 floor, DNS-over-HTTPS)."
        if ($Strict) { $out += "(dry run) Strict: would also block third-party cookies and prompt for every download location." }
        return $out
    }

    foreach ($t in $script:ChromiumTargets) {
        foreach ($name in $script:CommonValues.Keys) {
            $errs += Set-BrowserPolicyValue -Path $t.Path -Name $name -Value $script:CommonValues[$name].Value -Type $script:CommonValues[$name].Type
        }
        if ($t.Browser -eq 'Edge') {
            foreach ($name in $script:EdgeOnlyValues.Keys) {
                $errs += Set-BrowserPolicyValue -Path $t.Path -Name $name -Value $script:EdgeOnlyValues[$name].Value -Type $script:EdgeOnlyValues[$name].Type
            }
        }
        if ($Strict) {
            foreach ($name in $script:StrictValues.Keys) {
                $errs += Set-BrowserPolicyValue -Path $t.Path -Name $name -Value $script:StrictValues[$name].Value -Type $script:StrictValues[$name].Type
            }
        }
        $out += "$($t.Browser): applied balanced security policies$(if ($Strict) { ' + strict cookie/download policies' } else { '' })."
    }

    foreach ($name in $script:FirefoxValues.Keys) {
        $errs += Set-BrowserPolicyValue -Path $script:FirefoxKey -Name $name -Value $script:FirefoxValues[$name].Value -Type $script:FirefoxValues[$name].Type
    }
    $errs += Set-BrowserPolicyValue -Path $script:FirefoxDohKey -Name 'Enabled' -Value 1 -Type 'DWord'
    if ($Strict) {
        $errs += Set-BrowserPolicyValue -Path $script:FirefoxCookiesKey -Name 'Behavior' -Value 'reject_foreign' -Type 'String'
    }
    $out += "Firefox: applied policy hardening (telemetry off, TLS 1.2 floor, DNS-over-HTTPS on)$(if ($Strict) { ' + third-party cookie rejection' } else { '' })."

    $errs = @($errs | Where-Object { $_ })
    if ($errs) { $out += $errs }
    $out
}

function Invoke-BrowserHardeningRollback {
    param(
        [switch]$Remediate,
        [switch]$Strict
    )
    $out = @()
    if ($Remediate) {
        foreach ($t in $script:ChromiumTargets) {
            $names = @($script:CommonValues.Keys) + @($script:StrictValues.Keys)
            if ($t.Browser -eq 'Edge') { $names += @($script:EdgeOnlyValues.Keys) }
            foreach ($name in $names) {
                Remove-ItemProperty -Path $t.Path -Name $name -Force -ErrorAction SilentlyContinue
            }
            $out += "$($t.Browser): removed browser-hardening policy values."
        }
        foreach ($name in $script:FirefoxValues.Keys) {
            Remove-ItemProperty -Path $script:FirefoxKey -Name $name -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -Path $script:FirefoxDohKey -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $script:FirefoxCookiesKey -Recurse -Force -ErrorAction SilentlyContinue
        $out += 'Firefox: removed browser-hardening policy values.'
    } else {
        $out += '(dry run) Would remove all BrowserHardening policy values from Edge, Chrome, and Firefox.'
    }
    $out
}

Export-ModuleMember -Function Get-BrowserHardeningStatus, Invoke-BrowserHardeningHardening, Invoke-BrowserHardeningRollback, Set-BrowserPolicyValue
