<#
.SYNOPSIS
    Blocks the browser-side delivery mechanism for fake-virus-alert / tech-support-scam popups
    and raises phishing-site detection, across Edge, Chrome, and Firefox.

.DESCRIPTION
    AppLocker governs what runs on disk; it has no visibility into a browser tab. But a huge share
    of the scams this baseline targets (ClickFix, fake tech-support alerts, fake "your computer is
    infected" pages) are delivered entirely inside the browser before anything ever touches disk:

        - A malicious or compromised site asks for notification permission behind a disguised
          "click Allow to view the content / verify you're human" prompt. Once granted, it can
          push OS-style popups that look like real virus alerts indefinitely, even after the user
          has closed the tab or left the site. This is the actual delivery mechanism behind most
          "your computer has a virus, call this number" popups people now report.
        - The browser's phishing/malware site warning is what would normally stop a user from
          reaching a ClickFix-style fake-CAPTCHA page in the first place; Enhanced/strict Safe
          Browsing meaningfully widens that net versus the default level.

    This module sets the Chromium policy equivalents for Edge and Chrome, and the matching
    Firefox enterprise policy, via the registry (Chromium browsers read policy straight out of
    HKLM\SOFTWARE\Policies\...; Firefox needs its policies.json companion file, written here under
    its install directory's distribution\ folder per Mozilla's documented mechanism). Setting a
    registry value or policy file for a browser that isn't installed is harmless - the browser
    picks it up if and when it's installed; nothing else reads or needs that key.

    No AppLocker policy fragment - this module manages browser policy, not AppLocker rules.
#>

$script:RegistryTargets = @(
    @{ Browser = 'Edge';   Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' },
    @{ Browser = 'Chrome'; Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome' }
)
$script:FirefoxPolicyPaths = @(
    "${env:ProgramFiles}\Mozilla Firefox\distribution\policies.json",
    "${env:ProgramFiles(x86)}\Mozilla Firefox\distribution\policies.json"
)

function Get-BrowserScamGuardStatus {
    $results = @()
    foreach ($target in $script:RegistryTargets) {
        $notif = (Get-ItemProperty -Path $target.Path -Name 'DefaultNotificationsSetting' -ErrorAction SilentlyContinue).DefaultNotificationsSetting
        $safe = (Get-ItemProperty -Path $target.Path -Name 'SafeBrowsingProtectionLevel' -ErrorAction SilentlyContinue).SafeBrowsingProtectionLevel
        $results += "$($target.Browser): notification prompts $(if ($notif -eq 2) { 'blocked' } else { 'allowed (scam popup risk)' }), Safe Browsing level $(if ($safe) { $safe } else { 'not configured' })"
    }
    foreach ($policyPath in $script:FirefoxPolicyPaths) {
        if (Test-Path $policyPath) {
            $configured = (Get-Content $policyPath -Raw) -match '"DefaultNotification"\s*:\s*"block"'
            $results += "Firefox ($policyPath): notification prompts $(if ($configured) { 'blocked' } else { 'allowed (scam popup risk)' })"
        }
    }
    if ($results.Count -eq 0) { $results += 'No Chromium/Firefox install locations found to report on.' }
    $results
}

function Invoke-BrowserScamGuardHardening {
    param([switch]$Remediate)
    $results = @()

    foreach ($target in $script:RegistryTargets) {
        if ($Remediate) {
            if (-not (Test-Path $target.Path)) { New-Item -Path $target.Path -Force | Out-Null }
            Set-ItemProperty -Path $target.Path -Name 'DefaultNotificationsSetting' -Value 2 -Type DWord
            Set-ItemProperty -Path $target.Path -Name 'SafeBrowsingProtectionLevel' -Value 2 -Type DWord
            $results += "$($target.Browser): blocked notification permission prompts, set Safe Browsing to Enhanced (policy applies once $($target.Browser) is installed)."
        } else {
            $results += "(dry run) Would block notification prompts and set Enhanced Safe Browsing for $($target.Browser) at $($target.Path)."
        }
    }

    $firefoxJson = '{"policies":{"PopupBlocking":{"Default":true},"Permissions":{"Notifications":{"BlockNewRequests":true}},"DefaultNotification":"block"}}'
    foreach ($policyPath in $script:FirefoxPolicyPaths) {
        $installDir = Split-Path -Parent (Split-Path -Parent $policyPath)
        if (-not (Test-Path $installDir)) { continue }
        if ($Remediate) {
            $distDir = Split-Path -Parent $policyPath
            if (-not (Test-Path $distDir)) { New-Item -ItemType Directory -Path $distDir -Force | Out-Null }
            Set-Content -Path $policyPath -Value $firefoxJson -Encoding UTF8
            $results += "Firefox: wrote $policyPath blocking notification permission prompts and popups."
        } else {
            $results += "(dry run) Would write $policyPath for Firefox (notification prompts + popups blocked)."
        }
    }

    $results
}

function Invoke-BrowserScamGuardRollback {
    param([switch]$Remediate)
    $results = @()
    foreach ($target in $script:RegistryTargets) {
        if ($Remediate) {
            try {
                Remove-ItemProperty -Path $target.Path -Name 'DefaultNotificationsSetting' -Force -ErrorAction Stop
                Remove-ItemProperty -Path $target.Path -Name 'SafeBrowsingProtectionLevel' -Force -ErrorAction Stop
                $results += "Removed $($target.Browser) notification and Safe Browsing policies."
            } catch {
                Write-Warning "Failed to remove $($target.Browser) browser policies: $($_.Exception.Message). Requires an elevated session."
                $results += "FAILED ($($target.Browser)): $($_.Exception.Message)"
            }
        } else {
            $results += "(dry run) Would remove $($target.Browser) browser policies from $($target.Path)."
        }
    }
    foreach ($policyPath in $script:FirefoxPolicyPaths) {
        if (-not (Test-Path $policyPath)) { continue }
        if ($Remediate) {
            try {
                Remove-Item -Path $policyPath -Force -ErrorAction Stop
                $results += "Removed Firefox enterprise policy file at $policyPath."
            } catch {
                Write-Warning "Failed to remove Firefox policy file: $($_.Exception.Message)"
                $results += "FAILED (Firefox): $($_.Exception.Message)"
            }
        } else {
            $results += "(dry run) Would remove Firefox policy file at $policyPath."
        }
    }
    $results
}

Export-ModuleMember -Function Get-BrowserScamGuardStatus, Invoke-BrowserScamGuardHardening, Invoke-BrowserScamGuardRollback
