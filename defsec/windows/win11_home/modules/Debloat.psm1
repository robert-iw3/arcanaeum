<#
.SYNOPSIS
    Removes the out-of-box consumer bloat that expands attack surface and phones home - retired
    apps, ad-driven content channels, the Widgets feed, and the deprecated WMIC LOLBin.

.DESCRIPTION
    A stock Windows 11 install ships software nobody asked for, and each piece is attack
    surface: preinstalled apps with their own update/content channels (some, like Skype and
    Cortana, for services Microsoft has retired outright), a Start menu that silently installs
    promoted third-party apps, the Widgets news feed pulling remote content onto the lock
    screen of the taskbar, and the advertising ID tying it together. Every removed component is
    one less parser, one less network channel, one less thing an adversary can hide behind.

    What it does:
    - Removes a conservative list of preinstalled Appx packages (installed copies for all
      users + the provisioned copies new accounts would inherit). Every one of them is
      reinstallable from the Microsoft Store if someone misses it.
    - Turns off Content Delivery Manager auto-install channels (the mechanism that silently
      installs promoted apps like TikTok/Instagram onto new profiles) and Start suggestions.
    - Disables the advertising ID (user value + machine policy).
    - Turns off the Widgets news-and-interests feed (policy + taskbar button).
    - Removes the deprecated WMIC capability if present - `wmic process call create` is a
      staple LOTL execution primitive, the tool has been deprecated since 21H1, and modern
      PowerShell CIM cmdlets replace every legitimate use.

    What it deliberately KEEPS (balance - see README): the Store itself, Phone Link, Windows
    Media Player / Movies & TV, Weather, Calculator/Photos/Camera, Quick Assist (the sanctioned
    remote-help path), Get Help, and all Xbox components - gaming is a first-class home use
    case. Pass -IncludeXbox on a direct module call for machines where it truly is dead weight.

    Rollback restores every registry change; removed apps are listed with Store-reinstall
    guidance (the orchestrator also snapshots the provisioned-package list before removal).
#>

$script:AppxTargets = @(
    @{ Name = 'Microsoft.549981C3F5F10';                Label = 'Cortana (service retired)' },
    @{ Name = 'Microsoft.BingNews';                     Label = 'Microsoft News' },
    @{ Name = 'Microsoft.Getstarted';                   Label = 'Tips' },
    @{ Name = 'Microsoft.Microsoft3DViewer';            Label = '3D Viewer' },
    @{ Name = 'Microsoft.MixedReality.Portal';          Label = 'Mixed Reality Portal' },
    @{ Name = 'Microsoft.MicrosoftOfficeHub';           Label = 'Microsoft 365 promo hub' },
    @{ Name = 'Microsoft.MicrosoftSolitaireCollection'; Label = 'Solitaire Collection (ad-supported)' },
    @{ Name = 'Microsoft.People';                       Label = 'People (retired)' },
    @{ Name = 'Microsoft.SkypeApp';                     Label = 'Skype (service retired)' },
    @{ Name = 'Microsoft.WindowsFeedbackHub';           Label = 'Feedback Hub' },
    @{ Name = 'MicrosoftTeams';                         Label = 'Teams consumer Chat' },
    @{ Name = 'Microsoft.Todos';                        Label = 'Microsoft To Do' },
    @{ Name = 'Clipchamp.Clipchamp';                    Label = 'Clipchamp' }
)

$script:XboxAppxTargets = @(
    @{ Name = 'Microsoft.GamingApp';               Label = 'Xbox app' },
    @{ Name = 'Microsoft.XboxGamingOverlay';       Label = 'Xbox Game Bar' },
    @{ Name = 'Microsoft.XboxGameOverlay';         Label = 'Xbox Game Bar plugin' },
    @{ Name = 'Microsoft.XboxSpeechToTextOverlay'; Label = 'Xbox speech overlay' },
    @{ Name = 'Microsoft.Xbox.TCUI';               Label = 'Xbox TCUI' },
    @{ Name = 'Microsoft.XboxIdentityProvider';    Label = 'Xbox identity provider' }
)

$script:CdmKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
$script:CdmValues = @(
    'SilentInstalledAppsEnabled',      # silent auto-install of promoted apps
    'OemPreInstalledAppsEnabled',      # OEM app pushes
    'PreInstalledAppsEnabled',         # MS-partner app pushes
    'SubscribedContent-338388Enabled', # Start menu app suggestions
    'SubscribedContent-338389Enabled', # tips/tricks/suggestions notifications
    'SubscribedContent-310093Enabled'  # post-OOBE "finish setup" pushes
)

$script:AdvertisingUserKey   = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
$script:AdvertisingPolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'
$script:WidgetsPolicyKey     = 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh'
$script:TaskbarKey           = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$script:WmicExePath          = "$env:SystemRoot\System32\wbem\WMIC.exe"

function Import-DebloatCompatModule {
    # Appx/Dism load natively on Windows PowerShell 5.1; PowerShell 7 needs the
    # -UseWindowsPowerShell compatibility session for Appx on most builds.
    param([Parameter(Mandatory)] [string]$Name)
    if (Get-Module -Name $Name) { return $true }
    try {
        Import-Module -Name $Name -ErrorAction Stop -WarningAction SilentlyContinue
        return $true
    } catch {
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            try {
                Import-Module -Name $Name -UseWindowsPowerShell -ErrorAction Stop -WarningAction SilentlyContinue
                return $true
            } catch { return $false }
        }
        return $false
    }
}

function Get-DebloatAppxTarget {
    <#
    .SYNOPSIS
        The Appx package names this module removes (default set; add -IncludeXbox for the
        opt-in Xbox set).
    #>
    param([switch]$IncludeXbox)
    $targets = @($script:AppxTargets)
    if ($IncludeXbox) { $targets = $targets + $script:XboxAppxTargets }
    $targets
}

function Set-DebloatRegistryValue {
    <#
    .SYNOPSIS
        Ensures a key exists and writes one value, returning $null on success or a readable
        message on failure. Never throws - so one ACL-protected policy key (e.g. a locked
        HKLM:\SOFTWARE\Policies\Microsoft\Dsh on some Windows 11 builds) reports cleanly and the
        rest of the remediation continues, instead of aborting the whole run with a raw
        UnauthorizedAccessException.
    #>
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] $Value,
        [string]$Type = 'DWord'
    )
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -ErrorAction Stop
        return $null
    } catch {
        if ($_.Exception -is [System.UnauthorizedAccessException]) {
            return "SKIPPED ${Path}\${Name}: access denied. Re-run elevated; if it persists this policy key is ACL-protected on this build - set it via gpedit.msc or after taking ownership of the key."
        }
        return "SKIPPED ${Path}\${Name}: $($_.Exception.Message)"
    }
}

function Get-DebloatStatus {
    $out = @()
    if (Import-DebloatCompatModule -Name 'Appx') {
        try {
            $installed = @(Get-AppxPackage -ErrorAction Stop | ForEach-Object { $_.Name })
            $present = @($script:AppxTargets | Where-Object { $_.Name -in $installed })
            if ($present.Count -gt 0) {
                $out += "Bloat apps installed for the current user: $(($present | ForEach-Object { $_.Label }) -join ', ')"
            } else {
                $out += 'No targeted bloat apps installed for the current user.'
            }
        } catch {
            $out += "Could not enumerate Appx packages: $($_.Exception.Message)"
        }
    } else {
        $out += 'Appx cmdlets unavailable in this session - cannot report installed bloat apps.'
    }

    $silent = (Get-ItemProperty -Path $script:CdmKey -Name 'SilentInstalledAppsEnabled' -ErrorAction SilentlyContinue).SilentInstalledAppsEnabled
    if ($silent -eq 0) {
        $out += 'Content Delivery Manager: silent promoted-app installs disabled.'
    } else {
        $out += 'Content Delivery Manager: Windows may SILENTLY INSTALL promoted third-party apps.'
    }

    $adPolicy = (Get-ItemProperty -Path $script:AdvertisingPolicyKey -Name 'DisabledByGroupPolicy' -ErrorAction SilentlyContinue).DisabledByGroupPolicy
    $out += "Advertising ID: $(if ($adPolicy -eq 1) { 'disabled by policy' } else { 'enabled (default)' })."

    $widgets = (Get-ItemProperty -Path $script:WidgetsPolicyKey -Name 'AllowNewsAndInterests' -ErrorAction SilentlyContinue).AllowNewsAndInterests
    $out += "Widgets feed: $(if ($widgets -eq 0) { 'disabled by policy' } else { 'enabled (default)' })."

    if (Test-Path -LiteralPath $script:WmicExePath) {
        $out += 'WMIC: present - wmic.exe is a deprecated LOTL execution primitive and can be removed.'
    } else {
        $out += 'WMIC: not present.'
    }
    $out
}

function Invoke-DebloatHardening {
    param(
        [switch]$Remediate,
        [switch]$IncludeXbox
    )
    $out = @()
    $targets = Get-DebloatAppxTarget -IncludeXbox:$IncludeXbox

    if (-not $Remediate) {
        $out += "(dry run) Would remove these Appx packages (installed + provisioned) if present: $(($targets | ForEach-Object { $_.Label }) -join ', ')."
        $out += '(dry run) Would disable Content Delivery Manager auto-install/suggestion channels for the current user.'
        $out += '(dry run) Would disable the advertising ID (user value + machine policy).'
        $out += '(dry run) Would disable the Widgets news feed (policy) and hide its taskbar button.'
        $out += '(dry run) Would remove the deprecated WMIC capability if present.'
        return $out
    }

    # --- Appx removal (installed for all users + provisioned for future users) ---
    if (Import-DebloatCompatModule -Name 'Appx') {
        foreach ($t in $targets) {
            try {
                $pkgs = @(Get-AppxPackage -AllUsers -Name $t.Name -ErrorAction SilentlyContinue)
                foreach ($pkg in $pkgs) {
                    Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                    $out += "Removed installed app: $($t.Label) ($($pkg.PackageFullName))."
                }
            } catch {
                $out += "Could not remove $($t.Label): $($_.Exception.Message)"
            }
        }
    } else {
        $out += 'Appx cmdlets unavailable - skipped installed-app removal.'
    }
    if (Import-DebloatCompatModule -Name 'Dism') {
        try {
            $provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop)
            foreach ($t in $targets) {
                foreach ($prov in @($provisioned | Where-Object { $_.DisplayName -eq $t.Name })) {
                    try {
                        Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction Stop | Out-Null
                        $out += "Removed provisioned package (new accounts will not get it): $($t.Label)."
                    } catch {
                        $out += "Could not deprovision $($t.Label): $($_.Exception.Message)"
                    }
                }
            }
        } catch {
            $out += "Could not enumerate provisioned packages (elevation required): $($_.Exception.Message)"
        }
    } else {
        $out += 'Dism cmdlets unavailable - skipped provisioned-package removal.'
    }

    # --- Content Delivery Manager: no silent installs, no suggestions ---
    $cdmErrs = @($script:CdmValues | ForEach-Object { Set-DebloatRegistryValue -Path $script:CdmKey -Name $_ -Value 0 } | Where-Object { $_ })
    if ($cdmErrs) { $out += $cdmErrs } else { $out += 'Disabled Content Delivery Manager auto-install and suggestion channels (current user).' }

    # --- Advertising ID ---
    $adErrs = @(
        Set-DebloatRegistryValue -Path $script:AdvertisingUserKey -Name 'Enabled' -Value 0
        Set-DebloatRegistryValue -Path $script:AdvertisingPolicyKey -Name 'DisabledByGroupPolicy' -Value 1
    ) | Where-Object { $_ }
    if ($adErrs) { $out += $adErrs } else { $out += 'Disabled the advertising ID (user setting + machine policy).' }

    # --- Widgets feed ---
    # AllowNewsAndInterests lives under HKLM:\SOFTWARE\Policies\Microsoft\Dsh, which is
    # ACL-protected on some builds; if that one write is denied, TaskbarDa (HKCU) still hides
    # the taskbar button and the denial is reported rather than aborting the run.
    $wErrs = @(
        Set-DebloatRegistryValue -Path $script:WidgetsPolicyKey -Name 'AllowNewsAndInterests' -Value 0
        Set-DebloatRegistryValue -Path $script:TaskbarKey -Name 'TaskbarDa' -Value 0
    ) | Where-Object { $_ }
    if ($wErrs) { $out += $wErrs } else { $out += 'Disabled the Widgets news feed and hid its taskbar button.' }

    # --- WMIC capability (deprecated LOTL primitive) ---
    if (Test-Path -LiteralPath $script:WmicExePath) {
        if (Import-DebloatCompatModule -Name 'Dism') {
            try {
                $cap = Get-WindowsCapability -Online -Name 'WMIC~~~~*' -ErrorAction Stop | Where-Object { $_.State -eq 'Installed' }
                if ($cap) {
                    $cap | Remove-WindowsCapability -Online -ErrorAction Stop | Out-Null
                    $out += 'Removed the deprecated WMIC capability (wmic.exe LOTL primitive; PowerShell CIM cmdlets replace it).'
                } else {
                    $out += 'WMIC binary present but not managed as a removable capability on this build - left in place.'
                }
            } catch {
                $out += "Could not remove WMIC capability: $($_.Exception.Message)"
            }
        }
    } else {
        $out += 'WMIC: not present - nothing to remove.'
    }
    $out
}

function Invoke-DebloatRollback {
    param([switch]$Remediate)
    $out = @()
    if ($Remediate) {
        foreach ($name in $script:CdmValues) {
            Remove-ItemProperty -Path $script:CdmKey -Name $name -Force -ErrorAction SilentlyContinue
        }
        $out += 'Restored Content Delivery Manager defaults (removed the disable overrides).'

        Remove-ItemProperty -Path $script:AdvertisingUserKey -Name 'Enabled' -Force -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $script:AdvertisingPolicyKey -Name 'DisabledByGroupPolicy' -Force -ErrorAction SilentlyContinue
        $out += 'Restored advertising ID defaults.'

        Remove-ItemProperty -Path $script:WidgetsPolicyKey -Name 'AllowNewsAndInterests' -Force -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $script:TaskbarKey -Name 'TaskbarDa' -Force -ErrorAction SilentlyContinue
        $out += 'Restored Widgets defaults.'

        $out += 'Removed apps are not auto-reinstalled: each is available from the Microsoft Store by name. The orchestrator saved the pre-change provisioned-package list under HomeReports\ for reference.'
        $out += 'WMIC (if removed) can be restored with: Add-WindowsCapability -Online -Name WMIC~~~~ (requires Windows Update connectivity).'
    } else {
        $out += '(dry run) Would remove the Content Delivery Manager, advertising ID, and Widgets registry overrides; removed apps reinstall via the Microsoft Store.'
    }
    $out
}

Export-ModuleMember -Function Get-DebloatStatus, Invoke-DebloatHardening, Invoke-DebloatRollback, Get-DebloatAppxTarget
