#Requires -Module Pester

<#
.SYNOPSIS
    Contract tests for every module under modules\*.psm1, plus dedicated hardening/rollback-path
    tests for each shipped module (registry/firewall/service/Appx calls mocked - these tests
    never touch real machine state and run unelevated on PowerShell 5.1 and 7+).
#>

BeforeAll {
    $script:Root = Join-Path $PSScriptRoot '..'
    $script:ModulesRoot = Join-Path $script:Root 'modules'
    $script:ModuleFiles = Get-ChildItem -LiteralPath $script:ModulesRoot -Filter '*.psm1' -File

    # Parse the orchestrator's real $DefaultModules line so "is/isn't default" assertions stay
    # honest about the actual shipped configuration instead of a hand-copied list going stale.
    $orchestratorSource = Get-Content (Join-Path $script:Root 'Invoke-HomeBaseline.ps1') -Raw
    if ($orchestratorSource -notmatch '\$DefaultModules\s*=\s*@\(([^)]*)\)') {
        throw 'Could not locate $DefaultModules in Invoke-HomeBaseline.ps1 - has it been renamed?'
    }
    $script:RealDefaultModules = [regex]::Matches($Matches[1], "'([^']+)'") | ForEach-Object { $_.Groups[1].Value }
}

Describe 'Module contract: <_.Name>' -ForEach $ModuleFiles {

    BeforeAll {
        $script:ModName = $_.BaseName
        Import-Module $_.FullName -Force
    }

    It 'imports cleanly' {
        Get-Module $script:ModName | Should -Not -BeNullOrEmpty
    }

    It 'Get-<Name>Status (if present) runs without throwing and unelevated' {
        $fn = "Get-${script:ModName}Status"
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because "$script:ModName does not export $fn"
            return
        }
        { & $fn } | Should -Not -Throw
    }

    It 'Invoke-<Name>Hardening (if present) is a no-op dry run without -Remediate' {
        $fn = "Invoke-${script:ModName}Hardening"
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because "$script:ModName does not export $fn"
            return
        }
        { & $fn } | Should -Not -Throw
        (& $fn) -join "`n" | Should -Match '\(dry run\)'
    }

    It 'Invoke-<Name>Rollback (if present) is a no-op dry run without -Remediate' {
        $fn = "Invoke-${script:ModName}Rollback"
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because "$script:ModName does not export $fn"
            return
        }
        { & $fn } | Should -Not -Throw
    }

    It 'every Hardening function ships a matching Rollback (containment must be reversible)' {
        $hardening = "Invoke-${script:ModName}Hardening"
        if (-not (Get-Command $hardening -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because "$script:ModName has no Hardening function (status-only module)"
            return
        }
        Get-Command "Invoke-${script:ModName}Rollback" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe 'ScriptHostGuard: disables WSH and neutralizes script/HTA double-click' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'ScriptHostGuard.psm1') -Force }

    It 'is in the default set' { $script:RealDefaultModules | Should -Contain 'ScriptHostGuard' }

    It 'Hardening -Remediate sets WSH Enabled=0 and Edit default verbs' {
        Mock -ModuleName ScriptHostGuard Test-Path { $false }
        Mock -ModuleName ScriptHostGuard New-Item { }
        Mock -ModuleName ScriptHostGuard Set-ItemProperty { }

        $result = Invoke-ScriptHostGuardHardening -Remediate

        Should -Invoke -ModuleName ScriptHostGuard Set-ItemProperty -Times 1 -ParameterFilter {
            $Path -match 'Windows Script Host' -and $Name -eq 'Enabled' -and $Value -eq 0
        }
        # 6 WSH ProgId default verbs flipped to Edit
        Should -Invoke -ModuleName ScriptHostGuard Set-ItemProperty -Times 6 -ParameterFilter {
            $Name -eq '(default)' -and $Value -eq 'Edit' -and $Path -match '\\Shell$'
        }
        ($result -join "`n") | Should -Match 'Disabled Windows Script Host'
    }

    It 'does not touch the registry without -Remediate' {
        Mock -ModuleName ScriptHostGuard Set-ItemProperty { }
        Invoke-ScriptHostGuardHardening | Out-Null
        Should -Invoke -ModuleName ScriptHostGuard Set-ItemProperty -Times 0
    }

    It 'Rollback -Remediate removes the WSH override' {
        Mock -ModuleName ScriptHostGuard Remove-ItemProperty { }
        Mock -ModuleName ScriptHostGuard Remove-Item { }
        $result = Invoke-ScriptHostGuardRollback -Remediate
        Should -Invoke -ModuleName ScriptHostGuard Remove-ItemProperty -ParameterFilter { $Name -eq 'Enabled' }
        ($result -join "`n") | Should -Match 'Re-enabled Windows Script Host'
    }
}

Describe 'LolbinEgressGuard: outbound firewall blocks for download cradles' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'LolbinEgressGuard.psm1') -Force }

    It 'is in the default set' { $script:RealDefaultModules | Should -Contain 'LolbinEgressGuard' }

    It 'Get-LolbinEgressTarget resolves only binaries that exist and covers System32' {
        $targets = Get-LolbinEgressTarget
        $targets | Should -Not -BeNullOrEmpty
        foreach ($t in $targets) { Test-Path -LiteralPath $t.Path | Should -BeTrue }
        ($targets | Where-Object { $_.Path -match 'System32' }) | Should -Not -BeNullOrEmpty
    }

    It 'Hardening -Remediate creates an outbound Block rule per target binary' {
        Mock -ModuleName LolbinEgressGuard Get-NetFirewallRule { @() }
        Mock -ModuleName LolbinEgressGuard New-NetFirewallRule { }
        Mock -ModuleName LolbinEgressGuard Get-LolbinEgressTarget {
            @([pscustomobject]@{ Binary = 'mshta.exe'; Path = 'C:\Windows\System32\mshta.exe'; DisplayName = 'Block outbound - mshta.exe (System32)' })
        }

        Invoke-LolbinEgressGuardHardening -Remediate | Out-Null

        Should -Invoke -ModuleName LolbinEgressGuard New-NetFirewallRule -Times 1 -ParameterFilter {
            $Direction -eq 'Outbound' -and $Action -eq 'Block' -and $Program -eq 'C:\Windows\System32\mshta.exe'
        }
    }

    It 'does not create rules without -Remediate' {
        Mock -ModuleName LolbinEgressGuard New-NetFirewallRule { }
        $result = Invoke-LolbinEgressGuardHardening
        Should -Invoke -ModuleName LolbinEgressGuard New-NetFirewallRule -Times 0
        ($result -join "`n") | Should -Match '\(dry run\)'
    }

    It '-IncludeCurl adds curl.exe to the target set' {
        Mock -ModuleName LolbinEgressGuard Get-NetFirewallRule { @() }
        Mock -ModuleName LolbinEgressGuard New-NetFirewallRule { }
        $result = Invoke-LolbinEgressGuardHardening -IncludeCurl   # dry run
        ($result -join "`n") | Should -Match 'curl\.exe'
    }

    It 'Rollback -Remediate removes the rule group' {
        Mock -ModuleName LolbinEgressGuard Get-NetFirewallRule { @([pscustomobject]@{ DisplayName = 'x' }) }
        Mock -ModuleName LolbinEgressGuard Remove-NetFirewallRule { }
        Invoke-LolbinEgressGuardRollback -Remediate | Out-Null
        Should -Invoke -ModuleName LolbinEgressGuard Remove-NetFirewallRule -Times 1
    }
}

Describe 'CredentialTheftGuard: LSA Protection (RunAsPPL)' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'CredentialTheftGuard.psm1') -Force }

    It 'is in the default set' { $script:RealDefaultModules | Should -Contain 'CredentialTheftGuard' }

    It 'Hardening -Remediate sets RunAsPPL=1' {
        Mock -ModuleName CredentialTheftGuard Set-ItemProperty { }
        $result = Invoke-CredentialTheftGuardHardening -Remediate
        Should -Invoke -ModuleName CredentialTheftGuard Set-ItemProperty -Times 1 -ParameterFilter {
            $Name -eq 'RunAsPPL' -and $Value -eq 1
        }
        ($result -join "`n") | Should -Match 'RunAsPPL'
    }

    It 'does not write without -Remediate' {
        Mock -ModuleName CredentialTheftGuard Set-ItemProperty { }
        Invoke-CredentialTheftGuardHardening | Out-Null
        Should -Invoke -ModuleName CredentialTheftGuard Set-ItemProperty -Times 0
    }

    It 'Status reminds the operator to verify Tamper Protection' {
        $status = Get-CredentialTheftGuardStatus
        ($status -join "`n") | Should -Match 'Tamper Protection'
    }

    It 'Rollback -Remediate removes RunAsPPL' {
        Mock -ModuleName CredentialTheftGuard Remove-ItemProperty { }
        Invoke-CredentialTheftGuardRollback -Remediate | Out-Null
        Should -Invoke -ModuleName CredentialTheftGuard Remove-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'RunAsPPL' }
    }
}

Describe 'NameResolutionGuard: LLMNR/NetBIOS/WPAD poisoning defenses' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'NameResolutionGuard.psm1') -Force }

    It 'is in the default set' { $script:RealDefaultModules | Should -Contain 'NameResolutionGuard' }

    It 'Hardening -Remediate disables LLMNR, sets P-node, disables WPAD' {
        Mock -ModuleName NameResolutionGuard Test-Path { $false }
        Mock -ModuleName NameResolutionGuard New-Item { }
        Mock -ModuleName NameResolutionGuard Set-ItemProperty { }

        Invoke-NameResolutionGuardHardening -Remediate | Out-Null

        Should -Invoke -ModuleName NameResolutionGuard Set-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'EnableMulticast' -and $Value -eq 0 }
        Should -Invoke -ModuleName NameResolutionGuard Set-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'NodeType' -and $Value -eq 2 }
        Should -Invoke -ModuleName NameResolutionGuard Set-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'WpadOverride' -and $Value -eq 1 }
    }

    It 'does not leave mDNS in scope (balance: printers/casting stay working)' {
        # No mDNS registry value is ever written - assert the module never references EnableMDNS.
        $src = Get-Content (Join-Path $script:ModulesRoot 'NameResolutionGuard.psm1') -Raw
        $src | Should -Not -Match 'EnableMDNS'
    }

    It 'Rollback -Remediate removes all three values' {
        Mock -ModuleName NameResolutionGuard Remove-ItemProperty { }
        Invoke-NameResolutionGuardRollback -Remediate | Out-Null
        Should -Invoke -ModuleName NameResolutionGuard Remove-ItemProperty -Times 3
    }
}

Describe 'RemoteServiceGuard: disables WinRM and Remote Registry' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'RemoteServiceGuard.psm1') -Force }

    It 'is in the default set' { $script:RealDefaultModules | Should -Contain 'RemoteServiceGuard' }

    It 'Hardening -Remediate stops and disables present services' {
        Mock -ModuleName RemoteServiceGuard Get-Service { [pscustomobject]@{ Name = $Name; Status = 'Running'; StartType = 'Automatic' } }
        Mock -ModuleName RemoteServiceGuard Stop-Service { }
        Mock -ModuleName RemoteServiceGuard Set-Service { }

        Invoke-RemoteServiceGuardHardening -Remediate | Out-Null

        Should -Invoke -ModuleName RemoteServiceGuard Set-Service -Times 2 -ParameterFilter { $StartupType -eq 'Disabled' }
        Should -Invoke -ModuleName RemoteServiceGuard Stop-Service -Times 2
    }

    It 'reports and skips services that are not installed' {
        Mock -ModuleName RemoteServiceGuard Get-Service { $null }
        Mock -ModuleName RemoteServiceGuard Set-Service { }
        Invoke-RemoteServiceGuardHardening -Remediate | Out-Null
        Should -Invoke -ModuleName RemoteServiceGuard Set-Service -Times 0
    }

    It 'Rollback -Remediate restores Windows 11 default startup types' {
        Mock -ModuleName RemoteServiceGuard Get-Service { [pscustomobject]@{ Name = $Name; Status = 'Stopped'; StartType = 'Disabled' } }
        Mock -ModuleName RemoteServiceGuard Set-Service { }
        Invoke-RemoteServiceGuardRollback -Remediate | Out-Null
        Should -Invoke -ModuleName RemoteServiceGuard Set-Service -Times 1 -ParameterFilter { $Name -eq 'WinRM' -and $StartupType -eq 'Manual' }
        Should -Invoke -ModuleName RemoteServiceGuard Set-Service -Times 1 -ParameterFilter { $Name -eq 'RemoteRegistry' -and $StartupType -eq 'Disabled' }
    }
}

Describe 'ExplorerVisibilityHardening: show known file extensions' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'ExplorerVisibilityHardening.psm1') -Force }

    It 'is in the default set' { $script:RealDefaultModules | Should -Contain 'ExplorerVisibilityHardening' }

    It 'Hardening -Remediate sets HideFileExt=0 for current user and seeds the Default profile' {
        Mock -ModuleName ExplorerVisibilityHardening Test-Path { $false }
        Mock -ModuleName ExplorerVisibilityHardening New-Item { }
        Mock -ModuleName ExplorerVisibilityHardening Set-ItemProperty { }
        Mock -ModuleName ExplorerVisibilityHardening Stop-Process { }
        Mock -ModuleName ExplorerVisibilityHardening Set-ExplorerDefaultProfileHideFileExt { 'seeded' }

        Invoke-ExplorerVisibilityHardeningHardening -Remediate | Out-Null

        # HKCU is the only direct Set-ItemProperty in the function now; the Default profile is
        # handled by the (mocked) helper via a hive load/unload.
        Should -Invoke -ModuleName ExplorerVisibilityHardening Set-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'HideFileExt' -and $Value -eq 0 }
        Should -Invoke -ModuleName ExplorerVisibilityHardening Set-ExplorerDefaultProfileHideFileExt -Times 1 -ParameterFilter { $Remediate -and -not $Remove }
    }

    It 'Default-profile helper writes into the loaded hive, never to HKLM Explorer\Advanced' {
        # Regression guard for the original bug: the seed must go through the Default user hive,
        # not HKLM:\...\Explorer\Advanced (which is ignored as a live preference).
        $src = Get-Content (Join-Path $script:ModulesRoot 'ExplorerVisibilityHardening.psm1') -Raw
        $src | Should -Not -Match "HKLM:\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Advanced"
        $src | Should -Match 'Users\\Default\\NTUSER\.DAT'
    }

    It 'Rollback -Remediate removes the current-user override and the Default-profile seed' {
        Mock -ModuleName ExplorerVisibilityHardening Remove-ItemProperty { }
        Mock -ModuleName ExplorerVisibilityHardening Stop-Process { }
        Mock -ModuleName ExplorerVisibilityHardening Set-ExplorerDefaultProfileHideFileExt { 'removed' }
        Invoke-ExplorerVisibilityHardeningRollback -Remediate | Out-Null
        Should -Invoke -ModuleName ExplorerVisibilityHardening Remove-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'HideFileExt' }
        Should -Invoke -ModuleName ExplorerVisibilityHardening Set-ExplorerDefaultProfileHideFileExt -Times 1 -ParameterFilter { $Remove -and $Remediate }
        Should -Invoke -ModuleName ExplorerVisibilityHardening Stop-Process -Times 1 -ParameterFilter { $Name -eq 'explorer' }
    }
}

Describe 'Debloat: app removal, content-delivery, advertising ID, Widgets, WMIC' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'Debloat.psm1') -Force }

    It 'is in the default set' { $script:RealDefaultModules | Should -Contain 'Debloat' }

    It 'default target set excludes Xbox; -IncludeXbox adds it' {
        $default = Get-DebloatAppxTarget
        ($default | Where-Object { $_.Name -match 'Xbox' }) | Should -BeNullOrEmpty
        $withXbox = Get-DebloatAppxTarget -IncludeXbox
        ($withXbox | Where-Object { $_.Name -match 'Xbox' }) | Should -Not -BeNullOrEmpty
    }

    It 'keeps first-class home apps out of the removal list (Store, Phone Link, media, Quick Assist)' {
        $names = (Get-DebloatAppxTarget -IncludeXbox).Name -join ' '
        foreach ($keep in 'WindowsStore', 'PhoneLink', 'YourPhone', 'ZuneMusic', 'ZuneVideo', 'QuickAssist', 'WindowsCalculator', 'Photos') {
            $names | Should -Not -Match $keep -Because "$keep is a legitimate home app and must not be removed"
        }
    }

    It 'Hardening -Remediate disables silent installs, advertising ID, and Widgets' {
        Mock -ModuleName Debloat Import-DebloatCompatModule { $false }   # skip Appx/Dism paths in the unit test
        Mock -ModuleName Debloat Test-Path { $false }
        Mock -ModuleName Debloat New-Item { }
        Mock -ModuleName Debloat Set-ItemProperty { }

        Invoke-DebloatHardening -Remediate | Out-Null

        Should -Invoke -ModuleName Debloat Set-ItemProperty -ParameterFilter { $Name -eq 'SilentInstalledAppsEnabled' -and $Value -eq 0 }
        Should -Invoke -ModuleName Debloat Set-ItemProperty -ParameterFilter { $Name -eq 'DisabledByGroupPolicy' -and $Value -eq 1 }
        Should -Invoke -ModuleName Debloat Set-ItemProperty -ParameterFilter { $Name -eq 'AllowNewsAndInterests' -and $Value -eq 0 }
    }

    It 'does not write without -Remediate' {
        Mock -ModuleName Debloat Set-ItemProperty { }
        Mock -ModuleName Debloat Remove-AppxPackage { }
        Invoke-DebloatHardening | Out-Null
        Should -Invoke -ModuleName Debloat Set-ItemProperty -Times 0
        Should -Invoke -ModuleName Debloat Remove-AppxPackage -Times 0
    }

    It 'Rollback -Remediate removes the registry overrides' {
        Mock -ModuleName Debloat Remove-ItemProperty { }
        $result = Invoke-DebloatRollback -Remediate
        Should -Invoke -ModuleName Debloat Remove-ItemProperty -ParameterFilter { $Name -eq 'AllowNewsAndInterests' }
        ($result -join "`n") | Should -Match 'Microsoft Store'
    }
}

Describe 'SmartAppControlAudit: status-only reporting' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'SmartAppControlAudit.psm1') -Force }

    It 'is in the default set' { $script:RealDefaultModules | Should -Contain 'SmartAppControlAudit' }

    It 'exports no Hardening function (cannot be scripted on)' {
        Get-Command Invoke-SmartAppControlAuditHardening -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }

    It 'reports each SAC state distinctly' {
        Mock -ModuleName SmartAppControlAudit Get-ItemProperty { [pscustomobject]@{ VerifiedAndReputablePolicyState = 1 } }
        (Get-SmartAppControlAuditStatus) -join ' ' | Should -Match 'ON'
        Mock -ModuleName SmartAppControlAudit Get-ItemProperty { [pscustomobject]@{ VerifiedAndReputablePolicyState = 2 } }
        (Get-SmartAppControlAuditStatus) -join ' ' | Should -Match 'EVALUATION'
        Mock -ModuleName SmartAppControlAudit Get-ItemProperty { [pscustomobject]@{ VerifiedAndReputablePolicyState = 0 } }
        (Get-SmartAppControlAuditStatus) -join ' ' | Should -Match 'OFF'
    }
}

Describe 'NtlmEgressGuard: opt-in outgoing-NTLM deny' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'NtlmEgressGuard.psm1') -Force }

    It 'is NOT in the default set (breaks NTLM-only NAS/printers)' {
        $script:RealDefaultModules | Should -Not -Contain 'NtlmEgressGuard'
    }

    It 'Hardening -Remediate sets RestrictSendingNTLMTraffic=2' {
        Mock -ModuleName NtlmEgressGuard Set-ItemProperty { }
        Invoke-NtlmEgressGuardHardening -Remediate | Out-Null
        Should -Invoke -ModuleName NtlmEgressGuard Set-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'RestrictSendingNTLMTraffic' -and $Value -eq 2 }
    }

    It 'Rollback -Remediate removes the restriction' {
        Mock -ModuleName NtlmEgressGuard Remove-ItemProperty { }
        Invoke-NtlmEgressGuardRollback -Remediate | Out-Null
        Should -Invoke -ModuleName NtlmEgressGuard Remove-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'RestrictSendingNTLMTraffic' }
    }
}

# --- Modules ported from the applocker baseline (reimplemented without AppLocker) ---

Describe 'BrowserScamGuard: notification-prompt + Safe Browsing hardening (ported)' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'BrowserScamGuard.psm1') -Force }

    It 'is in the default set' { $script:RealDefaultModules | Should -Contain 'BrowserScamGuard' }

    It 'Hardening -Remediate blocks notification prompts and raises Safe Browsing for Edge and Chrome' {
        Mock -ModuleName BrowserScamGuard Test-Path { $false }
        Mock -ModuleName BrowserScamGuard New-Item { }
        Mock -ModuleName BrowserScamGuard Set-ItemProperty { }
        Mock -ModuleName BrowserScamGuard Set-Content { }

        Invoke-BrowserScamGuardHardening -Remediate | Out-Null

        Should -Invoke -ModuleName BrowserScamGuard Set-ItemProperty -Times 1 -ParameterFilter {
            $Path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -and $Name -eq 'DefaultNotificationsSetting' -and $Value -eq 2
        }
        Should -Invoke -ModuleName BrowserScamGuard Set-ItemProperty -Times 2 -ParameterFilter {
            $Name -eq 'SafeBrowsingProtectionLevel' -and $Value -eq 2
        }
    }

    It 'does not write without -Remediate' {
        Mock -ModuleName BrowserScamGuard Set-ItemProperty { }
        Mock -ModuleName BrowserScamGuard Set-Content { }
        Mock -ModuleName BrowserScamGuard Test-Path { $false }
        Invoke-BrowserScamGuardHardening | Out-Null
        Should -Invoke -ModuleName BrowserScamGuard Set-ItemProperty -Times 0
    }
}

Describe 'BrowserHardening: balanced max-security policy across Edge/Chrome/Firefox' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'BrowserHardening.psm1') -Force }

    It 'is in the default set' { $script:RealDefaultModules | Should -Contain 'BrowserHardening' }

    It 'Hardening -Remediate blocks dangerous downloads and disables remote-debug on Edge and Chrome' {
        Mock -ModuleName BrowserHardening Test-Path { $false }
        Mock -ModuleName BrowserHardening New-Item { }
        Mock -ModuleName BrowserHardening Set-ItemProperty { }

        Invoke-BrowserHardeningHardening -Remediate | Out-Null

        # DownloadRestrictions=1 and RemoteDebuggingAllowed=0 to both Chromium browsers.
        Should -Invoke -ModuleName BrowserHardening Set-ItemProperty -Times 2 -ParameterFilter { $Name -eq 'DownloadRestrictions' -and $Value -eq 1 }
        Should -Invoke -ModuleName BrowserHardening Set-ItemProperty -Times 2 -ParameterFilter { $Name -eq 'RemoteDebuggingAllowed' -and $Value -eq 0 }
        # Edge-only Enhanced Security Mode.
        Should -Invoke -ModuleName BrowserHardening Set-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'EnhanceSecurityMode' -and $Path -match 'Edge' }
        # Firefox telemetry off.
        Should -Invoke -ModuleName BrowserHardening Set-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'DisableTelemetry' -and $Path -match 'Mozilla' }
    }

    It 'does not block third-party cookies unless -Strict (balance)' {
        Mock -ModuleName BrowserHardening Test-Path { $false }
        Mock -ModuleName BrowserHardening New-Item { }
        Mock -ModuleName BrowserHardening Set-ItemProperty { }

        Invoke-BrowserHardeningHardening -Remediate | Out-Null
        Should -Invoke -ModuleName BrowserHardening Set-ItemProperty -Times 0 -ParameterFilter { $Name -eq 'BlockThirdPartyCookies' }

        Invoke-BrowserHardeningHardening -Remediate -Strict | Out-Null
        Should -Invoke -ModuleName BrowserHardening Set-ItemProperty -Times 2 -ParameterFilter { $Name -eq 'BlockThirdPartyCookies' -and $Value -eq 1 }
    }

    It 'keeps the password manager and DevTools working (balance - never disables them)' {
        $src = Get-Content (Join-Path $script:ModulesRoot 'BrowserHardening.psm1') -Raw
        $src | Should -Not -Match 'PasswordManagerEnabled'
        $src | Should -Not -Match 'DeveloperToolsAvailability'
        $src | Should -Not -Match 'HttpsOnlyMode'   # no forced HTTPS-Only (breaks http router pages)
    }

    It 'does not write without -Remediate' {
        Mock -ModuleName BrowserHardening Set-ItemProperty { }
        Invoke-BrowserHardeningHardening | Out-Null
        Should -Invoke -ModuleName BrowserHardening Set-ItemProperty -Times 0
    }

    It 'Rollback -Remediate removes the policy values' {
        Mock -ModuleName BrowserHardening Remove-ItemProperty { }
        Mock -ModuleName BrowserHardening Remove-Item { }
        Invoke-BrowserHardeningRollback -Remediate | Out-Null
        Should -Invoke -ModuleName BrowserHardening Remove-ItemProperty -ParameterFilter { $Name -eq 'DownloadRestrictions' }
    }
}

Describe 'RemovableMediaGuard: AutoRun/AutoPlay prompt lockdown (ported, storage preserved)' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'RemovableMediaGuard.psm1') -Force }

    It 'is in the default set' { $script:RealDefaultModules | Should -Contain 'RemovableMediaGuard' }

    It 'Hardening -Remediate sets NoDriveTypeAutoRun=255 (prompt off, storage still usable)' {
        Mock -ModuleName RemovableMediaGuard Test-Path { $false }
        Mock -ModuleName RemovableMediaGuard New-Item { }
        Mock -ModuleName RemovableMediaGuard Set-ItemProperty { }
        $result = Invoke-RemovableMediaGuardHardening -Remediate
        Should -Invoke -ModuleName RemovableMediaGuard Set-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'NoDriveTypeAutoRun' -and $Value -eq 255 }
        ($result -join "`n") | Should -Match 'still'
    }
}

Describe 'PhishingAttachmentGuard: Mark-of-the-Web enforcement (registry reimplementation)' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'PhishingAttachmentGuard.psm1') -Force }

    It 'is in the default set' { $script:RealDefaultModules | Should -Contain 'PhishingAttachmentGuard' }

    It 'Hardening -Remediate preserves MOTW (SaveZoneInformation=2) and forces AV scan (=3)' {
        Mock -ModuleName PhishingAttachmentGuard Test-Path { $false }
        Mock -ModuleName PhishingAttachmentGuard New-Item { }
        Mock -ModuleName PhishingAttachmentGuard Set-ItemProperty { }

        Invoke-PhishingAttachmentGuardHardening -Remediate | Out-Null

        Should -Invoke -ModuleName PhishingAttachmentGuard Set-ItemProperty -ParameterFilter { $Name -eq 'SaveZoneInformation' -and $Value -eq 2 }
        Should -Invoke -ModuleName PhishingAttachmentGuard Set-ItemProperty -ParameterFilter { $Name -eq 'ScanWithAntiVirus' -and $Value -eq 3 }
    }

    It 'does not write without -Remediate' {
        Mock -ModuleName PhishingAttachmentGuard Set-ItemProperty { }
        Mock -ModuleName PhishingAttachmentGuard Test-Path { $false }
        Invoke-PhishingAttachmentGuardHardening | Out-Null
        Should -Invoke -ModuleName PhishingAttachmentGuard Set-ItemProperty -Times 0
    }
}

Describe 'RunDialogLockdown: Win+R removal (ported, opt-in)' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'RunDialogLockdown.psm1') -Force }

    It 'is NOT in the default set' { $script:RealDefaultModules | Should -Not -Contain 'RunDialogLockdown' }

    It 'Hardening -Remediate sets NoRun=1' {
        Mock -ModuleName RunDialogLockdown Test-Path { $false }
        Mock -ModuleName RunDialogLockdown New-Item { }
        Mock -ModuleName RunDialogLockdown Set-ItemProperty { }
        Invoke-RunDialogLockdownHardening -Remediate | Out-Null
        Should -Invoke -ModuleName RunDialogLockdown Set-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'NoRun' -and $Value -eq 1 }
    }
}

Describe 'OfficeMacroGuard: Defender ASR macro rules (ported, opt-in)' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'OfficeMacroGuard.psm1') -Force }

    It 'is NOT in the default set' { $script:RealDefaultModules | Should -Not -Contain 'OfficeMacroGuard' }

    It 'Hardening -Remediate enables both ASR rule GUIDs when Defender is present' {
        Mock -ModuleName OfficeMacroGuard Get-Command { [pscustomobject]@{} }
        Mock -ModuleName OfficeMacroGuard Add-MpPreference { }
        Invoke-OfficeMacroGuardHardening -Remediate | Out-Null
        Should -Invoke -ModuleName OfficeMacroGuard Add-MpPreference -Times 1 -ParameterFilter { $AttackSurfaceReductionRules_Ids -eq 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' }
        Should -Invoke -ModuleName OfficeMacroGuard Add-MpPreference -Times 1 -ParameterFilter { $AttackSurfaceReductionRules_Ids -eq '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' }
    }

    It 'reports gracefully when Defender cmdlets are unavailable' {
        Mock -ModuleName OfficeMacroGuard Get-Command { $null }
        (Invoke-OfficeMacroGuardHardening -Remediate) -join ' ' | Should -Match 'not present'
    }
}

# --- Retrospective additions ---

Describe 'UacHardening: secure-desktop UAC + Admin Approval Mode' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'UacHardening.psm1') -Force }

    It 'is in the default set' { $script:RealDefaultModules | Should -Contain 'UacHardening' }

    It 'Hardening -Remediate sets consent-on-secure-desktop and admin approval mode' {
        Mock -ModuleName UacHardening Test-Path { $false }
        Mock -ModuleName UacHardening New-Item { }
        Mock -ModuleName UacHardening Set-ItemProperty { }
        Invoke-UacHardeningHardening -Remediate | Out-Null
        Should -Invoke -ModuleName UacHardening Set-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'ConsentPromptBehaviorAdmin' -and $Value -eq 2 }
        Should -Invoke -ModuleName UacHardening Set-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'FilterAdministratorToken' -and $Value -eq 1 }
    }

    It 'Rollback restores Windows defaults (never deletes EnableLUA)' {
        Mock -ModuleName UacHardening Set-ItemProperty { }
        Invoke-UacHardeningRollback -Remediate | Out-Null
        Should -Invoke -ModuleName UacHardening Set-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'ConsentPromptBehaviorAdmin' -and $Value -eq 5 }
        Should -Invoke -ModuleName UacHardening Set-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'EnableLUA' -and $Value -eq 1 }
    }
}

Describe 'DiskImageMountGuard: disable ISO/VHD double-click auto-mount' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'DiskImageMountGuard.psm1') -Force }

    It 'is in the default set' { $script:RealDefaultModules | Should -Contain 'DiskImageMountGuard' }

    It 'Hardening -Remediate marks the mount verb ProgrammaticAccessOnly when present' {
        Mock -ModuleName DiskImageMountGuard Test-Path { $true }
        Mock -ModuleName DiskImageMountGuard Set-ItemProperty { }
        Invoke-DiskImageMountGuardHardening -Remediate | Out-Null
        Should -Invoke -ModuleName DiskImageMountGuard Set-ItemProperty -Times 2 -ParameterFilter { $Name -eq 'ProgrammaticAccessOnly' }
    }

    It 'does nothing when the mount verb is not present' {
        Mock -ModuleName DiskImageMountGuard Test-Path { $false }
        Mock -ModuleName DiskImageMountGuard Set-ItemProperty { }
        Invoke-DiskImageMountGuardHardening -Remediate | Out-Null
        Should -Invoke -ModuleName DiskImageMountGuard Set-ItemProperty -Times 0
    }
}

Describe 'SmartScreenOsGuard: OS SmartScreen = Block + PUA' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'SmartScreenOsGuard.psm1') -Force }

    It 'is in the default set' { $script:RealDefaultModules | Should -Contain 'SmartScreenOsGuard' }

    It 'Hardening -Remediate sets ShellSmartScreenLevel=Block and PUAProtection=1' {
        Mock -ModuleName SmartScreenOsGuard Test-Path { $false }
        Mock -ModuleName SmartScreenOsGuard New-Item { }
        Mock -ModuleName SmartScreenOsGuard Set-ItemProperty { }
        Invoke-SmartScreenOsGuardHardening -Remediate | Out-Null
        Should -Invoke -ModuleName SmartScreenOsGuard Set-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'ShellSmartScreenLevel' -and $Value -eq 'Block' }
        Should -Invoke -ModuleName SmartScreenOsGuard Set-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'PUAProtection' -and $Value -eq 1 }
    }
}

Describe 'UpdateAssurance: enforce automatic updates' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'UpdateAssurance.psm1') -Force }

    It 'is in the default set' { $script:RealDefaultModules | Should -Contain 'UpdateAssurance' }

    It 'Hardening -Remediate sets NoAutoUpdate=0 and AUOptions=4' {
        Mock -ModuleName UpdateAssurance Test-Path { $false }
        Mock -ModuleName UpdateAssurance New-Item { }
        Mock -ModuleName UpdateAssurance Set-ItemProperty { }
        Mock -ModuleName UpdateAssurance Get-Service { $null }
        Invoke-UpdateAssuranceHardening -Remediate | Out-Null
        Should -Invoke -ModuleName UpdateAssurance Set-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'NoAutoUpdate' -and $Value -eq 0 }
        Should -Invoke -ModuleName UpdateAssurance Set-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'AUOptions' -and $Value -eq 4 }
    }
}

Describe 'DnsFilterGuard: filtering resolver (opt-in)' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'DnsFilterGuard.psm1') -Force }

    It 'is NOT in the default set' { $script:RealDefaultModules | Should -Not -Contain 'DnsFilterGuard' }

    It 'Hardening -Remediate sets Quad9 by default' {
        Mock -ModuleName DnsFilterGuard Get-DnsFilterGuardTargetInterface { [pscustomobject]@{ InterfaceIndex = 5; InterfaceAlias = 'Wi-Fi' } }
        Mock -ModuleName DnsFilterGuard Set-DnsClientServerAddress { }
        Mock -ModuleName DnsFilterGuard Invoke-Expression { }   # guard, unused
        Invoke-DnsFilterGuardHardening -Remediate | Out-Null
        Should -Invoke -ModuleName DnsFilterGuard Set-DnsClientServerAddress -Times 1 -ParameterFilter { $ServerAddresses -contains '9.9.9.9' }
    }

    It 'Provider=Cloudflare uses the Cloudflare malware resolver' {
        Mock -ModuleName DnsFilterGuard Get-DnsFilterGuardTargetInterface { [pscustomobject]@{ InterfaceIndex = 5; InterfaceAlias = 'Wi-Fi' } }
        Mock -ModuleName DnsFilterGuard Set-DnsClientServerAddress { }
        Invoke-DnsFilterGuardHardening -Remediate -Provider Cloudflare | Out-Null
        Should -Invoke -ModuleName DnsFilterGuard Set-DnsClientServerAddress -Times 1 -ParameterFilter { $ServerAddresses -contains '1.1.1.2' }
    }

    It 'Rollback resets interfaces to DHCP' {
        Mock -ModuleName DnsFilterGuard Get-DnsFilterGuardTargetInterface { [pscustomobject]@{ InterfaceIndex = 5; InterfaceAlias = 'Wi-Fi' } }
        Mock -ModuleName DnsFilterGuard Set-DnsClientServerAddress { }
        Invoke-DnsFilterGuardRollback -Remediate | Out-Null
        Should -Invoke -ModuleName DnsFilterGuard Set-DnsClientServerAddress -Times 1 -ParameterFilter { $ResetServerAddresses -eq $true }
    }
}

Describe 'RansomwareResilience: Controlled Folder Access (opt-in)' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'RansomwareResilience.psm1') -Force }

    It 'is NOT in the default set' { $script:RealDefaultModules | Should -Not -Contain 'RansomwareResilience' }

    It 'Hardening -Remediate enables Controlled Folder Access when Defender is present' {
        Mock -ModuleName RansomwareResilience Get-Command { [pscustomobject]@{} }
        Mock -ModuleName RansomwareResilience Set-MpPreference { }
        Mock -ModuleName RansomwareResilience Enable-ComputerRestore { }
        Mock -ModuleName RansomwareResilience Test-Path { $true }
        Mock -ModuleName RansomwareResilience Set-ItemProperty { }
        Invoke-RansomwareResilienceHardening -Remediate | Out-Null
        Should -Invoke -ModuleName RansomwareResilience Set-MpPreference -Times 1 -ParameterFilter { $EnableControlledFolderAccess -eq 'Enabled' }
    }

    It 'Mode=Audit uses AuditMode' {
        Mock -ModuleName RansomwareResilience Get-Command { [pscustomobject]@{} }
        Mock -ModuleName RansomwareResilience Set-MpPreference { }
        Mock -ModuleName RansomwareResilience Enable-ComputerRestore { }
        Mock -ModuleName RansomwareResilience Test-Path { $true }
        Mock -ModuleName RansomwareResilience Set-ItemProperty { }
        Invoke-RansomwareResilienceHardening -Remediate -Mode Audit | Out-Null
        Should -Invoke -ModuleName RansomwareResilience Set-MpPreference -Times 1 -ParameterFilter { $EnableControlledFolderAccess -eq 'AuditMode' }
    }
}

Describe 'OfficeHardening: document-borne attack chain (opt-in, conditional)' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'OfficeHardening.psm1') -Force }

    It 'is NOT in the default set' { $script:RealDefaultModules | Should -Not -Contain 'OfficeHardening' }

    It 'auto-skips when desktop Office is not installed' {
        Mock -ModuleName OfficeHardening Test-OfficeInstalled { $false }
        Mock -ModuleName OfficeHardening Set-ItemProperty { }
        $r = Invoke-OfficeHardeningHardening -Remediate
        Should -Invoke -ModuleName OfficeHardening Set-ItemProperty -Times 0
        ($r -join ' ') | Should -Match 'not detected'
    }

    It 'blocks macros-from-internet when Office is installed' {
        Mock -ModuleName OfficeHardening Test-OfficeInstalled { $true }
        Mock -ModuleName OfficeHardening Test-Path { $false }
        Mock -ModuleName OfficeHardening New-Item { }
        Mock -ModuleName OfficeHardening Set-ItemProperty { }
        Invoke-OfficeHardeningHardening -Remediate | Out-Null
        Should -Invoke -ModuleName OfficeHardening Set-ItemProperty -Times 3 -ParameterFilter { $Name -eq 'blockcontentexecutionfrominternet' -and $Value -eq 1 }
    }
}

Describe 'RemoteAccessToolGuard: block RATs by filename via IFEO (registry reimplementation)' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'RemoteAccessToolGuard.psm1') -Force }

    It 'is NOT in the default set' { $script:RealDefaultModules | Should -Not -Contain 'RemoteAccessToolGuard' }

    It 'covers the scam-tool filenames (AnyDesk, UltraViewer, TeamViewer QuickSupport)' {
        $names = (Get-RemoteAccessToolGuardTarget).FileName
        foreach ($exe in 'AnyDesk.exe', 'UltraViewer_Desktop.exe', 'TeamViewerQS.exe') {
            $names | Should -Contain $exe
        }
    }

    It 'Hardening -Remediate writes an IFEO Debugger redirect per tool' {
        Mock -ModuleName RemoteAccessToolGuard Test-Path { $false }
        Mock -ModuleName RemoteAccessToolGuard New-Item { }
        Mock -ModuleName RemoteAccessToolGuard Set-ItemProperty { }

        Invoke-RemoteAccessToolGuardHardening -Remediate | Out-Null

        $toolCount = (Get-RemoteAccessToolGuardTarget).Count
        Should -Invoke -ModuleName RemoteAccessToolGuard Set-ItemProperty -Times $toolCount -ParameterFilter {
            $Name -eq 'Debugger' -and $Path -match 'Image File Execution Options'
        }
    }

    It 'Rollback -Remediate removes every IFEO key' {
        Mock -ModuleName RemoteAccessToolGuard Test-Path { $true }
        Mock -ModuleName RemoteAccessToolGuard Remove-Item { }
        Mock -ModuleName RemoteAccessToolGuard Get-LocalUser { $null }
        Invoke-RemoteAccessToolGuardRollback -Remediate | Out-Null
        $toolCount = (Get-RemoteAccessToolGuardTarget).Count
        Should -Invoke -ModuleName RemoteAccessToolGuard Remove-Item -Times $toolCount
    }

    It 'Enable-RemoteAccessToolGuardSupportSession -Remediate creates a non-admin account' {
        Mock -ModuleName RemoteAccessToolGuard Get-LocalUser { $null }
        Mock -ModuleName RemoteAccessToolGuard New-LocalUser { }
        Mock -ModuleName RemoteAccessToolGuard Remove-LocalGroupMember { }
        $result = Enable-RemoteAccessToolGuardSupportSession -Remediate -DurationHours 2
        Should -Invoke -ModuleName RemoteAccessToolGuard New-LocalUser -Times 1 -ParameterFilter { $Name -eq 'RemoteSupport' }
        Should -Invoke -ModuleName RemoteAccessToolGuard Remove-LocalGroupMember -Times 1 -ParameterFilter { "$Group" -eq 'Administrators' }
        ($result -join "`n") | Should -Match 'Created/enabled'
    }
}
