#Requires -Module Pester

<#
.SYNOPSIS
    Contract tests for every module under modules\*.psm1, plus dedicated remediation-path tests
    for each shipped module (registry/Defender calls mocked - these tests never touch the real
    registry or change real machine state).
#>

BeforeAll {
    $script:Root = Join-Path $PSScriptRoot '..'
    $script:ModulesRoot = Join-Path $script:Root 'modules'
    $script:ModuleFiles = Get-ChildItem -LiteralPath $script:ModulesRoot -Filter '*.psm1' -File

    # Parse the orchestrator's real $DefaultModules line so "is/isn't default" assertions stay
    # honest about the actual shipped configuration instead of a hand-copied list going stale.
    $orchestratorSource = Get-Content (Join-Path $script:Root 'Invoke-AppLockerBaseline.ps1') -Raw
    if ($orchestratorSource -notmatch '\$DefaultModules\s*=\s*@\(([^)]*)\)') {
        throw 'Could not locate $DefaultModules in Invoke-AppLockerBaseline.ps1 - has it been renamed?'
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

    It 'Get-<Name>PolicyFragment (if present) returns well-formed AppLocker rule fragments' {
        $fn = "Get-${script:ModName}PolicyFragment"
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because "$script:ModName does not export $fn"
            return
        }
        $fragments = @(& $fn)
        $fragments.Count | Should -BeGreaterThan 0

        foreach ($f in $fragments) {
            $f.CollectionType | Should -BeIn @('Dll', 'Exe', 'Msi', 'Script', 'Appx')
            $f.Name | Should -Not -BeNullOrEmpty

            $ruleDoc = [xml]$f.Xml
            $ruleDoc.DocumentElement.LocalName | Should -BeIn @('FilePathRule', 'FilePublisherRule', 'FileHashRule')
            $ruleDoc.DocumentElement.Id | Should -Match '^[0-9a-fA-F-]{36}$'
            $ruleDoc.DocumentElement.Action | Should -BeIn @('Allow', 'Deny')
            $ruleDoc.DocumentElement.UserOrGroupSid | Should -Not -BeNullOrEmpty
            $ruleDoc.DocumentElement.Description | Should -Not -BeNullOrEmpty
            $ruleDoc.DocumentElement.Conditions | Should -Not -BeNullOrEmpty

            # Regression guard: AppLocker only resolves %WINDIR%, %SYSTEM32%, %OSDRIVE%, and
            # %PROGRAMFILES% as path variables. Any other %TOKEN% (e.g. %PROGRAMDATA%, %APPDATA%,
            # %LOCALAPPDATA%, %USERPROFILE%, %TEMP%) is NOT resolved - the rule silently matches
            # nothing instead of erroring, which is exactly how DefenderCompatibility's first
            # version went undetected (denies/blocks just kept happening, no error anywhere).
            if ($ruleDoc.DocumentElement.LocalName -eq 'FilePathRule') {
                foreach ($path in $ruleDoc.FilePathRule.Conditions.FilePathCondition.Path) {
                    $tokens = [regex]::Matches($path, '%[A-Z0-9_]+%') | ForEach-Object { $_.Value }
                    foreach ($token in $tokens) {
                        $token | Should -BeIn @('%WINDIR%', '%SYSTEM32%', '%OSDRIVE%', '%PROGRAMFILES%') -Because "'$token' in '$path' is not a real AppLocker path variable and will never match"
                    }
                }
            }
        }
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
    }

    It 'Invoke-<Name>Rollback (if present) is a no-op dry run without -Remediate' {
        $fn = "Invoke-${script:ModName}Rollback"
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because "$script:ModName does not export $fn"
            return
        }
        { & $fn } | Should -Not -Throw
    }
}

Describe 'ClickFix module: targets wscript/cscript/mshta + disables WSH' {

    BeforeAll {
        Import-Module (Join-Path $script:ModulesRoot 'ClickFix.psm1') -Force
    }

    It 'denies wscript.exe, cscript.exe, and mshta.exe under both System32 and SysWOW64' {
        $fragments = Get-ClickFixPolicyFragment
        $paths = $fragments | ForEach-Object { ([xml]$_.Xml).FilePathRule.Conditions.FilePathCondition.Path }

        foreach ($bin in 'wscript.exe', 'cscript.exe', 'mshta.exe') {
            ($paths | Where-Object { $_ -match [regex]::Escape($bin) }).Count | Should -Be 2
        }
        $fragments | ForEach-Object { $_.CollectionType | Should -Be 'Exe' }
        $fragments | ForEach-Object { ([xml]$_.Xml).FilePathRule.Action | Should -Be 'Deny' }
    }

    It 'Invoke-ClickFixHardening -Remediate disables Windows Script Host via the registry' {
        Mock -ModuleName ClickFix Test-Path { $false }
        Mock -ModuleName ClickFix New-Item { }
        Mock -ModuleName ClickFix Set-ItemProperty { }

        $result = Invoke-ClickFixHardening -Remediate

        Should -Invoke -ModuleName ClickFix New-Item -Times 1
        Should -Invoke -ModuleName ClickFix Set-ItemProperty -Times 1 -ParameterFilter {
            $Name -eq 'Enabled' -and $Value -eq 0
        }
        $result | Should -Match 'Disabled Windows Script Host'
    }

    It 'does not touch the registry without -Remediate' {
        Mock -ModuleName ClickFix Set-ItemProperty { }
        Mock -ModuleName ClickFix New-Item { }

        Invoke-ClickFixHardening | Out-Null

        Should -Invoke -ModuleName ClickFix Set-ItemProperty -Times 0
        Should -Invoke -ModuleName ClickFix New-Item -Times 0
    }
}

Describe 'RunDialogLockdown module: opt-in Win+R removal' {

    BeforeAll {
        Import-Module (Join-Path $script:ModulesRoot 'RunDialogLockdown.psm1') -Force
    }

    It 'is not in the orchestrator default module set' {
        $script:RealDefaultModules | Should -Not -Contain 'RunDialogLockdown'
    }

    It 'exports no AppLocker policy fragment - it is registry-only' {
        Get-Command Get-RunDialogLockdownPolicyFragment -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }

    It 'Invoke-RunDialogLockdownHardening -Remediate sets NoRun = 1' {
        Mock -ModuleName RunDialogLockdown Test-Path { $false }
        Mock -ModuleName RunDialogLockdown New-Item { }
        Mock -ModuleName RunDialogLockdown Set-ItemProperty { }

        $result = Invoke-RunDialogLockdownHardening -Remediate

        Should -Invoke -ModuleName RunDialogLockdown Set-ItemProperty -Times 1 -ParameterFilter {
            $Name -eq 'NoRun' -and $Value -eq 1
        }
        $result | Should -Match 'Disabled the Run dialog'
    }
}

Describe 'PhishingAttachmentGuard module: Outlook/browser-cache execution denies' {

    BeforeAll {
        Import-Module (Join-Path $script:ModulesRoot 'PhishingAttachmentGuard.psm1') -Force
    }

    It 'is in the orchestrator default module set' {
        $script:RealDefaultModules | Should -Contain 'PhishingAttachmentGuard'
    }

    It 'denies Exe and Script execution from Outlook temp and every major browser cache' {
        $fragments = Get-PhishingAttachmentGuardPolicyFragment
        $paths = $fragments | ForEach-Object { ([xml]$_.Xml).FilePathRule.Conditions.FilePathCondition.Path }

        foreach ($needle in 'Content.Outlook', 'INetCache', 'Edge\User Data', 'Chrome\User Data', 'Firefox\Profiles') {
            ($paths | Where-Object { $_ -match [regex]::Escape($needle) }) | Should -Not -BeNullOrEmpty -Because "expected a rule covering '$needle'"
        }

        $collectionTypes = $fragments | ForEach-Object { $_.CollectionType } | Sort-Object -Unique
        $collectionTypes | Should -Be @('Exe', 'Script')
        $fragments | ForEach-Object { ([xml]$_.Xml).FilePathRule.Action | Should -Be 'Deny' }
    }

    It 'deliberately does not deny the Downloads folder (legitimate installer execution)' {
        $fragments = Get-PhishingAttachmentGuardPolicyFragment
        $paths = $fragments | ForEach-Object { ([xml]$_.Xml).FilePathRule.Conditions.FilePathCondition.Path }
        $paths | Where-Object { $_ -match '\\Downloads\\' } | Should -BeNullOrEmpty -Because 'Downloads is a deliberate, legitimate save location - blocking it would catch normal installer downloads, not just attacks'
    }

    It 'exports no Hardening function - it is policy-only' {
        Get-Command Invoke-PhishingAttachmentGuardHardening -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }
}

Describe 'RemoteAccessToolGuard module: opt-in tech-support-scam RAT denies' {

    BeforeAll {
        Import-Module (Join-Path $script:ModulesRoot 'RemoteAccessToolGuard.psm1') -Force
    }

    It 'is not in the orchestrator default module set' {
        $script:RealDefaultModules | Should -Not -Contain 'RemoteAccessToolGuard'
    }

    It 'denies known remote-access tools by filename anywhere on disk' {
        $fragments = Get-RemoteAccessToolGuardPolicyFragment
        $paths = $fragments | ForEach-Object { ([xml]$_.Xml).FilePathRule.Conditions.FilePathCondition.Path }

        foreach ($exe in 'AnyDesk.exe', 'UltraViewer_Desktop.exe', 'TeamViewerQS.exe',
            'ScreenConnect.ClientService.exe', 'ScreenConnect.WindowsClient.exe', 'AteraAgent.exe', 'SplashtopStreamer.exe') {
            $paths | Should -Contain "*\$exe"
        }
        $fragments | ForEach-Object { $_.CollectionType | Should -Be 'Exe' }
        $fragments | ForEach-Object { ([xml]$_.Xml).FilePathRule.Action | Should -Be 'Deny' }
    }

    It 'Enable-RemoteAccessToolGuardSupportSession -Remediate creates a non-admin, time-limited account when none exists' {
        Mock -ModuleName RemoteAccessToolGuard Get-LocalUser { $null }
        Mock -ModuleName RemoteAccessToolGuard New-LocalUser { }
        Mock -ModuleName RemoteAccessToolGuard Set-LocalUser { }
        Mock -ModuleName RemoteAccessToolGuard Remove-LocalGroupMember { }

        $result = Enable-RemoteAccessToolGuardSupportSession -Remediate -DurationHours 2

        Should -Invoke -ModuleName RemoteAccessToolGuard New-LocalUser -Times 1 -ParameterFilter { $Name -eq 'RemoteSupport' }
        Should -Invoke -ModuleName RemoteAccessToolGuard Set-LocalUser -Times 0
        Should -Invoke -ModuleName RemoteAccessToolGuard Remove-LocalGroupMember -Times 1 -ParameterFilter { "$Group" -eq 'Administrators' -and "$Member" -eq 'RemoteSupport' }
        ($result -join "`n") | Should -Match 'Created/enabled'
    }

    It 'Enable-RemoteAccessToolGuardSupportSession -Remediate re-enables and extends an existing account instead of creating a new one' {
        Mock -ModuleName RemoteAccessToolGuard Get-LocalUser { [pscustomobject]@{ Name = 'RemoteSupport'; Enabled = $false } }
        Mock -ModuleName RemoteAccessToolGuard New-LocalUser { }
        Mock -ModuleName RemoteAccessToolGuard Set-LocalUser { }
        Mock -ModuleName RemoteAccessToolGuard Enable-LocalUser { }
        Mock -ModuleName RemoteAccessToolGuard Remove-LocalGroupMember { }

        Enable-RemoteAccessToolGuardSupportSession -Remediate | Out-Null

        Should -Invoke -ModuleName RemoteAccessToolGuard New-LocalUser -Times 0
        Should -Invoke -ModuleName RemoteAccessToolGuard Set-LocalUser -Times 1 -ParameterFilter { $Name -eq 'RemoteSupport' }
        Should -Invoke -ModuleName RemoteAccessToolGuard Enable-LocalUser -Times 1 -ParameterFilter { $Name -eq 'RemoteSupport' }
    }

    It 'Enable-RemoteAccessToolGuardSupportSession does not touch any account without -Remediate' {
        Mock -ModuleName RemoteAccessToolGuard New-LocalUser { }
        Mock -ModuleName RemoteAccessToolGuard Set-LocalUser { }

        $result = Enable-RemoteAccessToolGuardSupportSession

        Should -Invoke -ModuleName RemoteAccessToolGuard New-LocalUser -Times 0
        Should -Invoke -ModuleName RemoteAccessToolGuard Set-LocalUser -Times 0
        $result | Should -Match '\(dry run\)'
    }

    It 'Disable-RemoteAccessToolGuardSupportSession -Remediate disables an existing account' {
        Mock -ModuleName RemoteAccessToolGuard Get-LocalUser { [pscustomobject]@{ Name = 'RemoteSupport' } }
        Mock -ModuleName RemoteAccessToolGuard Disable-LocalUser { }

        $result = Disable-RemoteAccessToolGuardSupportSession -Remediate

        Should -Invoke -ModuleName RemoteAccessToolGuard Disable-LocalUser -Times 1 -ParameterFilter { $Name -eq 'RemoteSupport' }
        $result | Should -Match 'Disabled'
    }

    It 'Disable-RemoteAccessToolGuardSupportSession -Remediate reports when no account exists' {
        Mock -ModuleName RemoteAccessToolGuard Get-LocalUser { $null }
        Mock -ModuleName RemoteAccessToolGuard Disable-LocalUser { }

        $result = Disable-RemoteAccessToolGuardSupportSession -Remediate

        Should -Invoke -ModuleName RemoteAccessToolGuard Disable-LocalUser -Times 0
        $result | Should -Match 'No .* account found'
    }
}

Describe 'DefenderCompatibility module: allow-lists Defender''s ProgramData platform binaries' {
    <#
        Regression coverage for two real incidents, both with the same underlying cause:
        Microsoft Defender's platform binaries (MsMpEng.exe, MPOAV.DLL, etc.) install under
        ProgramData\Microsoft\Windows Defender\Platform\<version>\, which the base policy's
        allow rules (Program Files, Windows) don't cover, so AppLocker audited/blocked
        Defender's own files continuously. The first fix used "%PROGRAMDATA%" as the path
        prefix - which is NOT a real AppLocker path variable (AppLocker only resolves %WINDIR%,
        %SYSTEM32%, %OSDRIVE%, %PROGRAMFILES%), so that rule silently matched nothing and the
        blocking continued. The real fix uses %OSDRIVE%\ProgramData instead.
    #>

    BeforeAll {
        Import-Module (Join-Path $script:ModulesRoot 'DefenderCompatibility.psm1') -Force
    }

    It 'is in the orchestrator default module set' {
        $script:RealDefaultModules | Should -Contain 'DefenderCompatibility'
    }

    It 'allows Exe, Dll, and Script execution from the Defender Platform folder using a real AppLocker macro' {
        $fragments = Get-DefenderCompatibilityPolicyFragment
        $collectionTypes = $fragments | ForEach-Object { $_.CollectionType } | Sort-Object -Unique
        $collectionTypes | Should -Be @('Dll', 'Exe', 'Script')

        foreach ($f in $fragments) {
            $rule = ([xml]$f.Xml).FilePathRule
            $rule.Action | Should -Be 'Allow'
            $rule.Conditions.FilePathCondition.Path | Should -Be '%OSDRIVE%\ProgramData\Microsoft\Windows Defender\Platform\*'
            $rule.Conditions.FilePathCondition.Path | Should -Not -Match '%PROGRAMDATA%'
        }
    }

    It 'exports no Hardening function - it is policy-only' {
        Get-Command Invoke-DefenderCompatibilityHardening -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }
}

Describe 'RemovableMediaGuard module: AutoRun/AutoPlay lockdown' {

    BeforeAll {
        Import-Module (Join-Path $script:ModulesRoot 'RemovableMediaGuard.psm1') -Force
    }

    It 'is in the orchestrator default module set' {
        $script:RealDefaultModules | Should -Contain 'RemovableMediaGuard'
    }

    It 'exports no AppLocker policy fragment - it is registry-only' {
        Get-Command Get-RemovableMediaGuardPolicyFragment -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }

    It 'Invoke-RemovableMediaGuardHardening -Remediate disables AutoRun for all drive types' {
        Mock -ModuleName RemovableMediaGuard Test-Path { $false }
        Mock -ModuleName RemovableMediaGuard New-Item { }
        Mock -ModuleName RemovableMediaGuard Set-ItemProperty { }

        $result = Invoke-RemovableMediaGuardHardening -Remediate

        Should -Invoke -ModuleName RemovableMediaGuard Set-ItemProperty -Times 1 -ParameterFilter {
            $Name -eq 'NoDriveTypeAutoRun' -and $Value -eq 255
        }
        $result | Should -Match 'Disabled AutoRun/AutoPlay'
    }

    It 'does not touch the registry without -Remediate' {
        Mock -ModuleName RemovableMediaGuard Set-ItemProperty { }
        Invoke-RemovableMediaGuardHardening | Out-Null
        Should -Invoke -ModuleName RemovableMediaGuard Set-ItemProperty -Times 0
    }
}

Describe 'ExplorerVisibilityHardening module: show known file extensions' {

    BeforeAll {
        Import-Module (Join-Path $script:ModulesRoot 'ExplorerVisibilityHardening.psm1') -Force
    }

    It 'is in the orchestrator default module set' {
        $script:RealDefaultModules | Should -Contain 'ExplorerVisibilityHardening'
    }

    It 'Invoke-ExplorerVisibilityHardeningHardening -Remediate sets HideFileExt = 0 for current user and Default profile' {
        Mock -ModuleName ExplorerVisibilityHardening Test-Path { $false }
        Mock -ModuleName ExplorerVisibilityHardening New-Item { }
        Mock -ModuleName ExplorerVisibilityHardening Set-ItemProperty { }

        $result = Invoke-ExplorerVisibilityHardeningHardening -Remediate

        Should -Invoke -ModuleName ExplorerVisibilityHardening Set-ItemProperty -Times 2 -ParameterFilter {
            $Name -eq 'HideFileExt' -and $Value -eq 0
        }
        $result.Count | Should -Be 2
    }

    It 'does not touch the registry without -Remediate' {
        Mock -ModuleName ExplorerVisibilityHardening Set-ItemProperty { }
        Invoke-ExplorerVisibilityHardeningHardening | Out-Null
        Should -Invoke -ModuleName ExplorerVisibilityHardening Set-ItemProperty -Times 0
    }
}

Describe 'OfficeMacroGuard module: opt-in Defender ASR rules for Office macros' {

    BeforeAll {
        Import-Module (Join-Path $script:ModulesRoot 'OfficeMacroGuard.psm1') -Force
    }

    It 'is not in the orchestrator default module set' {
        $script:RealDefaultModules | Should -Not -Contain 'OfficeMacroGuard'
    }

    It 'reports gracefully when Defender cmdlets are unavailable, without throwing' {
        Mock -ModuleName OfficeMacroGuard Get-Command { $null }

        $status = Get-OfficeMacroGuardStatus
        $hardening = Invoke-OfficeMacroGuardHardening -Remediate

        $status | Should -Match 'not present'
        $hardening | Should -Match 'not present'
    }

    It 'Invoke-OfficeMacroGuardHardening -Remediate enables both ASR rules when Defender is present' {
        Mock -ModuleName OfficeMacroGuard Get-Command { [pscustomobject]@{} }
        Mock -ModuleName OfficeMacroGuard Add-MpPreference { }

        Invoke-OfficeMacroGuardHardening -Remediate | Out-Null

        Should -Invoke -ModuleName OfficeMacroGuard Add-MpPreference -Times 1 -ParameterFilter {
            $AttackSurfaceReductionRules_Ids -eq 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' -and $AttackSurfaceReductionRules_Actions -eq 'Enabled'
        }
        Should -Invoke -ModuleName OfficeMacroGuard Add-MpPreference -Times 1 -ParameterFilter {
            $AttackSurfaceReductionRules_Ids -eq '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' -and $AttackSurfaceReductionRules_Actions -eq 'Enabled'
        }
    }

    It 'does not call Add-MpPreference without -Remediate' {
        Mock -ModuleName OfficeMacroGuard Get-Command { [pscustomobject]@{} }
        Mock -ModuleName OfficeMacroGuard Add-MpPreference { }

        Invoke-OfficeMacroGuardHardening | Out-Null

        Should -Invoke -ModuleName OfficeMacroGuard Add-MpPreference -Times 0
    }

    It 'Get-OfficeMacroGuardStatus reports each rule''s configured action' {
        Mock -ModuleName OfficeMacroGuard Get-Command { [pscustomobject]@{} }
        Mock -ModuleName OfficeMacroGuard Get-MpPreference {
            [pscustomobject]@{
                AttackSurfaceReductionRules_Ids     = @('D4F940AB-401B-4EFC-AADC-AD5F3C50688A')
                AttackSurfaceReductionRules_Actions = @(1)
            }
        }

        $status = Get-OfficeMacroGuardStatus

        ($status | Where-Object { $_ -match 'child processes' }) | Should -Match 'Block'
        ($status | Where-Object { $_ -match 'Win32 API' }) | Should -Match 'NotConfigured'
    }
}

Describe 'BrowserScamGuard module: scam-popup/notification + Safe Browsing hardening' {

    BeforeAll {
        Import-Module (Join-Path $script:ModulesRoot 'BrowserScamGuard.psm1') -Force
    }

    It 'is in the orchestrator default module set' {
        $script:RealDefaultModules | Should -Contain 'BrowserScamGuard'
    }

    It 'exports no AppLocker policy fragment - it manages browser policy, not AppLocker rules' {
        Get-Command Get-BrowserScamGuardPolicyFragment -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }

    It 'Invoke-BrowserScamGuardHardening -Remediate blocks notification prompts and raises Safe Browsing for Edge and Chrome' {
        Mock -ModuleName BrowserScamGuard Test-Path { $false }
        Mock -ModuleName BrowserScamGuard New-Item { }
        Mock -ModuleName BrowserScamGuard Set-ItemProperty { }
        Mock -ModuleName BrowserScamGuard Set-Content { }

        $result = Invoke-BrowserScamGuardHardening -Remediate

        Should -Invoke -ModuleName BrowserScamGuard Set-ItemProperty -Times 1 -ParameterFilter {
            $Path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -and $Name -eq 'DefaultNotificationsSetting' -and $Value -eq 2
        }
        Should -Invoke -ModuleName BrowserScamGuard Set-ItemProperty -Times 1 -ParameterFilter {
            $Path -eq 'HKLM:\SOFTWARE\Policies\Google\Chrome' -and $Name -eq 'DefaultNotificationsSetting' -and $Value -eq 2
        }
        Should -Invoke -ModuleName BrowserScamGuard Set-ItemProperty -Times 2 -ParameterFilter {
            $Name -eq 'SafeBrowsingProtectionLevel' -and $Value -eq 2
        }
        ($result -join "`n") | Should -Match 'Edge'
        ($result -join "`n") | Should -Match 'Chrome'
    }

    It 'writes a Firefox enterprise policy blocking notifications and popups when Firefox is installed' {
        Mock -ModuleName BrowserScamGuard Test-Path { $true }
        Mock -ModuleName BrowserScamGuard New-Item { }
        Mock -ModuleName BrowserScamGuard Set-ItemProperty { }
        Mock -ModuleName BrowserScamGuard Set-Content { }

        Invoke-BrowserScamGuardHardening -Remediate | Out-Null

        Should -Invoke -ModuleName BrowserScamGuard Set-Content -ParameterFilter {
            $Path -match 'policies\.json' -and $Value -match 'DefaultNotification.*block'
        }
    }

    It 'does not touch the registry or filesystem without -Remediate' {
        Mock -ModuleName BrowserScamGuard Test-Path { $true }
        Mock -ModuleName BrowserScamGuard Set-ItemProperty { }
        Mock -ModuleName BrowserScamGuard Set-Content { }

        Invoke-BrowserScamGuardHardening | Out-Null

        Should -Invoke -ModuleName BrowserScamGuard Set-ItemProperty -Times 0
        Should -Invoke -ModuleName BrowserScamGuard Set-Content -Times 0
    }
}

Describe 'Module rollback: ClickFix removes WSH restriction' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'ClickFix.psm1') -Force }
    It '-Remediate removes the WSH Enabled registry value' {
        Mock -ModuleName ClickFix Test-Path { $true }
        Mock -ModuleName ClickFix Remove-ItemProperty { }
        $result = Invoke-ClickFixRollback -Remediate
        Should -Invoke -ModuleName ClickFix Remove-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'Enabled' }
        $result | Should -Match 'Re-enabled Windows Script Host'
    }
    It 'dry run does not call Remove-ItemProperty' {
        Mock -ModuleName ClickFix Remove-ItemProperty { }
        Invoke-ClickFixRollback | Out-Null
        Should -Invoke -ModuleName ClickFix Remove-ItemProperty -Times 0
    }
}

Describe 'Module rollback: RunDialogLockdown restores Win+R' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'RunDialogLockdown.psm1') -Force }
    It '-Remediate removes the NoRun policy value' {
        Mock -ModuleName RunDialogLockdown Remove-ItemProperty { }
        $result = Invoke-RunDialogLockdownRollback -Remediate
        Should -Invoke -ModuleName RunDialogLockdown Remove-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'NoRun' }
        $result | Should -Match 'Restored Win\+R Run dialog'
    }
}

Describe 'Module rollback: RemovableMediaGuard restores AutoRun defaults' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'RemovableMediaGuard.psm1') -Force }
    It '-Remediate removes the NoDriveTypeAutoRun policy value' {
        Mock -ModuleName RemovableMediaGuard Remove-ItemProperty { }
        $result = Invoke-RemovableMediaGuardRollback -Remediate
        Should -Invoke -ModuleName RemovableMediaGuard Remove-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'NoDriveTypeAutoRun' }
        $result | Should -Match 'Restored AutoRun/AutoPlay defaults'
    }
}

Describe 'Module rollback: ExplorerVisibilityHardening removes HideFileExt overrides' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'ExplorerVisibilityHardening.psm1') -Force }
    It '-Remediate removes HideFileExt from both HKCU and Default profile and restarts Explorer' {
        Mock -ModuleName ExplorerVisibilityHardening Remove-ItemProperty { }
        Mock -ModuleName ExplorerVisibilityHardening Stop-Process { }
        $result = Invoke-ExplorerVisibilityHardeningRollback -Remediate
        Should -Invoke -ModuleName ExplorerVisibilityHardening Remove-ItemProperty -Times 2 -ParameterFilter { $Name -eq 'HideFileExt' }
        Should -Invoke -ModuleName ExplorerVisibilityHardening Stop-Process -Times 1 -ParameterFilter { $Name -eq 'explorer' }
        ($result -join "`n") | Should -Match 'Explorer restarted'
    }
}

Describe 'Module rollback: BrowserScamGuard removes browser policies' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'BrowserScamGuard.psm1') -Force }
    It '-Remediate removes Edge and Chrome policy values' {
        Mock -ModuleName BrowserScamGuard Remove-ItemProperty { }
        Mock -ModuleName BrowserScamGuard Remove-Item { }
        Mock -ModuleName BrowserScamGuard Test-Path { $false }
        $result = Invoke-BrowserScamGuardRollback -Remediate
        Should -Invoke -ModuleName BrowserScamGuard Remove-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'DefaultNotificationsSetting' -and $Path -match 'Edge' }
        Should -Invoke -ModuleName BrowserScamGuard Remove-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'DefaultNotificationsSetting' -and $Path -match 'Chrome' }
        ($result -join "`n") | Should -Match 'Edge'
        ($result -join "`n") | Should -Match 'Chrome'
    }
    It 'does not call Remove-ItemProperty without -Remediate' {
        Mock -ModuleName BrowserScamGuard Remove-ItemProperty { }
        Invoke-BrowserScamGuardRollback | Out-Null
        Should -Invoke -ModuleName BrowserScamGuard Remove-ItemProperty -Times 0
    }
}

Describe 'Module rollback: OfficeMacroGuard removes ASR rules' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'OfficeMacroGuard.psm1') -Force }
    It '-Remediate calls Remove-MpPreference for both ASR rule GUIDs' {
        Mock -ModuleName OfficeMacroGuard Get-Command { [pscustomobject]@{} }
        Mock -ModuleName OfficeMacroGuard Remove-MpPreference { }
        Invoke-OfficeMacroGuardRollback -Remediate | Out-Null
        Should -Invoke -ModuleName OfficeMacroGuard Remove-MpPreference -Times 1 -ParameterFilter { $AttackSurfaceReductionRules_Ids -eq 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' }
        Should -Invoke -ModuleName OfficeMacroGuard Remove-MpPreference -Times 1 -ParameterFilter { $AttackSurfaceReductionRules_Ids -eq '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' }
    }
}

Describe 'Module rollback: RemoteAccessToolGuard removes support account' {
    BeforeAll { Import-Module (Join-Path $script:ModulesRoot 'RemoteAccessToolGuard.psm1') -Force }
    It '-Remediate removes the RemoteSupport account when it exists' {
        Mock -ModuleName RemoteAccessToolGuard Get-LocalUser { [pscustomobject]@{ Name = 'RemoteSupport' } }
        Mock -ModuleName RemoteAccessToolGuard Remove-LocalUser { }
        $result = Invoke-RemoteAccessToolGuardRollback -Remediate
        Should -Invoke -ModuleName RemoteAccessToolGuard Remove-LocalUser -Times 1 -ParameterFilter { $Name -eq 'RemoteSupport' }
        $result | Should -Match 'Removed local account'
    }
    It '-Remediate reports cleanly when no account exists' {
        Mock -ModuleName RemoteAccessToolGuard Get-LocalUser { $null }
        Mock -ModuleName RemoteAccessToolGuard Remove-LocalUser { }
        $result = Invoke-RemoteAccessToolGuardRollback -Remediate
        Should -Invoke -ModuleName RemoteAccessToolGuard Remove-LocalUser -Times 0
        $result | Should -Match 'No .* account found'
    }
}

Describe 'WindowsAppRepository module: publisher rule for Microsoft-signed packaged app DLLs' {
    <#
        Validates the sideloading-critical properties of the Dll allow rule: it MUST be a
        FilePublisherRule (publisher-verified), not a FilePathRule (path rules can be sideloaded
        by placing a malicious DLL with a matching name in an allowed path before the real one).
        It MUST target only the Dll collection. And the publisher must be O=MICROSOFT CORPORATION
        exactly (case-insensitive checked below to match AppLocker's actual comparison).
    #>

    BeforeAll {
        Import-Module (Join-Path $script:ModulesRoot 'WindowsAppRepository.psm1') -Force
    }

    It 'is in the orchestrator default module set' {
        $script:RealDefaultModules | Should -Contain 'WindowsAppRepository'
    }

    It 'adds ONLY a Dll collection rule - Exe and Script are already covered by base policy' {
        $fragments = Get-WindowsAppRepositoryPolicyFragment
        $fragments.Count | Should -Be 1
        $fragments[0].CollectionType | Should -Be 'Dll'
    }

    It 'uses a FilePublisherRule (publisher-verified) not a FilePathRule (sideloading-vulnerable)' {
        $fragment = Get-WindowsAppRepositoryPolicyFragment
        $rule = ([xml]$fragment.Xml).DocumentElement
        $rule.LocalName | Should -Be 'FilePublisherRule'
    }

    It 'targets O=MICROSOFT CORPORATION and action Allow' {
        $fragment = Get-WindowsAppRepositoryPolicyFragment
        $rule = ([xml]$fragment.Xml).FilePublisherRule
        $rule.Action | Should -Be 'Allow'
        $rule.Conditions.FilePublisherCondition.PublisherName | Should -Match 'O=MICROSOFT CORPORATION'
    }

    It 'has no FilePathCondition (confirming no path-based sideloading vector)' {
        $fragment = Get-WindowsAppRepositoryPolicyFragment
        ([xml]$fragment.Xml).SelectNodes('//FilePathCondition').Count | Should -Be 0
    }

    It 'is default-on and the policy description explains why publisher rule is used' {
        $fragment = Get-WindowsAppRepositoryPolicyFragment
        ([xml]$fragment.Xml).FilePublisherRule.Description | Should -Match 'publisher'
        ([xml]$fragment.Xml).FilePublisherRule.Description | Should -Match 'sideload'
    }
}
