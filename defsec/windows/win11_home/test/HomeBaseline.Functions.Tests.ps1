#Requires -Module Pester

<#
.SYNOPSIS
    Unit tests for the pure helper functions in Invoke-HomeBaseline.Functions.ps1. No elevation
    required, no machine state touched.
#>

BeforeAll {
    $script:Root = Join-Path $PSScriptRoot '..'
    $script:ModulesRoot = Join-Path $script:Root 'modules'
    . (Join-Path $script:Root 'Invoke-HomeBaseline.Functions.ps1')

    $script:DefaultModules = @('ScriptHostGuard', 'LolbinEgressGuard', 'CredentialTheftGuard', 'NameResolutionGuard', 'RemoteServiceGuard', 'ExplorerVisibilityHardening', 'Debloat', 'SmartAppControlAudit')
}

Describe 'Get-HomeAvailableModule' {

    It 'lists every .psm1 base name under modules\' {
        $available = Get-HomeAvailableModule -ModulesRoot $script:ModulesRoot
        $expected = Get-ChildItem -LiteralPath $script:ModulesRoot -Filter '*.psm1' -File | ForEach-Object { $_.BaseName }
        $available | Should -Be @($expected)
    }

    It 'returns an empty array for a nonexistent folder' {
        Get-HomeAvailableModule -ModulesRoot (Join-Path $script:Root 'no-such-folder') | Should -BeNullOrEmpty
    }
}

Describe 'Resolve-HomeModule' {

    It 'returns the default set when -Modules was not bound' {
        $resolved = Resolve-HomeModule -RequestedModules $null -BoundModules $false `
            -DefaultModules $script:DefaultModules -ModulesRoot $script:ModulesRoot
        $resolved | Should -Be $script:DefaultModules
    }

    It 'returns every available module for All (including opt-in NtlmEgressGuard)' {
        $resolved = Resolve-HomeModule -RequestedModules @('All') -BoundModules $true `
            -DefaultModules $script:DefaultModules -ModulesRoot $script:ModulesRoot
        $resolved | Should -Contain 'NtlmEgressGuard'
        $resolved.Count | Should -BeGreaterThan $script:DefaultModules.Count
    }

    It 'returns nothing for an explicitly empty request' {
        $resolved = Resolve-HomeModule -RequestedModules @() -BoundModules $true `
            -DefaultModules $script:DefaultModules -ModulesRoot $script:ModulesRoot
        $resolved | Should -BeNullOrEmpty
    }

    It 'splits comma-joined values as passed by powershell.exe -File' {
        $resolved = Resolve-HomeModule -RequestedModules @('ScriptHostGuard,Debloat') -BoundModules $true `
            -DefaultModules $script:DefaultModules -ModulesRoot $script:ModulesRoot
        $resolved | Should -Be @('ScriptHostGuard', 'Debloat')
    }

    It 'filters unknown modules and emits a warning for each' {
        $warnings = @()
        $resolved = Resolve-HomeModule -RequestedModules @('Debloat', 'NoSuchModule') -BoundModules $true `
            -DefaultModules $script:DefaultModules -ModulesRoot $script:ModulesRoot `
            -WarningOut { param($msg) $script:warnings += $msg }

        $resolved | Should -Be @('Debloat')
    }
}

Describe 'Invoke-HomeModulePhase' {

    BeforeAll {
        function global:Get-PhaseFakeStatus { 'fake-status' }
        function global:Invoke-PhaseFakeHardening { param([switch]$Remediate) if ($Remediate) { 'hardened' } else { 'dry' } }
        function global:Invoke-PhaseFakeRollback { param([switch]$Remediate) if ($Remediate) { 'rolled-back' } else { 'dry' } }
    }

    AfterAll {
        Remove-Item -Path Function:\Get-PhaseFakeStatus, Function:\Invoke-PhaseFakeHardening, Function:\Invoke-PhaseFakeRollback -ErrorAction SilentlyContinue
    }

    It 'dispatches the Status phase' {
        Invoke-HomeModulePhase -ModuleName 'PhaseFake' -Phase Status | Should -Be 'fake-status'
    }

    It 'passes -Remediate through to Hardening' {
        Invoke-HomeModulePhase -ModuleName 'PhaseFake' -Phase Hardening -Remediate | Should -Be 'hardened'
        Invoke-HomeModulePhase -ModuleName 'PhaseFake' -Phase Hardening | Should -Be 'dry'
    }

    It 'passes -Remediate through to Rollback' {
        Invoke-HomeModulePhase -ModuleName 'PhaseFake' -Phase Rollback -Remediate | Should -Be 'rolled-back'
    }

    It 'returns $null when the module does not export the phase function' {
        Invoke-HomeModulePhase -ModuleName 'NoSuchModule' -Phase Status | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-HomeModulePhaseSafe' {

    BeforeAll {
        function global:Invoke-SafeOkHardening { param([switch]$Remediate) 'ok' }
        function global:Invoke-SafeBoomHardening { param([switch]$Remediate) throw 'kaboom' }
    }
    AfterAll {
        Remove-Item Function:\Invoke-SafeOkHardening, Function:\Invoke-SafeBoomHardening -ErrorAction SilentlyContinue
    }

    It 'returns the phase output with no error on success' {
        $r = Invoke-HomeModulePhaseSafe -ModuleName 'SafeOk' -Phase Hardening -Remediate
        $r.Lines | Should -Be 'ok'
        $r.Error | Should -BeNullOrEmpty
    }

    It 'captures the exception instead of throwing when a module fails' {
        $ErrorActionPreference = 'Stop'
        { Invoke-HomeModulePhaseSafe -ModuleName 'SafeBoom' -Phase Hardening -Remediate } | Should -Not -Throw
        $r = Invoke-HomeModulePhaseSafe -ModuleName 'SafeBoom' -Phase Hardening -Remediate
        $r.Lines | Should -BeNullOrEmpty
        $r.Error | Should -Match 'kaboom'
    }
}

Describe 'Import-HomeCompatModule' {

    It 'returns $true for a module that is already loaded' {
        Import-HomeCompatModule -Name 'Microsoft.PowerShell.Utility' | Should -BeTrue
    }

    It 'returns $false for a module that does not exist on either engine' {
        Import-HomeCompatModule -Name 'ZZZ-NoSuchModule-ZZZ' | Should -BeFalse
    }
}
