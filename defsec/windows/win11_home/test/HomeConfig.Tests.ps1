#Requires -Module Pester

<#
.SYNOPSIS
    Tests for the config.ini parsing/resolution helpers and the shipped config.ini. No machine
    state touched.
#>

BeforeAll {
    $script:Root = Join-Path $PSScriptRoot '..'
    $script:ModulesRoot = Join-Path $script:Root 'modules'
    . (Join-Path $script:Root 'Invoke-HomeBaseline.Functions.ps1')
    $script:ConfigPath = Join-Path $script:Root 'config.ini'
}

Describe 'ConvertTo-HomeConfigValue' {
    It 'types booleans' {
        ConvertTo-HomeConfigValue -Raw 'true'  | Should -BeTrue
        ConvertTo-HomeConfigValue -Raw 'False' | Should -BeFalse
        ConvertTo-HomeConfigValue -Raw 'yes'   | Should -BeTrue
        ConvertTo-HomeConfigValue -Raw 'off'   | Should -BeFalse
    }
    It 'types integers greater than 1' {
        ConvertTo-HomeConfigValue -Raw '255' | Should -Be 255
        (ConvertTo-HomeConfigValue -Raw '255').GetType().Name | Should -Be 'Int32'
    }
    It 'strips inline comments' {
        ConvertTo-HomeConfigValue -Raw 'true   ; because reasons' | Should -BeTrue
    }
    It 'passes strings through' {
        ConvertTo-HomeConfigValue -Raw 'Enhanced' | Should -Be 'Enhanced'
    }
}

Describe 'ConvertFrom-HomeIni' {
    It 'parses sections and key/values, ignoring comments and blanks' {
        $ini = @(
            '; a comment',
            '# another',
            '',
            '[Alpha]',
            'Enabled = true',
            'IncludeCurl = false',
            '[Beta]',
            'Enabled = false'
        )
        $parsed = ConvertFrom-HomeIni -Lines $ini
        $parsed.Keys | Should -Contain 'Alpha'
        $parsed.Keys | Should -Contain 'Beta'
        $parsed['Alpha']['Enabled'] | Should -Be 'true'
        $parsed['Alpha']['IncludeCurl'] | Should -Be 'false'
    }
    It 'drops keys that appear before any section header' {
        $parsed = ConvertFrom-HomeIni -Lines @('Orphan = 1', '[S]', 'K = v')
        $parsed.Keys | Should -Be @('S')
    }
}

Describe 'Get-HomeConfig' {
    BeforeAll {
        $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) "homecfg-$([guid]::NewGuid()).ini"
        @(
            '[ScriptHostGuard]',
            'Enabled = true',
            '[LolbinEgressGuard]',
            'Enabled = true',
            'IncludeCurl = true',
            '[Debloat]',
            'Enabled = false',
            'IncludeXbox = true'
        ) | Set-Content -Path $script:Tmp
    }
    AfterAll { Remove-Item $script:Tmp -Force -ErrorAction SilentlyContinue }

    It 'returns only enabled modules in file order' {
        $cfg = Get-HomeConfig -Path $script:Tmp
        $cfg.Modules | Should -Be @('ScriptHostGuard', 'LolbinEgressGuard')
    }
    It 'captures per-module options excluding Enabled, typed' {
        $cfg = Get-HomeConfig -Path $script:Tmp
        $cfg.Options['LolbinEgressGuard']['IncludeCurl'] | Should -BeTrue
        $cfg.Options['LolbinEgressGuard'].ContainsKey('Enabled') | Should -BeFalse
    }
    It 'retains options even for a disabled module (options apply regardless of selection)' {
        $cfg = Get-HomeConfig -Path $script:Tmp
        $cfg.Options['Debloat']['IncludeXbox'] | Should -BeTrue
    }
    It 'throws on a missing file' {
        { Get-HomeConfig -Path (Join-Path $script:Root 'no-such.ini') } | Should -Throw
    }
}

Describe 'Shipped config.ini' {
    It 'exists next to the orchestrator' {
        Test-Path $script:ConfigPath | Should -BeTrue
    }
    It 'parses without error and every section maps to a real module file (or the reserved [Baseline])' {
        $null = Get-HomeConfig -Path $script:ConfigPath   # must not throw
        $available = Get-HomeAvailableModule -ModulesRoot $script:ModulesRoot
        $parsed = ConvertFrom-HomeIni -Lines (Get-Content $script:ConfigPath)
        foreach ($section in $parsed.Keys) {
            if ($section -eq 'Baseline') { continue }
            $section | Should -BeIn $available -Because "config.ini [$section] must correspond to modules\$section.psm1"
        }
    }

    It 'parses the reserved [Baseline] section into Settings, not as a module' {
        $cfg = Get-HomeConfig -Path $script:ConfigPath
        $cfg.Modules | Should -Not -Contain 'Baseline'
        $cfg.Settings.Keys | Should -Contain 'Remediate'
        $cfg.Settings.Keys | Should -Contain 'NoReport'
        # Safe-by-default: the shipped config must not silently apply changes.
        $cfg.Settings['Remediate'] | Should -BeFalse
    }
    It 'has a section for every module that exists' {
        $parsed = ConvertFrom-HomeIni -Lines (Get-Content $script:ConfigPath)
        $available = Get-HomeAvailableModule -ModulesRoot $script:ModulesRoot
        foreach ($mod in $available) {
            $parsed.Keys | Should -Contain $mod -Because "every module should be documented and selectable in config.ini"
        }
    }
    It 'the LolbinEgressGuard option key matches a real parameter on the hardening function' {
        Import-Module (Join-Path $script:ModulesRoot 'LolbinEgressGuard.psm1') -Force
        (Get-Command Invoke-LolbinEgressGuardHardening).Parameters.Keys | Should -Contain 'IncludeCurl'
    }
    It 'the Debloat option key matches a real parameter on the hardening function' {
        Import-Module (Join-Path $script:ModulesRoot 'Debloat.psm1') -Force
        (Get-Command Invoke-DebloatHardening).Parameters.Keys | Should -Contain 'IncludeXbox'
    }
}

Describe 'Get-HomeModuleCoverage' {
    It 'has a coverage description for every module that exists (keeps the report from going stale)' {
        $cov = Get-HomeModuleCoverage
        $available = Get-HomeAvailableModule -ModulesRoot $script:ModulesRoot
        foreach ($mod in $available) {
            $cov.Contains($mod) | Should -BeTrue -Because "Get-HomeModuleCoverage must describe modules\$mod.psm1"
        }
    }
}

Describe 'New-HomeBaselineReport' {
    BeforeAll {
        $script:RunLog = [ordered]@{}
        $script:RunLog['ScriptHostGuard'] = @{ Status = @('WSH: ENABLED'); Action = @('Disabled Windows Script Host.'); Error = $null }
        $script:RunLog['LolbinEgressGuard'] = @{ Status = @(); Action = @(); Error = 'access denied' }
        $script:Ctx = @{
            Timestamp = '2026-07-03 10:00:00'; Computer = 'PC1'; OS = 'Windows 11 Home'; Build = '26200'
            PSVersion = '5.1'; Elevated = $true; ConfigPath = 'C:\config.ini'; BackupPath = 'C:\HomeReports\x'
        }
    }

    It 'produces Markdown with context, applied actions, and a failure warning' {
        $md = New-HomeBaselineReport -Mode Remediate -Context $script:Ctx -RunLog $script:RunLog -AllModules @('ScriptHostGuard', 'LolbinEgressGuard', 'NtlmEgressGuard')
        $md | Should -Match '# Windows 11 Home Baseline - Run Report'
        $md | Should -Match 'Mode \| Remediate'
        $md | Should -Match 'Disabled Windows Script Host'
        $md | Should -Match 'Applied:'
        $md | Should -Match 'may be only partially applied'          # failure warning
        $md | Should -Match 'Error \(skipped, run continued\).*access denied'
    }

    It 'lists modules that were available but not run' {
        $md = New-HomeBaselineReport -Mode Assess -Context $script:Ctx -RunLog $script:RunLog -AllModules @('ScriptHostGuard', 'LolbinEgressGuard', 'NtlmEgressGuard')
        $md | Should -Match 'Available but not run'
        $md | Should -Match 'NtlmEgressGuard'
    }

    It 'uses the Rolled back label in Rollback mode' {
        $md = New-HomeBaselineReport -Mode Rollback -Context $script:Ctx -RunLog $script:RunLog
        $md | Should -Match 'Rolled back:'
    }
}
