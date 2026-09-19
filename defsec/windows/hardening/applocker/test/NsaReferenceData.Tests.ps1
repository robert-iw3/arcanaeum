#Requires -Module Pester

<#
.SYNOPSIS
    Regression tests for nsa\ - the vendored NSA AppLocker-Guidance reference files.

.DESCRIPTION
    This folder was previously found with every file's content shuffled onto the wrong filename
    (e.g. the file named "Windows11_AppLocker Starter Policy.xml" actually contained the Windows
    10 policy, and DISCLAIMER.md actually contained a scheduled-task XML) after a bad copy
    operation. These tests assert each reference file's content actually matches its filename, so
    a future bad copy/sync is caught here instead of silently feeding the wrong policy into
    Invoke-AppLockerBaseline.ps1.
#>

BeforeAll {
    $script:Root = Join-Path $PSScriptRoot '..'
    $script:NsaRoot = Join-Path $script:Root 'nsa'
}

Describe 'nsa\ folder structure' {

    It 'has the expected top-level files and subfolders' {
        Test-Path (Join-Path $script:NsaRoot 'README.md') | Should -BeTrue
        Test-Path (Join-Path $script:NsaRoot 'DISCLAIMER.md') | Should -BeTrue
        Test-Path (Join-Path $script:NsaRoot 'LICENSE.md') | Should -BeTrue
        Test-Path (Join-Path $script:NsaRoot 'AppLocker Starter Policy') | Should -BeTrue
        Test-Path (Join-Path $script:NsaRoot 'Create AppLocker Popup Task') | Should -BeTrue
    }
}

Describe 'README.md / DISCLAIMER.md / LICENSE.md content sanity' {

    It 'README.md is actually the AppLocker-Guidance README (mentions LOLBAS)' {
        $content = Get-Content (Join-Path $script:NsaRoot 'README.md') -Raw
        $content | Should -Match 'AppLocker Guidance'
        $content | Should -Match 'LOLBAS'
    }

    It 'DISCLAIMER.md is actually a disclaimer, not a scheduled-task XML' {
        $content = Get-Content (Join-Path $script:NsaRoot 'DISCLAIMER.md') -Raw
        $content | Should -Match 'Disclaimer of Warranty'
        $content | Should -Not -Match '<Task '
    }

    It 'LICENSE.md is actually a license, not a batch script' {
        $content = Get-Content (Join-Path $script:NsaRoot 'LICENSE.md') -Raw
        $content | Should -Match 'Copyright'
        $content | Should -Not -Match '^REM '
    }
}

Describe 'Windows 11 starter policy identity and content' {

    BeforeAll {
        $script:Win11Path = Join-Path $script:NsaRoot 'AppLocker Starter Policy\Windows11_AppLocker Starter Policy.xml'
        $script:Win10Path = Join-Path $script:NsaRoot 'AppLocker Starter Policy\Windows10_AppLocker Starter Policy.xml'
    }

    It 'is the file Invoke-AppLockerBaseline.ps1 defaults to' {
        $orchestrator = Get-Content (Join-Path $script:Root 'Invoke-AppLockerBaseline.ps1') -Raw
        $orchestrator | Should -Match ([regex]::Escape('AppLocker Starter Policy\Windows11_AppLocker Starter Policy.xml'))
    }

    It 'is a well-formed AppLockerPolicy document with all five rule collections' {
        [xml]$doc = Get-Content $script:Win11Path -Raw
        $doc.DocumentElement.Name | Should -Be 'AppLockerPolicy'
        $types = $doc.SelectNodes('//RuleCollection') | ForEach-Object { $_.Type }
        ($types | Sort-Object -Unique) | Should -Be @('Appx', 'Dll', 'Exe', 'Msi', 'Script')
    }

    It 'denies execution from the standard-user-writable Windows bypass folders' {
        $raw = Get-Content $script:Win11Path -Raw
        foreach ($bypassPath in 'machinekeys', 'spool\\drivers\\color', '\\Tasks\\', '\\Temp\\') {
            $raw | Should -Match $bypassPath
        }
    }

    It 'is meaningfully larger than the Windows 10 starter policy (it is NOT the Windows10 file mislabeled)' {
        (Get-Item $script:Win11Path).Length | Should -BeGreaterThan 150000
        (Get-Item $script:Win10Path).Length | Should -BeLessThan 120000
        (Get-Item $script:Win10Path).Length | Should -BeGreaterThan 50000
    }
}

Describe 'Popup alert task XML identity' {

    It 'is actually the popup-on-block scheduled task definition' {
        $taskPath = Join-Path $script:NsaRoot 'Create AppLocker Popup Task\AppLocker Popup Alert Task.xml'
        Test-Path $taskPath | Should -BeTrue
        [xml]$doc = Get-Content $taskPath -Raw
        $doc.DocumentElement.Name | Should -Be 'Task'
        ($doc.Task.RegistrationInfo.Description) | Should -Match 'popup'
        $doc.Task.Actions.Exec.Command | Should -Match 'msg\.exe'
    }
}
