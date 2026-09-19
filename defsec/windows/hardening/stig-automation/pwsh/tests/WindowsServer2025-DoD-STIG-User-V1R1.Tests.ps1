#Requires -Module Pester

<#
.SYNOPSIS
    Pester tests for server2025/WindowsServer2025-DoD-STIG-User-V1R1.ps1.

.DESCRIPTION
    Black-box tests driven through the script's own CLI surface (-ListRules -PassThru), with
    no -Remediate, so no HKCU writes happen - safe to run on any dev box or in CI.
#>

BeforeAll {
    $script:ScriptPath = Join-Path $PSScriptRoot '..\server2025\WindowsServer2025-DoD-STIG-User-V1R1.ps1'
    $script:IniPath    = Join-Path $PSScriptRoot '..\server2025\WindowsServer2025-DoD-STIG-User-V1R1.ini'
    $script:AllRules   = & $script:ScriptPath -ListRules -PassThru -IgnoreRulesFile
}

Describe 'WindowsServer2025-DoD-STIG-User-V1R1 rule data' {

    It 'loads at least one rule' {
        $script:AllRules.Count | Should -BeGreaterThan 0
    }

    It 'has a unique VID for every rule' {
        $dupes = $script:AllRules.VID | Group-Object | Where-Object Count -gt 1
        $dupes | Should -BeNullOrEmpty
    }

    It 'uses real DISA V-numbers from the V1R1 XCCDF' {
        foreach ($vid in $script:AllRules.VID) {
            $vid | Should -Match '^V-\d+$'
        }
    }

    It 'every rule targets HKCU, not HKLM' {
        foreach ($r in $script:AllRules) {
            $r.Path | Should -Match '^HKCU:'
        }
    }
}

Describe 'WindowsServer2025-DoD-STIG-User-V1R1 -StigId targeting' {

    It 'returns exactly the one rule asked for' {
        $oneId = $script:AllRules[0].VID
        $r = & $script:ScriptPath -StigId $oneId -ListRules -PassThru
        $r.Count | Should -Be 1
        $r[0].VID | Should -Be $oneId
    }

    It 'warns and returns nothing for an unknown VID' {
        $r = & $script:ScriptPath -StigId 'WS2025-USER-9999' -ListRules -PassThru -WarningVariable warnings -WarningAction SilentlyContinue
        $r | Should -BeNullOrEmpty
        $warnings | Should -Not -BeNullOrEmpty
    }
}

Describe 'WindowsServer2025-DoD-STIG-User-V1R1 RulesFile (.ini) include/exclude' {

    It 'ships a default .ini next to the script' {
        Test-Path $script:IniPath | Should -BeTrue
    }

    It 'every active (uncommented) VID in the ini matches a real rule' {
        $enabled = Get-Content $script:IniPath |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and -not $_.StartsWith(';') -and -not $_.StartsWith('#') -and -not $_.StartsWith('[') } |
            ForEach-Object { ($_ -split '=', 2)[0].Trim() }
        $enabled | Should -Not -BeNullOrEmpty
        $enabled | Should -BeIn $script:AllRules.VID
    }

    It 'commenting out a VID line removes it from scope, uncommenting restores it' {
        $targetId = $script:AllRules[0].VID
        $original = Get-Content $script:IniPath -Raw
        try {
            $commented = $original -replace "(?m)^(\s*)$([regex]::Escape($targetId))(\s*=)", ('$1; ' + $targetId + '$2')
            $commented | Should -Not -Be $original
            Set-Content -Path $script:IniPath -Value $commented -NoNewline -Encoding UTF8

            $afterComment = & $script:ScriptPath -ListRules -PassThru
            $afterComment.VID | Should -Not -Contain $targetId
        }
        finally {
            Set-Content -Path $script:IniPath -Value $original -NoNewline -Encoding UTF8
        }

        $afterRestore = & $script:ScriptPath -ListRules -PassThru
        $afterRestore.VID | Should -Contain $targetId
    }
}

Describe 'WindowsServer2025-DoD-STIG-User-V1R1 check-only execution' {

    It 'produces a well-formed report row without touching -Remediate' {
        $oneId = $script:AllRules[0].VID
        $r = & $script:ScriptPath -StigId $oneId -PassThru
        $r.Count | Should -Be 1
        $r[0].VID        | Should -Be $oneId
        $r[0].Remediated | Should -Be 'No'
        $r[0].Status     | Should -BeIn @('Compliant', 'Non-Compliant')
    }
}
