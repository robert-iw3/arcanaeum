#Requires -Module Pester

<#
.SYNOPSIS
    Pester tests for win11/Windows11-STIG-User-V2R7.ps1.

.DESCRIPTION
    Black-box tests driven through the script's own CLI surface (-ListRules -PassThru),
    with no -Remediate, so no HKCU writes happen - safe to run on any dev box or in CI.
#>

BeforeAll {
    $script:ScriptPath = Join-Path $PSScriptRoot '..\win11\Windows11-STIG-User-V2R7.ps1'
    $script:IniPath    = Join-Path $PSScriptRoot '..\win11\Windows11-STIG-User-V2R7.ini'
    # -IgnoreRulesFile so this represents the FULL rule set, unaffected by ini comments.
    $script:AllRules   = & $script:ScriptPath -Section All -ListRules -PassThru -IgnoreRulesFile
}

Describe 'Windows11-STIG-User-V2R7 rule data' {

    It 'loads at least one rule' {
        $script:AllRules.Count | Should -BeGreaterThan 0
    }

    It 'has a unique STIGID for every rule' {
        $dupes = $script:AllRules.STIGID | Group-Object | Where-Object Count -gt 1
        $dupes | Should -BeNullOrEmpty
    }

    It 'every rule is a Registry check with Path/Name/Expected set' {
        foreach ($r in $script:AllRules) {
            $r.CheckType | Should -Be 'Registry'
            $r.Path      | Should -Not -BeNullOrEmpty
            $r.Name      | Should -Not -BeNullOrEmpty
            $null -ne $r.Expected | Should -BeTrue
        }
    }

    It 'every rule targets HKCU, not HKLM' {
        foreach ($r in $script:AllRules) {
            $r.Path | Should -Match '^HKCU:'
        }
    }
}

Describe 'Windows11-STIG-User-V2R7 -StigId targeting' {

    It 'returns exactly the one rule asked for' {
        $oneId = $script:AllRules[0].STIGID
        $r = & $script:ScriptPath -StigId $oneId -ListRules -PassThru
        $r.Count | Should -Be 1
        $r[0].STIGID | Should -Be $oneId
    }

    It 'warns and returns nothing for an unknown STIG ID' {
        $r = & $script:ScriptPath -StigId 'WN11-NOT-REAL' -ListRules -PassThru -WarningVariable warnings -WarningAction SilentlyContinue
        $r | Should -BeNullOrEmpty
        $warnings | Should -Not -BeNullOrEmpty
    }
}

Describe 'Windows11-STIG-User-V2R7 RulesFile (.ini) include/exclude' {

    It 'ships a default .ini next to the script' {
        Test-Path $script:IniPath | Should -BeTrue
    }

    It 'every active (uncommented) STIGID in the ini matches a real rule' {
        $enabled = Get-Content $script:IniPath |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and -not $_.StartsWith(';') -and -not $_.StartsWith('#') -and -not $_.StartsWith('[') } |
            ForEach-Object { ($_ -split '=', 2)[0].Trim() }
        $enabled | Should -Not -BeNullOrEmpty
        $enabled | Should -BeIn $script:AllRules.STIGID
    }

    It 'commenting out a STIGID line removes it from scope, uncommenting restores it' {
        $targetId = $script:AllRules[0].STIGID
        $original = Get-Content $script:IniPath -Raw
        try {
            $commented = $original -replace "(?m)^(\s*)$([regex]::Escape($targetId))(\s*=)", ('$1; ' + $targetId + '$2')
            $commented | Should -Not -Be $original
            Set-Content -Path $script:IniPath -Value $commented -NoNewline -Encoding UTF8

            $afterComment = & $script:ScriptPath -Section All -ListRules -PassThru
            $afterComment.STIGID | Should -Not -Contain $targetId
        }
        finally {
            Set-Content -Path $script:IniPath -Value $original -NoNewline -Encoding UTF8
        }

        $afterRestore = & $script:ScriptPath -Section All -ListRules -PassThru
        $afterRestore.STIGID | Should -Contain $targetId
    }

    It '-StigId bypasses the ini even when the target line is commented out' {
        $targetId = $script:AllRules[0].STIGID
        $original = Get-Content $script:IniPath -Raw
        try {
            $commented = $original -replace "(?m)^(\s*)$([regex]::Escape($targetId))(\s*=)", ('$1; ' + $targetId + '$2')
            Set-Content -Path $script:IniPath -Value $commented -NoNewline -Encoding UTF8

            $r = & $script:ScriptPath -StigId $targetId -ListRules -PassThru
            $r.Count | Should -Be 1
        }
        finally {
            Set-Content -Path $script:IniPath -Value $original -NoNewline -Encoding UTF8
        }
    }
}

Describe 'Windows11-STIG-User-V2R7 check-only execution' {

    It 'produces a well-formed report row without touching -Remediate' {
        $oneId = $script:AllRules[0].STIGID
        $r = & $script:ScriptPath -StigId $oneId -PassThru
        $r.Count | Should -Be 1
        $r[0].STIGID     | Should -Be $oneId
        $r[0].Remediated | Should -Be 'No'
        $r[0].Status     | Should -BeIn @('Compliant', 'Non-Compliant')
    }
}
