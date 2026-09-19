#Requires -Module Pester

<#
.SYNOPSIS
    Pester tests for server2022/WindowsServer2022-STIG-V2R7.ps1.

.DESCRIPTION
    Black-box tests driven through the script's own CLI surface (-ListRules -PassThru), with
    no -Remediate, so no registry/secedit/auditpol writes ever happen and no elevation is
    required - safe to run on any dev box or in CI.
#>

BeforeAll {
    $script:ScriptPath = Join-Path $PSScriptRoot '..\server2022\WindowsServer2022-STIG-V2R7.ps1'
    $script:IniPath    = Join-Path $PSScriptRoot '..\server2022\WindowsServer2022-STIG-V2R7.ini'
    # -IgnoreRulesFile so this represents the FULL rule set, unaffected by ini comments.
    $script:AllRules   = & $script:ScriptPath -ListRules -PassThru -IgnoreRulesFile
}

Describe 'WindowsServer2022-STIG-V2R7 rule data' {

    It 'loads at least one rule' {
        $script:AllRules.Count | Should -BeGreaterThan 0
    }

    It 'has a unique VID for every rule, except the one known SYSVOL/NETLOGON pair sharing V-254340' {
        $dupes = @($script:AllRules.VID | Group-Object | Where-Object Count -gt 1)
        $dupes.Length | Should -Be 1
        $dupes[0].Name | Should -Be 'V-254340'
        $dupes[0].Count | Should -Be 2
    }

    It 'has no rule with a blank VID or Title' {
        $bad = $script:AllRules | Where-Object { -not $_.VID -or -not $_.Title }
        $bad | Should -BeNullOrEmpty
    }

    It 'every Registry-typed rule has a Path, Name and Expected' {
        $regRules = $script:AllRules | Where-Object CheckType -eq 'Registry'
        $regRules.Count | Should -BeGreaterThan 0
        foreach ($r in $regRules) {
            $r.Path | Should -Not -BeNullOrEmpty
            $r.Name | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'WindowsServer2022-STIG-V2R7 -StigId targeting' {

    It 'defaults to evaluating every rule' {
        $default = & $script:ScriptPath -ListRules -PassThru
        $default.Count | Should -Be $script:AllRules.Count
    }

    It 'returns exactly the one rule asked for' {
        $oneId = $script:AllRules[0].VID
        $r = & $script:ScriptPath -StigId $oneId -ListRules -PassThru
        $r.Count | Should -Be 1
        $r[0].VID | Should -Be $oneId
    }

    It 'accepts multiple IDs at once' {
        $ids = $script:AllRules[0..2].VID
        $r = & $script:ScriptPath -StigId $ids -ListRules -PassThru
        $r.Count | Should -Be $ids.Count
        (Compare-Object $r.VID $ids | Measure-Object).Count | Should -Be 0
    }

    It 'warns and returns nothing for an unknown VID' {
        $r = & $script:ScriptPath -StigId 'V-NOTREAL' -ListRules -PassThru -WarningVariable warnings -WarningAction SilentlyContinue
        $r | Should -BeNullOrEmpty
        $warnings | Should -Not -BeNullOrEmpty
    }
}

Describe 'WindowsServer2022-STIG-V2R7 RulesFile (.ini) include/exclude' {

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

    It 'every rule is active in the shipped ini (no opt-in/opt-out sections in this baseline)' {
        $withIni = (& $script:ScriptPath -ListRules -PassThru).Count
        $withIni | Should -Be $script:AllRules.Count
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

    It '-StigId bypasses the ini even when the target line is commented out' {
        $targetId = $script:AllRules[0].VID
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

Describe 'WindowsServer2022-STIG-V2R7 check-only execution' {

    It 'produces a well-formed report row without touching -Remediate' {
        $regId = ($script:AllRules | Where-Object CheckType -eq 'Registry' | Select-Object -First 1).VID
        $r = & $script:ScriptPath -StigId $regId -PassThru
        $r.Count | Should -Be 1
        $r[0].VID        | Should -Be $regId
        $r[0].Remediated | Should -Be 'No'
        $r[0].Status     | Should -BeIn @('Compliant', 'Non-Compliant')
    }
}
