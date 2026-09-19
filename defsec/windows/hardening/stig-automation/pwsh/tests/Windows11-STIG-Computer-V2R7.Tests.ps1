#Requires -Module Pester

<#
.SYNOPSIS
    Pester tests for win11/Windows11-STIG-Computer-V2R7.ps1.

.DESCRIPTION
    Black-box tests driven through the script's own CLI surface (-ListRules -PassThru),
    the same way Invoke-StigHardening.ps1 drives it. Everything here uses -ListRules and/or
    -PassThru with no -Remediate, so no registry/secedit/auditpol writes ever happen and
    no elevation is required - safe to run on any dev box or in CI.
#>

BeforeAll {
    $script:ScriptPath = Join-Path $PSScriptRoot '..\win11\Windows11-STIG-Computer-V2R7.ps1'
    $script:IniPath    = Join-Path $PSScriptRoot '..\win11\Windows11-STIG-Computer-V2R7.ini'
    # -IgnoreRulesFile so this represents the FULL rule set, unaffected by ini comments.
    $script:AllRules   = & $script:ScriptPath -Section All -ListRules -PassThru -IgnoreRulesFile
}

Describe 'Windows11-STIG-Computer-V2R7 rule data' {

    It 'loads at least one rule' {
        $script:AllRules.Count | Should -BeGreaterThan 0
    }

    It 'has a unique STIGID for every rule' {
        $dupes = $script:AllRules.STIGID | Group-Object | Where-Object Count -gt 1
        $dupes | Should -BeNullOrEmpty
    }

    It 'has no rule with a blank STIGID, Title, Section or Severity' {
        $bad = $script:AllRules | Where-Object {
            -not $_.STIGID -or -not $_.Title -or -not $_.Section -or -not $_.Severity
        }
        $bad | Should -BeNullOrEmpty
    }

    It 'only uses Severity values accepted by the -Severity parameter' {
        $cmd   = Get-Command $script:ScriptPath
        $valid = ($cmd.Parameters['Severity'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }).ValidValues
        ($script:AllRules.Severity | Sort-Object -Unique) | Should -BeIn $valid
    }

    It 'only uses Section values accepted by the -Section parameter (minus the All wildcard)' {
        $cmd   = Get-Command $script:ScriptPath
        $valid = ($cmd.Parameters['Section'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }).ValidValues |
            Where-Object { $_ -ne 'All' }
        ($script:AllRules.Section | Sort-Object -Unique) | Should -BeIn $valid
    }

    It 'every Registry-typed rule has a Path, Name and Expected' {
        $regRules = $script:AllRules | Where-Object CheckType -eq 'Registry'
        $regRules.Count | Should -BeGreaterThan 0
        foreach ($r in $regRules) {
            $r.Path     | Should -Not -BeNullOrEmpty
            $r.Name     | Should -Not -BeNullOrEmpty
            $null -ne $r.Expected | Should -BeTrue
        }
    }
}

Describe 'Windows11-STIG-Computer-V2R7 -Section / -Severity scoping' {

    It 'defaults to the laptop section set (no Domain/DoD/Restrictive)' {
        $default = & $script:ScriptPath -ListRules -PassThru
        $default.Section | Sort-Object -Unique | Should -Not -Contain 'Domain'
        $default.Section | Sort-Object -Unique | Should -Not -Contain 'DoD'
        $default.Section | Sort-Object -Unique | Should -Not -Contain 'Restrictive'
    }

    It '-Section All returns every rule' {
        $all = & $script:ScriptPath -Section All -ListRules -PassThru -IgnoreRulesFile
        $all.Count | Should -Be $script:AllRules.Count
    }

    It '-Section AccountPolicy returns only AccountPolicy rules' {
        $r = & $script:ScriptPath -Section AccountPolicy -ListRules -PassThru
        $r.Count | Should -BeGreaterThan 0
        ($r.Section | Sort-Object -Unique) | Should -Be 'AccountPolicy'
    }

    It '-Severity High returns only High severity rules' {
        $r = & $script:ScriptPath -Section All -Severity High -ListRules -PassThru -IgnoreRulesFile
        $r.Count | Should -BeGreaterThan 0
        ($r.Severity | Sort-Object -Unique) | Should -Be 'High'
    }
}

Describe 'Windows11-STIG-Computer-V2R7 -StigId targeting' {

    It 'returns exactly the one rule asked for' {
        $oneId = $script:AllRules[0].STIGID
        $r = & $script:ScriptPath -StigId $oneId -ListRules -PassThru
        $r.Count | Should -Be 1
        $r[0].STIGID | Should -Be $oneId
    }

    It 'ignores Section/Severity scoping and reaches opt-in (Restrictive) rules directly' {
        $restrictiveId = ($script:AllRules | Where-Object Section -eq 'Restrictive' | Select-Object -First 1).STIGID
        $restrictiveId | Should -Not -BeNullOrEmpty
        # Default Section scope excludes Restrictive, but -StigId should still find it.
        $r = & $script:ScriptPath -StigId $restrictiveId -ListRules -PassThru
        $r.Count | Should -Be 1
        $r[0].STIGID | Should -Be $restrictiveId
    }

    It 'accepts multiple IDs at once' {
        $ids = $script:AllRules[0..2].STIGID
        $r = & $script:ScriptPath -StigId $ids -ListRules -PassThru
        $r.Count | Should -Be $ids.Count
        (Compare-Object $r.STIGID $ids | Measure-Object).Count | Should -Be 0
    }

    It 'warns and returns nothing for an unknown STIG ID' {
        $r = & $script:ScriptPath -StigId 'WN11-NOT-REAL' -ListRules -PassThru -WarningVariable warnings -WarningAction SilentlyContinue
        $r | Should -BeNullOrEmpty
        $warnings | Should -Not -BeNullOrEmpty
    }
}

Describe 'Windows11-STIG-Computer-V2R7 RulesFile (.ini) include/exclude' {

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

    It 'default (laptop) sections are fully active in the shipped ini' {
        $defaultSections = 'AccountPolicy', 'UserRights', 'AuditPolicy', 'SecurityOptions', 'ComputerConfig', 'System'
        $withIni = (& $script:ScriptPath -Section $defaultSections -ListRules -PassThru).Count
        $noIni   = (& $script:ScriptPath -Section $defaultSections -ListRules -PassThru -IgnoreRulesFile).Count
        $withIni | Should -Be $noIni
    }

    It 'commenting out a STIGID line removes it from scope, uncommenting restores it' {
        $targetId = ($script:AllRules | Where-Object Section -eq 'AccountPolicy' | Select-Object -First 1).STIGID
        $original = Get-Content $script:IniPath -Raw
        try {
            $commented = $original -replace "(?m)^(\s*)$([regex]::Escape($targetId))(\s*=)", ('$1; ' + $targetId + '$2')
            $commented | Should -Not -Be $original
            Set-Content -Path $script:IniPath -Value $commented -NoNewline -Encoding UTF8

            $afterComment = & $script:ScriptPath -Section AccountPolicy -ListRules -PassThru
            $afterComment.STIGID | Should -Not -Contain $targetId
        }
        finally {
            Set-Content -Path $script:IniPath -Value $original -NoNewline -Encoding UTF8
        }

        $afterRestore = & $script:ScriptPath -Section AccountPolicy -ListRules -PassThru
        $afterRestore.STIGID | Should -Contain $targetId
    }

    It '-StigId bypasses the ini even when the target line is commented out' {
        $targetId = ($script:AllRules | Where-Object Section -eq 'Domain' | Select-Object -First 1).STIGID
        $targetId | Should -Not -BeNullOrEmpty
        # Domain section ships fully commented out in the ini, yet -StigId must still find it.
        $r = & $script:ScriptPath -StigId $targetId -ListRules -PassThru
        $r.Count | Should -Be 1
    }

    It '-IgnoreRulesFile evaluates a rule even when its ini line is commented out' {
        $targetId = ($script:AllRules | Where-Object Section -eq 'DoD' | Select-Object -First 1).STIGID
        $withIni    = & $script:ScriptPath -Section DoD -ListRules -PassThru
        $withoutIni = & $script:ScriptPath -Section DoD -ListRules -PassThru -IgnoreRulesFile
        $withIni.STIGID | Should -Not -Contain $targetId
        $withoutIni.STIGID | Should -Contain $targetId
    }
}

Describe 'Windows11-STIG-Computer-V2R7 check-only execution' {

    It 'produces a well-formed report row without touching -Remediate' {
        $regId = ($script:AllRules | Where-Object CheckType -eq 'Registry' | Select-Object -First 1).STIGID
        $r = & $script:ScriptPath -StigId $regId -PassThru
        $r.Count | Should -Be 1
        $r[0].STIGID     | Should -Be $regId
        $r[0].Remediated | Should -Be 'No'
        $r[0].Status     | Should -BeIn @('Compliant', 'Non-Compliant')
    }
}
