#Requires -Module Pester

<#
.SYNOPSIS
    Pester tests for the orchestrator's dispatch logic (Invoke-StigHardening.Functions.ps1)
    and a guarded end-to-end smoke test of Invoke-StigHardening.ps1 itself.

.DESCRIPTION
    Resolve-StigSet / Get-ValidSetValues / Get-ChildScriptParams / ConvertTo-NormalizedReportRow
    are pure (no registry/secedit/auditpol/filesystem writes), so they're unit-tested directly.
    Get-ChildScriptParams is exercised against the REAL Get-Command objects of every child
    script in this repo, so a rename/removal of -Section/-Severity/-StigId/-RulesFile on any
    child is caught here instead of only at run time.
#>

BeforeAll {
    $script:Root          = Join-Path $PSScriptRoot '..'
    $script:FunctionsPath = Join-Path $script:Root 'Invoke-StigHardening.Functions.ps1'
    $script:OrchestratorPath = Join-Path $script:Root 'Invoke-StigHardening.ps1'
    . $script:FunctionsPath

    $script:Win11ComputerCmd     = Get-Command (Join-Path $script:Root 'win11\Windows11-STIG-Computer-V2R7.ps1')
    $script:Win11UserCmd         = Get-Command (Join-Path $script:Root 'win11\Windows11-STIG-User-V2R7.ps1')
    $script:Server2022Cmd        = Get-Command (Join-Path $script:Root 'server2022\WindowsServer2022-STIG-V2R7.ps1')
    $script:Server2025ComputerCmd= Get-Command (Join-Path $script:Root 'server2025\WindowsServer2025-DoD-STIG-Computer-V1R1.ps1')
    $script:Server2025UserCmd    = Get-Command (Join-Path $script:Root 'server2025\WindowsServer2025-DoD-STIG-User-V1R1.ps1')
}

Describe 'Resolve-StigSet host-to-baseline dispatch' {

    It 'resolves Windows 11 to the win11 Computer + User scripts' {
        $sys = [pscustomobject]@{ OSCaption = 'Microsoft Windows 11 Pro' }
        $set = Resolve-StigSet -Sys $sys -RootPath $script:Root
        $set.Name | Should -Be 'Windows 11 STIG V2R7'
        $set.Computer | Should -Be (Join-Path $script:Root 'win11\Windows11-STIG-Computer-V2R7.ps1')
        $set.User     | Should -Be (Join-Path $script:Root 'win11\Windows11-STIG-User-V2R7.ps1')
        Test-Path $set.Computer | Should -BeTrue
        Test-Path $set.User     | Should -BeTrue
    }

    It 'resolves Windows Server 2022 to the server2022 Computer script with no User script' {
        $sys = [pscustomobject]@{ OSCaption = 'Microsoft Windows Server 2022 Standard' }
        $set = Resolve-StigSet -Sys $sys -RootPath $script:Root
        $set.Name | Should -Be 'Windows Server 2022 STIG V2R7'
        Test-Path $set.Computer | Should -BeTrue
        $set.User | Should -BeNullOrEmpty
    }

    It 'resolves Windows Server 2025 to the server2025 Computer + User scripts' {
        $sys = [pscustomobject]@{ OSCaption = 'Microsoft Windows Server 2025 Datacenter' }
        $set = Resolve-StigSet -Sys $sys -RootPath $script:Root
        $set.Name | Should -Be 'Windows Server 2025 DoD STIG V1R1'
        Test-Path $set.Computer | Should -BeTrue
        Test-Path $set.User     | Should -BeTrue
    }

    It 'returns $null for an unsupported OS' {
        $sys = [pscustomobject]@{ OSCaption = 'Microsoft Windows 10 Pro' }
        Resolve-StigSet -Sys $sys -RootPath $script:Root | Should -BeNullOrEmpty
    }
}

Describe 'Get-ValidSetValues' {

    It 'returns the ValidateSet values for a real ValidateSet parameter' {
        $values = Get-ValidSetValues -Cmd $script:Win11ComputerCmd -ParamName 'Section'
        $values | Should -Contain 'All'
        $values | Should -Contain 'AccountPolicy'
    }

    It 'returns $null for a parameter the command does not have' {
        Get-ValidSetValues -Cmd $script:Win11ComputerCmd -ParamName 'NotARealParam' | Should -BeNullOrEmpty
    }

    It 'does not throw for a real parameter that has no ValidateSet' {
        # The function returns @() internally for this case, but PowerShell unrolls an empty
        # array written to the output stream, so the caller still observes $null - same as a
        # nonexistent parameter. Get-ChildScriptParams relies on exactly this (falls through to
        # "pass the value through unfiltered") rather than on telling the two cases apart.
        { Get-ValidSetValues -Cmd $script:Win11ComputerCmd -ParamName 'StigId' } | Should -Not -Throw
    }
}

Describe 'Get-ChildScriptParams forwarding (against real child scripts)' {

    It 'forwards Section/Severity/StigId/RulesFile to a win11 script that declares them all' {
        $params = Get-ChildScriptParams -Cmd $script:Win11ComputerCmd -Section @('AccountPolicy') -Severity @('High') `
                    -StigId @('WN11-SO-000195') -RulesFile 'custom.ini' -IgnoreRulesFile:$false -DoRemediate:$false
        $params.PassThru   | Should -BeTrue
        $params.Section    | Should -Be @('AccountPolicy')
        $params.Severity   | Should -Be @('High')
        $params.StigId     | Should -Be @('WN11-SO-000195')
        $params.RulesFile  | Should -Be 'custom.ini'
        $params.ContainsKey('Remediate') | Should -BeFalse
    }

    It 'passes the All section wildcard through untouched' {
        $params = Get-ChildScriptParams -Cmd $script:Win11ComputerCmd -Section @('All') -Severity @('High','Medium','Low')
        $params.Section | Should -Be @('All')
    }

    It 'drops Section values the child does not recognize instead of passing them through' {
        $params = Get-ChildScriptParams -Cmd $script:Win11ComputerCmd -Section @('TotallyBogusSection') -Severity @('High')
        $params.ContainsKey('Section') | Should -BeFalse
    }

    It 'sets Remediate only when -DoRemediate is passed' {
        $params = Get-ChildScriptParams -Cmd $script:Win11ComputerCmd -Section @('All') -Severity @('High') -DoRemediate
        $params.Remediate | Should -BeTrue
    }

    It 'does not forward Section to server2022 (no such parameter), but does forward Severity' {
        $params = Get-ChildScriptParams -Cmd $script:Server2022Cmd -Section @('AccountPolicy') -Severity @('High') -StigId @('V-254293')
        $params.ContainsKey('Section')  | Should -BeFalse
        $params.Severity | Should -Be @('High')
        $params.StigId | Should -Be @('V-254293')
        $params.PassThru | Should -BeTrue
    }

    It 'forwards StigId/RulesFile to server2025 Computer and User scripts' {
        foreach ($cmd in @($script:Server2025ComputerCmd, $script:Server2025UserCmd)) {
            $params = Get-ChildScriptParams -Cmd $cmd -StigId @('X-1') -RulesFile 'foo.ini' -IgnoreRulesFile
            $params.StigId          | Should -Be @('X-1')
            $params.RulesFile       | Should -Be 'foo.ini'
            $params.IgnoreRulesFile | Should -BeTrue
        }
    }

    It 'omits StigId/RulesFile entirely when none were requested' {
        $params = Get-ChildScriptParams -Cmd $script:Win11ComputerCmd -Section @('All') -Severity @('High')
        $params.ContainsKey('StigId')          | Should -BeFalse
        $params.ContainsKey('RulesFile')       | Should -BeFalse
        $params.ContainsKey('IgnoreRulesFile') | Should -BeFalse
    }
}

Describe 'ConvertTo-NormalizedReportRow' {

    It 'normalizes a win11-style row (STIGID/Section/Sev/Current)' {
        $row = [pscustomobject]@{ STIGID='WN11-SO-000195'; Section='SecurityOptions'; Sev='High'; Title='t'; Status='Compliant'; Remediated='No'; Current='1' }
        $n = $row | ConvertTo-NormalizedReportRow -Layer 'Computer'
        $n.Layer    | Should -Be 'Computer'
        $n.Id       | Should -Be 'WN11-SO-000195'
        $n.Section  | Should -Be 'SecurityOptions'
        $n.Severity | Should -Be 'High'
        $n.Current  | Should -Be '1'
    }

    It 'normalizes a server-style row (bare VID, no Section/Sev/Current)' {
        $row = [pscustomobject]@{ VID='V-254238'; Title='t'; Status='Compliant'; Remediated='No' }
        $n = $row | ConvertTo-NormalizedReportRow -Layer 'Computer'
        $n.Id         | Should -Be 'V-254238'
        $n.Section    | Should -Be '(monolithic)'
        $n.Severity   | Should -Be ''
        $n.Current    | Should -Be ''
        $n.Remediated | Should -Be 'No'
    }
}

Describe 'Invoke-StigHardening.ps1 end-to-end (guarded, assess-only)' {

    It 'runs a real dry-run scoped to a single rule on a supported host, with no backup' {
        $sys = [pscustomobject]@{ OSCaption = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption }
        $set = Resolve-StigSet -Sys $sys -RootPath $script:Root
        if (-not $set) {
            Set-ItResult -Skipped -Because "this host's OS ($($sys.OSCaption)) has no matching baseline in this repo"
            return
        }

        # Find one StigId the live Computer script actually exposes, so the run is fast and read-only.
        $cmd = Get-Command $set.Computer
        if (-not $cmd.Parameters.ContainsKey('StigId')) {
            Set-ItResult -Skipped -Because 'resolved Computer script has no -StigId parameter'
            return
        }
        $oneId = (& $set.Computer -ListRules -PassThru -IgnoreRulesFile)[0] |
            ForEach-Object { if ($_.PSObject.Properties.Name -contains 'STIGID') { $_.STIGID } else { $_.VID } }

        $out = Join-Path $TestDrive 'orch-run'
        & $script:OrchestratorPath -StigId $oneId -SkipBackup -OutputPath $out -Scope Computer -WarningAction SilentlyContinue 2>$null | Out-Null

        Test-Path (Join-Path $out 'assessment-pre.csv') | Should -BeTrue
        Test-Path (Join-Path $out 'STIG-Report.txt')    | Should -BeTrue
        $rows = Import-Csv (Join-Path $out 'assessment-pre.csv')
        $rows.Count | Should -Be 1
        $rows[0].Id | Should -Be $oneId
    }
}
