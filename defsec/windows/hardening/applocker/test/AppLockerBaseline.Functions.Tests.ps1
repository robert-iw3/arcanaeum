#Requires -Module Pester

<#
.SYNOPSIS
    Unit tests for the pure logic in Invoke-AppLockerBaseline.Functions.ps1 - module
    discovery/resolution, module phase dispatch, and AppLockerPolicy XML manipulation. None of
    these touch the registry, services, or AppLocker itself, so they run anywhere, unelevated.
#>

BeforeAll {
    $script:Root          = Join-Path $PSScriptRoot '..'
    $script:FunctionsPath = Join-Path $script:Root 'Invoke-AppLockerBaseline.Functions.ps1'
    . $script:FunctionsPath

    function New-MinimalAppLockerPolicyDoc {
        $xml = @'
<AppLockerPolicy Version="1">
    <RuleCollection Type="Dll" EnforcementMode="AuditOnly"></RuleCollection>
    <RuleCollection Type="Exe" EnforcementMode="AuditOnly"></RuleCollection>
    <RuleCollection Type="Msi" EnforcementMode="AuditOnly"></RuleCollection>
    <RuleCollection Type="Script" EnforcementMode="AuditOnly"></RuleCollection>
    <RuleCollection Type="Appx" EnforcementMode="AuditOnly"></RuleCollection>
</AppLockerPolicy>
'@
        $doc = New-Object System.Xml.XmlDocument
        $doc.LoadXml($xml)
        $doc
    }
}

Describe 'Get-AppLockerAvailableModule' {

    It 'lists .psm1 base names in a real folder' {
        $tmp = Join-Path $TestDrive 'mods1'
        New-Item -ItemType Directory -Path $tmp | Out-Null
        'function Get-FooStatus {}' | Set-Content (Join-Path $tmp 'Foo.psm1')
        'function Get-BarStatus {}' | Set-Content (Join-Path $tmp 'Bar.psm1')
        'not a module' | Set-Content (Join-Path $tmp 'notes.txt')

        $names = Get-AppLockerAvailableModule -ModulesRoot $tmp
        $names | Should -Contain 'Foo'
        $names | Should -Contain 'Bar'
        $names.Count | Should -Be 2
    }

    It 'returns an empty array for a missing folder' {
        $names = Get-AppLockerAvailableModule -ModulesRoot (Join-Path $TestDrive 'does-not-exist')
        $names.Count | Should -Be 0
    }
}

Describe 'Resolve-AppLockerModule' {

    BeforeAll {
        $script:ModsDir = Join-Path $TestDrive 'mods2'
        New-Item -ItemType Directory -Path $script:ModsDir | Out-Null
        foreach ($n in 'Alpha', 'Beta', 'Gamma') {
            "function Get-${n}Status {}" | Set-Content (Join-Path $script:ModsDir "$n.psm1")
        }
    }

    It 'returns the default set (filtered to what exists) when -Modules was not bound' {
        $resolved = Resolve-AppLockerModule -RequestedModules @() -BoundModules $false `
            -DefaultModules @('Alpha', 'NotReal') -ModulesRoot $script:ModsDir
        $resolved | Should -Be @('Alpha')
    }

    It "returns every available module for -Modules 'All'" {
        $resolved = Resolve-AppLockerModule -RequestedModules @('All') -BoundModules $true `
            -DefaultModules @('Alpha') -ModulesRoot $script:ModsDir
        ($resolved | Sort-Object) | Should -Be @('Alpha', 'Beta', 'Gamma')
    }

    It 'returns nothing for an explicitly empty -Modules array' {
        $resolved = Resolve-AppLockerModule -RequestedModules @() -BoundModules $true `
            -DefaultModules @('Alpha') -ModulesRoot $script:ModsDir
        $resolved.Count | Should -Be 0
    }

    It 'filters a specific requested list down to what exists and warns about the rest' {
        $warnings = New-Object System.Collections.Generic.List[string]
        $resolved = Resolve-AppLockerModule -RequestedModules @('Beta', 'DoesNotExist') -BoundModules $true `
            -DefaultModules @('Alpha') -ModulesRoot $script:ModsDir `
            -WarningOut { param($msg) $warnings.Add($msg) }.GetNewClosure()

        $resolved | Should -Be @('Beta')
        $warnings.Count | Should -Be 1
        $warnings[0] | Should -Match 'DoesNotExist'
    }

    It 'splits a single comma-joined argument into individual module names (regression: powershell.exe -File does not split -Modules Foo,Bar across the array)' {
        $resolved = Resolve-AppLockerModule -RequestedModules @('Alpha,Beta,Gamma') -BoundModules $true `
            -DefaultModules @() -ModulesRoot $script:ModsDir
        ($resolved | Sort-Object) | Should -Be @('Alpha', 'Beta', 'Gamma')
    }
}

Describe 'Invoke-AppLockerModulePhase' {

    BeforeAll {
        $script:FixtureDir = Join-Path $TestDrive 'mods3'
        New-Item -ItemType Directory -Path $script:FixtureDir | Out-Null
        @'
function Get-FixtureStatus { @("status line 1", "status line 2") }
function Get-FixturePolicyFragment { @(@{ CollectionType = "Exe"; Name = "Test rule"; Xml = "<FilePathRule/>" }) }
function Invoke-FixtureHardening { param([switch]$Remediate) if ($Remediate) { @("did it") } else { @("dry run") } }
Export-ModuleMember -Function Get-FixtureStatus, Get-FixturePolicyFragment, Invoke-FixtureHardening
'@ | Set-Content (Join-Path $script:FixtureDir 'Fixture.psm1')

        @'
function Get-BareStatus { @("bare status") }
Export-ModuleMember -Function Get-BareStatus
'@ | Set-Content (Join-Path $script:FixtureDir 'Bare.psm1')

        Import-Module (Join-Path $script:FixtureDir 'Fixture.psm1') -Force
        Import-Module (Join-Path $script:FixtureDir 'Bare.psm1') -Force
    }

    It 'calls the Status function and returns its output' {
        Invoke-AppLockerModulePhase -ModuleName Fixture -Phase Status | Should -Be @('status line 1', 'status line 2')
    }

    It 'calls the PolicyFragment function and returns its output' {
        $frag = Invoke-AppLockerModulePhase -ModuleName Fixture -Phase PolicyFragment
        $frag.CollectionType | Should -Be 'Exe'
        $frag.Name | Should -Be 'Test rule'
    }

    It 'calls the Hardening function with -Remediate forwarded' {
        Invoke-AppLockerModulePhase -ModuleName Fixture -Phase Hardening -Remediate | Should -Be 'did it'
        Invoke-AppLockerModulePhase -ModuleName Fixture -Phase Hardening | Should -Be 'dry run'
    }

    It 'returns $null for a phase the module does not implement' {
        Invoke-AppLockerModulePhase -ModuleName Bare -Phase PolicyFragment | Should -BeNullOrEmpty
        Invoke-AppLockerModulePhase -ModuleName Bare -Phase Hardening | Should -BeNullOrEmpty
    }
}

Describe 'Add-AppLockerPolicyFragment' {

    It 'appends a rule node into the matching RuleCollection' {
        $doc = New-MinimalAppLockerPolicyDoc
        $ruleXml = '<FilePathRule Id="11111111-1111-1111-1111-111111111111" Name="Test" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%SYSTEM32%\test.exe" /></Conditions></FilePathRule>'

        Add-AppLockerPolicyFragment -PolicyDoc $doc -CollectionType Exe -RuleXml $ruleXml

        $exeCollection = $doc.SelectSingleNode("//RuleCollection[@Type='Exe']")
        $exeCollection.FilePathRule.Count | Should -Be 1
        $exeCollection.FilePathRule.Name | Should -Be 'Test'

        $dllCollection = $doc.SelectSingleNode("//RuleCollection[@Type='Dll']")
        $dllCollection.ChildNodes.Count | Should -Be 0
    }

    It 'throws when the target RuleCollection type does not exist in the document' {
        $xml = '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="AuditOnly"></RuleCollection></AppLockerPolicy>'
        $doc = New-Object System.Xml.XmlDocument
        $doc.LoadXml($xml)
        $ruleXml = '<FilePathRule Id="22222222-2222-2222-2222-222222222222" Name="Test" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%SYSTEM32%\test.exe" /></Conditions></FilePathRule>'

        { Add-AppLockerPolicyFragment -PolicyDoc $doc -CollectionType Script -RuleXml $ruleXml } | Should -Throw
    }
}

Describe 'Set-AppLockerRuleCollectionEnforcement' {

    It 'enables every collection except Dll by default' {
        $doc = New-MinimalAppLockerPolicyDoc
        Set-AppLockerRuleCollectionEnforcement -PolicyDoc $doc

        foreach ($rc in $doc.SelectNodes('//RuleCollection')) {
            if ($rc.Type -eq 'Dll') {
                $rc.EnforcementMode | Should -Be 'AuditOnly'
            } else {
                $rc.EnforcementMode | Should -Be 'Enabled'
            }
        }
    }

    It 'also enables Dll when -EnableDllRules is passed' {
        $doc = New-MinimalAppLockerPolicyDoc
        Set-AppLockerRuleCollectionEnforcement -PolicyDoc $doc -EnableDllRules

        $dll = $doc.SelectSingleNode("//RuleCollection[@Type='Dll']")
        $dll.EnforcementMode | Should -Be 'Enabled'
    }
}

Describe 'Get-AppLockerDllPublisherInfo' {
    <#
        Uses a real, always-present, Microsoft-signed system DLL (kernel32.dll) so the test
        is self-contained and exercises the real Get-AuthenticodeSignature code path. Skipped if
        the standard Windows system32 directory is not found (should never happen on Windows 11).
    #>

    BeforeAll {
        $script:K32 = Join-Path $env:WINDIR 'System32\kernel32.dll'
    }

    It 'returns ValidSignature=true and a publisher name containing O=MICROSOFT CORPORATION for kernel32.dll' {
        if (-not (Test-Path $script:K32)) { Set-ItResult -Skipped -Because "kernel32.dll not found at $script:K32"; return }
        $info = Get-AppLockerDllPublisherInfo -Path $script:K32
        $info.SignatureStatus | Should -Be 'Valid'
        $info.PublisherName   | Should -Match 'O=MICROSOFT CORPORATION'
        $info.IsSideloadingRisk | Should -Be $false
    }

    It 'populates OriginalName from version info, not the filename on disk (kernel32.dll InternalName is "KERNEL32" without extension)' {
        if (-not (Test-Path $script:K32)) { Set-ItResult -Skipped -Because "kernel32.dll not found"; return }
        $info = Get-AppLockerDllPublisherInfo -Path $script:K32
        $info.OriginalName | Should -Not -BeNullOrEmpty
        $info.OriginalName | Should -Be 'KERNEL32'              # version-info InternalName, not leaf filename "KERNEL32.DLL"
    }

    It 'returns a well-formed FilePublisherRule XML fragment' {
        if (-not (Test-Path $script:K32)) { Set-ItResult -Skipped -Because "kernel32.dll not found"; return }
        $info = Get-AppLockerDllPublisherInfo -Path $script:K32
        $info.SuggestedXml | Should -Not -BeNullOrEmpty
        $rule = ([xml]$info.SuggestedXml).DocumentElement
        $rule.LocalName | Should -Be 'FilePublisherRule'        # .LocalName gets the XML tag name; .Name returns the "Name" attribute value
        $rule.Action | Should -Be 'Allow'
        $rule.Id | Should -Match '^[0-9a-fA-F-]{36}$'
        $rule.Conditions.FilePublisherCondition.PublisherName | Should -Match 'O=MICROSOFT CORPORATION'
    }

    It 'sets IsSideloadingRisk = $true and returns no XML for a file that does not exist' {
        $info = Get-AppLockerDllPublisherInfo -Path 'C:\DoesNotExist\fake.dll'
        $info.IsSideloadingRisk | Should -Be $true
        $info.SuggestedXml | Should -BeNullOrEmpty
    }
}
