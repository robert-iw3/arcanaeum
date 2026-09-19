#Requires -Module Pester

<#
.SYNOPSIS
    Guarded, real (unmocked) end-to-end test of Invoke-AppLockerBaseline.ps1's assess-only path -
    mirrors the pattern used in stig-automation\pwsh\tests for its orchestrator. Only the safe,
    read-only dry-run and -ShowAuditHits paths are exercised for real; -Remediate is intentionally
    NOT run here since it changes local security policy and starts a service on whatever machine
    runs the suite.
#>

BeforeAll {
    $script:Root = Join-Path $PSScriptRoot '..'
    $script:OrchestratorPath = Join-Path $script:Root 'Invoke-AppLockerBaseline.ps1'
    # Dot-source only so Test-Admin exists to be Mock-able below; the orchestrator dot-sources its
    # own copy when run via & and isn't affected by this one.
    . (Join-Path $script:Root 'Invoke-AppLockerBaseline.Functions.ps1')

    $script:Available = $true
    $script:SkipReason = $null
    if (-not $IsWindows -and $PSVersionTable.PSVersion.Major -ge 6) {
        $script:Available = $false
        $script:SkipReason = 'Windows-only (AppLocker, CIM, services).'
    } elseif (-not (Get-Command Get-AppLockerPolicy -ErrorAction SilentlyContinue)) {
        $script:Available = $false
        $script:SkipReason = 'AppLocker PowerShell module is not present on this host.'
    }
}

Describe 'Invoke-AppLockerBaseline.ps1 end-to-end (guarded, assess-only)' {

    It 'runs a dry run, reports every section, and makes no changes' {
        if (-not $script:Available) { Set-ItResult -Skipped -Because $script:SkipReason; return }

        $out = & $script:OrchestratorPath *>&1 | Out-String

        $out | Should -Match 'Application Identity service'
        $out | Should -Match 'Local AppLocker policy'
        $out | Should -Match 'AppLocker event logs'
        $out | Should -Match 'Block-notification task'
        $out | Should -Match 'Dry run only'
    }

    It 'wires in the full default module set and reports each one''s status' {
        if (-not $script:Available) { Set-ItResult -Skipped -Because $script:SkipReason; return }

        $out = & $script:OrchestratorPath *>&1 | Out-String
        foreach ($name in 'ClickFix', 'PhishingAttachmentGuard', 'RemovableMediaGuard', 'ExplorerVisibilityHardening', 'BrowserScamGuard', 'DefenderCompatibility', 'WindowsAppRepository') {
            $out | Should -Match "Module: $name"
        }
        $out | Should -Match 'Windows Script Host'
    }

    It 'does not wire in the opt-in modules by default' {
        if (-not $script:Available) { Set-ItResult -Skipped -Because $script:SkipReason; return }

        $out = & $script:OrchestratorPath *>&1 | Out-String
        foreach ($name in 'RunDialogLockdown', 'RemoteAccessToolGuard', 'OfficeMacroGuard') {
            $out | Should -Not -Match "Module: $name"
        }
    }

    It '-Modules @() wires in no modules' {
        if (-not $script:Available) { Set-ItResult -Skipped -Because $script:SkipReason; return }

        $out = & $script:OrchestratorPath -Modules @() *>&1 | Out-String
        $out | Should -Not -Match 'Module: ClickFix'
    }

    It '-Modules All wires in every module, including the opt-in ones' {
        if (-not $script:Available) { Set-ItResult -Skipped -Because $script:SkipReason; return }

        $out = & $script:OrchestratorPath -Modules All *>&1 | Out-String
        foreach ($name in 'ClickFix', 'PhishingAttachmentGuard', 'RemovableMediaGuard', 'ExplorerVisibilityHardening',
            'BrowserScamGuard', 'DefenderCompatibility', 'WindowsAppRepository', 'RunDialogLockdown', 'RemoteAccessToolGuard', 'OfficeMacroGuard') {
            $out | Should -Match "Module: $name"
        }
    }

    It '-ShowAuditHits stays read-only and reports both Exe/Script and Dll sections' {
        if (-not $script:Available) { Set-ItResult -Skipped -Because $script:SkipReason; return }

        $out = & $script:OrchestratorPath -ShowAuditHits *>&1 | Out-String
        $out | Should -Match 'Exe/Script/MSI'
        $out | Should -Match 'Dll collection audit hits'
    }

    It 'never calls Set-AppLockerPolicy, Set-Service, or Register-ScheduledTask without -Remediate' {
        if (-not $script:Available) { Set-ItResult -Skipped -Because $script:SkipReason; return }

        Mock Set-AppLockerPolicy { throw 'Set-AppLockerPolicy should not be called in a dry run' }
        Mock Set-Service { throw 'Set-Service should not be called in a dry run' }
        Mock Register-ScheduledTask { throw 'Register-ScheduledTask should not be called in a dry run' }

        { & $script:OrchestratorPath *>&1 | Out-Null } | Should -Not -Throw
    }
}

Describe 'Invoke-AppLockerBaseline.ps1 -Remediate (fully mocked - no real service/policy changes)' {
    <#
        Regression coverage for a real bug: $ErrorActionPreference = 'Stop' at the top of the
        orchestrator means ANY unhandled error anywhere - including a non-fatal one, like
        Set-Service failing to flip AppIDSvc's StartType on a host with a locked-down service ACL -
        aborts the entire -Remediate run before the actual AppLocker policy import. AppIDSvc ships
        with its own trigger-start configuration, so failing to set its StartType to Automatic
        should be a warning, not a script-ending error.
    #>

    It 'still imports the AppLocker policy even when setting AppIDSvc startup type is access-denied' {
        if (-not $script:Available) { Set-ItResult -Skipped -Because $script:SkipReason; return }

        Mock Test-Admin { $true }
        Mock Get-CimInstance { [pscustomobject]@{ Caption = 'Microsoft Windows 11 Pro' } }
        Mock Get-Service { [pscustomobject]@{ Name = 'AppIDSvc'; StartType = 'Manual' } } -ParameterFilter { $Name -eq 'AppIDSvc' }
        Mock Set-Service { throw "Service 'Application Identity (AppIDSvc)' description cannot be configured due to the following error:`nAccess is denied" }
        Mock Start-Service { }
        Mock Get-AppLockerPolicy {
            if ($Xml) { '<AppLockerPolicy Version="1"></AppLockerPolicy>' } else { [pscustomobject]@{ RuleCollections = @() } }
        }
        Mock Set-AppLockerPolicy { }

        $outDir = Join-Path $TestDrive 'remediate-out'
        $out = & $script:OrchestratorPath -Remediate -SkipVisibility -Modules @() -OutputPath $outDir *>&1 | Out-String

        Should -Invoke Set-AppLockerPolicy -Times 1
        $out | Should -Match 'Could not set AppIDSvc startup type'
        $out | Should -Match 'Importing AppLocker policy from'
    }

    It 'passes Set-AppLockerPolicy a real file path, not inline XML text (regression: -XmlPolicy takes a path despite its name)' {
        <#
            Real bug: Set-AppLockerPolicy -XmlPolicy actually expects a path to a file containing
            the policy, not the XML content itself, despite what the name suggests. Passing the
            XML string directly fails for real with "The following file cannot be resolved:
            <AppLockerPolicy ...>". A mock that accepts any value blindly (as in the test above)
            can't catch this - it has to check that whatever was passed actually resolves as a file.
        #>
        if (-not $script:Available) { Set-ItResult -Skipped -Because $script:SkipReason; return }

        Mock Test-Admin { $true }
        Mock Get-CimInstance { [pscustomobject]@{ Caption = 'Microsoft Windows 11 Pro' } }
        Mock Get-Service { [pscustomobject]@{ Name = 'AppIDSvc'; StartType = 'Automatic' } } -ParameterFilter { $Name -eq 'AppIDSvc' }
        Mock Start-Service { }
        Mock Get-AppLockerPolicy {
            if ($Xml) { '<AppLockerPolicy Version="1"></AppLockerPolicy>' } else { [pscustomobject]@{ RuleCollections = @() } }
        }
        Mock Set-AppLockerPolicy { }

        $outDir = Join-Path $TestDrive 'remediate-out2'
        & $script:OrchestratorPath -Remediate -SkipVisibility -Modules @() -OutputPath $outDir *>&1 | Out-Null

        Should -Invoke Set-AppLockerPolicy -Times 1 -ParameterFilter {
            (Test-Path -LiteralPath $XmlPolicy -PathType Leaf) -and ((Get-Content -LiteralPath $XmlPolicy -Raw) -match '<AppLockerPolicy')
        }
    }
}

Describe 'Invoke-AppLockerBaseline.ps1 popup-alert task gating (fully mocked)' {
    <#
        Regression coverage for a real incident: the popup task fires on every Audit-level
        AppLocker event, not just real blocks. AuditOnly is expected to be noisy while the policy
        is tuned (every miss against the base allow-list gets logged, e.g. Microsoft Defender's
        own ProgramData platform binaries before DefenderCompatibility allow-lists them) - popping
        up a message for each one is disruptive, not informative. The task must only be registered
        once -Enforce is also passed.
    #>

    BeforeEach {
        if ($script:Available) {
            Mock Test-Admin { $true }
            Mock Get-CimInstance { [pscustomobject]@{ Caption = 'Microsoft Windows 11 Pro' } }
            Mock Get-Service { [pscustomobject]@{ Name = 'AppIDSvc'; StartType = 'Automatic' } } -ParameterFilter { $Name -eq 'AppIDSvc' }
            Mock Start-Service { }
            Mock Get-AppLockerPolicy {
                if ($Xml) { '<AppLockerPolicy Version="1"></AppLockerPolicy>' } else { [pscustomobject]@{ RuleCollections = @() } }
            }
            Mock Set-AppLockerPolicy { }
            Mock wevtutil.exe { }
            Mock Register-ScheduledTask { }
        }
    }

    It 'does not register the popup-alert task during plain AuditOnly -Remediate' {
        if (-not $script:Available) { Set-ItResult -Skipped -Because $script:SkipReason; return }
        Mock Get-ScheduledTask { $null }

        $outDir = Join-Path $TestDrive 'popup-auditonly'
        $out = & $script:OrchestratorPath -Remediate -Modules @() -OutputPath $outDir *>&1 | Out-String

        Should -Invoke Register-ScheduledTask -Times 0
        $out | Should -Match 'Skipping popup-alert task while in AuditOnly'
    }

    It 'disables an already-registered popup-alert task when re-running plain AuditOnly -Remediate' {
        if (-not $script:Available) { Set-ItResult -Skipped -Because $script:SkipReason; return }
        Mock Get-ScheduledTask { [pscustomobject]@{ TaskName = 'AppLocker Popup Alert'; State = 'Ready' } }
        Mock Disable-ScheduledTask { }

        $outDir = Join-Path $TestDrive 'popup-auditonly2'
        & $script:OrchestratorPath -Remediate -Modules @() -OutputPath $outDir *>&1 | Out-Null

        Should -Invoke Disable-ScheduledTask -Times 1
    }

    It 'registers the popup-alert task when -Enforce is passed' {
        if (-not $script:Available) { Set-ItResult -Skipped -Because $script:SkipReason; return }
        Mock Get-ScheduledTask { $null }

        $outDir = Join-Path $TestDrive 'popup-enforce'
        & $script:OrchestratorPath -Remediate -Enforce -Modules @() -OutputPath $outDir *>&1 | Out-Null

        Should -Invoke Register-ScheduledTask -Times 1 -ParameterFilter { $TaskName -eq 'AppLocker Popup Alert' }
    }
}
