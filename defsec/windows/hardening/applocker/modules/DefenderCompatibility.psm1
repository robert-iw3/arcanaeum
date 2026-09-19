<#
.SYNOPSIS
    Allow-lists Microsoft Defender's own platform binaries, which live outside the locations the
    base policy already trusts.

.DESCRIPTION
    Defender's antimalware platform (MsMpEng.exe, NisSrv.exe, MPOAV.DLL, and friends) installs to
    %OSDRIVE%\ProgramData\Microsoft\Windows Defender\Platform\<version>\ - not Program Files, not Windows -
    so the base policy's default-deny catches it. The practical symptom: as soon as the policy is
    deployed, AppLocker generates an audit/block hit for Defender's own components essentially
    continuously (every scan, every signature update spins up these binaries again), which is both
    noisy in the audit log and - if the popup-alert task is wired up - actively disruptive to the
    user.

    This module exists because the threat-targeted modules in this folder should stay narrowly
    scoped to actual attack paths (see modules/README.md); this one is different in kind - it's a
    correctness fix for the base policy's blind spot for a piece of necessary, already-trusted OS
    security software, not a deny rule against an attack. Default-on because leaving Defender
    broken is never the intended outcome of deploying this baseline.

    Allows Exe, Dll, and Script execution from the Platform folder specifically (not all of
    ProgramData, and not all of "Windows Defender" - just the versioned Platform subfolder where
    the actual executable components live) for Everyone, matching how the base policy scopes its
    other OS-component allow rules.
#>

# %PROGRAMDATA% is NOT a real AppLocker path variable - AppLocker only resolves %WINDIR%,
# %SYSTEM32%, %OSDRIVE%, and %PROGRAMFILES%. A rule written with %PROGRAMDATA% is silently
# inert (treated as a literal, nonexistent path) - this was exactly the bug that let Defender
# keep getting blocked even after this module was deployed. Use %OSDRIVE%\ProgramData instead.
$script:DefenderPlatformPath = '%OSDRIVE%\ProgramData\Microsoft\Windows Defender\Platform\*'

function Get-DefenderCompatibilityStatus {
    $results = @()
    try {
        $allRules = @()
        foreach ($collType in 'Exe', 'Dll', 'Script') {
            $coll = (Get-AppLockerPolicy -Local).RuleCollections | Where-Object { $_.RuleCollectionType -eq $collType }
            if ($coll) { $allRules += @($coll) }
        }
        $covered = @($allRules | Where-Object { $_.Action -eq 'Allow' -and $_.Name -match 'Defender' })
        $results += "Defender Platform allow rules present: $(if ($covered.Count -gt 0) { $covered.Count } else { '0 - run -Remediate' })"
    } catch {
        $results += "AppLocker rule collections not readable yet."
    }
    $results
}

function Get-DefenderCompatibilityPolicyFragment {
    foreach ($collectionType in 'Exe', 'Dll', 'Script') {
        $id = [guid]::NewGuid().ToString()
        $name = "Allow Microsoft Defender Platform binaries ($collectionType)"
        [PSCustomObject]@{
            CollectionType = $collectionType
            Name           = $name
            Xml            = @"
<FilePathRule Id="$id" Name="$name" Description="Defender's antimalware platform binaries install under ProgramData, outside the base policy's trusted locations, and would otherwise be denied/audited continuously. See modules/DefenderCompatibility.psm1." UserOrGroupSid="S-1-1-0" Action="Allow">
    <Conditions>
        <FilePathCondition Path="$script:DefenderPlatformPath" />
    </Conditions>
</FilePathRule>
"@
        }
    }
}

Export-ModuleMember -Function Get-DefenderCompatibilityStatus, Get-DefenderCompatibilityPolicyFragment
