<#
.SYNOPSIS
    Allow-lists Microsoft-signed DLLs loaded from the Windows App Repository (packaged app DLLs
    that live outside the locations the base Dll collection already trusts).

.DESCRIPTION
    Windows packages/stores DLLs for packaged (UWP/Appx) COM proxy and component libraries under
    %OSDRIVE%\ProgramData\Microsoft\Windows\AppRepository\Packages\<AppIdentity>\PackagedCOM\,
    not under Program Files or %WINDIR%, so the base Dll collection's path-based allow rules
    don't cover them. Windows Terminal's OpenConsoleProxy.dll is the most common real-world
    trigger: it generates continuous Dll collection audit/block hits immediately after Dll
    enforcement is turned on because any terminal window opened while running another app causes
    it to be loaded as a COM proxy DLL.

    Why publisher rule, not path rule:
    A FilePublisherRule verifies the DLL's embedded digital signature at load time - the rule
    evaluation checks that the binary is actually signed by O=MICROSOFT CORPORATION, regardless
    of where it was loaded from. A path rule would allow ANY DLL placed in the AppRepository
    path to run. The fundamental goal of the Dll collection is to prevent DLL sideloading
    (malware drops a fake DLL with the same name as a trusted one in a searched-before location
    to intercept load calls) - a publisher rule is immune to this by design since a malicious
    DLL cannot pass signature verification unless it is actually signed by Microsoft's code
    signing certificate. Use publisher rules for Dll collection wherever possible; path rules
    only when the binary is unsigned AND the path is demonstrably non-writable by standard users.

    Scope: Dll collection only. The Exe and Script collections already cover Program Files
    (where packaged app executables in WindowsApps\ live) - only the DLL loads from the
    AppRepository ProgramData path are a gap.
#>

$script:MicrosoftPublisher = 'O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US'

function Get-WindowsAppRepositoryStatus {
    $results = @()
    try {
        $dllCollection = @((Get-AppLockerPolicy -Local).RuleCollections | Where-Object { $_.RuleCollectionType -eq 'Dll' })
        $allowRules = @($dllCollection | Where-Object { $_.Action -eq 'Allow' -and $_.Name -match 'Packaged' })
        $results += "Microsoft packaged app Dll allow rule present: $(if ($allowRules.Count -gt 0) { 'yes' } else { 'no - run -Remediate' })"
    } catch {
        $results += "Dll rule collection not readable yet."
    }
    $results
}

function Get-WindowsAppRepositoryPolicyFragment {
    $id = [guid]::NewGuid().ToString()
    [PSCustomObject]@{
        CollectionType = 'Dll'
        Name           = "Allow Microsoft-signed packaged app DLLs (WindowsAppRepository)"
        Xml            = @"
<FilePublisherRule Id="$id" Name="Allow Microsoft-signed packaged app DLLs (WindowsAppRepository)" Description="Allows DLLs signed by Microsoft Corporation loaded from the Windows App Repository (PackagedCOM, ComponentLibrary etc. under ProgramData\Microsoft\Windows\AppRepository). Uses publisher verification, not path, so it cannot be exploited for DLL sideloading - the DLL must carry a valid Microsoft code-signing certificate. See modules/WindowsAppRepository.psm1." UserOrGroupSid="S-1-1-0" Action="Allow">
    <Conditions>
        <FilePublisherCondition PublisherName="$script:MicrosoftPublisher" ProductName="*" BinaryName="*">
            <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
    </Conditions>
</FilePublisherRule>
"@
    }
}

Export-ModuleMember -Function Get-WindowsAppRepositoryStatus, Get-WindowsAppRepositoryPolicyFragment
