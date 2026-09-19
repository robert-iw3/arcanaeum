<#
.SYNOPSIS
    AppLocker baseline module: blocks execution from the locations email/web attachments actually
    land in before a user ever deliberately interacts with them.

.DESCRIPTION
    Outlook opens an attachment straight out of its secure temp folder without ever saving it
    anywhere meaningful; every browser keeps its own on-disk cache that a drive-by download can
    land content in outside the normal save-as flow. A normal user never has a legitimate reason
    to run an EXE or script directly out of any of these, in any browser:

        - Outlook Content.Outlook - opening an attachment without saving it first
        - INetCache               - Internet Explorer / legacy Edge (EdgeHTML) cache
        - Edge (Chromium) cache
        - Chrome cache
        - Firefox cache

    Deliberately does NOT cover the Downloads folder: downloading and running a legitimate
    installer is one of the most common, benign things a normal user does, so a blanket deny
    there would catch far more legitimate activity than attacks. The locations actually covered
    here share one property the Downloads folder doesn't: nobody ever intentionally navigates to
    or saves something there on purpose - they're pure attack surface, not a workflow.

    Once the base policy's Exe/Script collections are Enabled, this is mostly belt-and-suspenders
    - default-deny already covers anything outside Program Files/Windows. An explicit, clearly
    named Deny rule here still earns its keep two ways: (a) the event log shows exactly what
    happened ("blocked: Outlook attachment cache execution") instead of a generic
    not-on-the-allow-list miss, and (b) it keeps winning even if an allow rule gets added later
    for app-compat reasons, since Deny always takes precedence in AppLocker regardless of rule
    order.
#>

function Get-PhishingAttachmentGuardStatus {
    $results = @()
    try {
        $allRules = @()
        foreach ($collType in 'Exe', 'Script') {
            $coll = (Get-AppLockerPolicy -Local).RuleCollections | Where-Object { $_.RuleCollectionType -eq $collType }
            if ($coll) { $allRules += @($coll) }
        }
        $denyNames = @($allRules | Where-Object { $_.Action -eq 'Deny' } | Select-Object -ExpandProperty Name)
        $covered = @('Content.Outlook', 'INetCache', 'Edge cache', 'Chrome cache', 'Firefox cache') | Where-Object {
            $loc = $_
            $denyNames | Where-Object { $_ -match [regex]::Escape($loc) }
        }
        $results += "AppLocker deny rules present for: $(if ($covered) { $covered -join ', ' } else { '(none yet - run -Remediate)' })"
    } catch {
        $results += "AppLocker rule collections not readable yet."
    }
    $results
}

function Get-PhishingAttachmentGuardPolicyFragment {
    $locations = @(
        @{ Label = "Outlook's secure attachment temp folder (Content.Outlook)"; Path = '%OSDRIVE%\Users\*\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\*' },
        @{ Label = 'the Internet Explorer/legacy Edge cache (INetCache)'; Path = '%OSDRIVE%\Users\*\AppData\Local\Microsoft\Windows\INetCache\*' },
        @{ Label = 'the Edge (Chromium) browser cache'; Path = '%OSDRIVE%\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Cache\*' },
        @{ Label = 'the Chrome browser cache'; Path = '%OSDRIVE%\Users\*\AppData\Local\Google\Chrome\User Data\*\Cache\*' },
        @{ Label = 'the Firefox browser cache'; Path = '%OSDRIVE%\Users\*\AppData\Local\Mozilla\Firefox\Profiles\*\cache2\*' }
    )

    foreach ($loc in $locations) {
        foreach ($collectionType in 'Exe', 'Script') {
            $id = [guid]::NewGuid().ToString()
            $name = "Deny execution from $($loc.Label) (phishing/attachment scam mitigation)"
            [PSCustomObject]@{
                CollectionType = $collectionType
                Name           = $name
                Xml            = @"
<FilePathRule Id="$id" Name="$name" Description="Blocks running files straight out of $($loc.Label) - a location nobody ever deliberately saves to or runs from. See modules/PhishingAttachmentGuard.psm1." UserOrGroupSid="S-1-1-0" Action="Deny">
    <Conditions>
        <FilePathCondition Path="$($loc.Path)" />
    </Conditions>
</FilePathRule>
"@
            }
        }
    }
}

Export-ModuleMember -Function Get-PhishingAttachmentGuardStatus, Get-PhishingAttachmentGuardPolicyFragment
