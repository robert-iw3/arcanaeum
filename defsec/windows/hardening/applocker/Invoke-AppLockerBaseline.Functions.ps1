<#
.SYNOPSIS
    Pure/testable helper functions for Invoke-AppLockerBaseline.ps1 - module discovery and
    dispatch, AppLocker policy XML manipulation. No registry/service/AppLocker calls live here;
    those stay in the orchestrator so this file can be dot-sourced and unit tested without
    Administrator rights or a live AppLocker stack.
#>

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-AppLockerAvailableModule {
    <#
    .SYNOPSIS
        Lists the module base names (without .psm1) available under a modules/ folder.
    #>
    param(
        [Parameter(Mandatory)] [string]$ModulesRoot
    )
    if (-not (Test-Path -LiteralPath $ModulesRoot)) { return @() }
    @(Get-ChildItem -LiteralPath $ModulesRoot -Filter '*.psm1' -File | ForEach-Object { $_.BaseName })
}

function Resolve-AppLockerModule {
    <#
    .SYNOPSIS
        Resolves which modules should be wired into a run.

    .DESCRIPTION
        - Not requested at all (BoundModules = $false) -> the default set.
        - Requested as @('All') -> every module found under ModulesRoot.
        - Requested as @() (explicitly empty) -> no modules.
        - Requested as a specific list -> that list, filtered to what actually exists
          (with a warning emitted via $WarningOut for anything not found).

        Each requested entry is also split on commas before resolution. This matters because
        `powershell.exe -File script.ps1 -Modules Foo,Bar` passes "Foo,Bar" as a single raw
        argument (no PowerShell-side array splitting happens across a -File boundary), so without
        this the whole comma-joined string is looked up as one (nonexistent) module name.
    #>
    param(
        [string[]]$RequestedModules,
        [bool]$BoundModules,
        [string[]]$DefaultModules,
        [Parameter(Mandatory)] [string]$ModulesRoot,
        [scriptblock]$WarningOut = { param($msg) Write-Warning $msg }
    )
    $available = Get-AppLockerAvailableModule -ModulesRoot $ModulesRoot

    if (-not $BoundModules) {
        return @($DefaultModules | Where-Object { $_ -in $available })
    }

    $RequestedModules = @($RequestedModules | ForEach-Object { $_ -split ',' } | Where-Object { $_ })

    if ($RequestedModules.Count -eq 1 -and $RequestedModules[0] -eq 'All') {
        return @($available)
    }
    if ($RequestedModules.Count -eq 0) {
        return @()
    }

    $resolved = @()
    foreach ($name in $RequestedModules) {
        if ($name -in $available) {
            $resolved += $name
        } else {
            & $WarningOut "Module '$name' not found under $ModulesRoot - skipping."
        }
    }
    return @($resolved)
}

function Invoke-AppLockerModulePhase {
    <#
    .SYNOPSIS
        Calls a module's convention-named function for a given phase, if it exports one.

    .DESCRIPTION
        Module contract (see modules\README.md):
            Get-<Name>Status            - phase 'Status'
            Get-<Name>PolicyFragment    - phase 'PolicyFragment'
            Invoke-<Name>Hardening      - phase 'Hardening'  (receives -Remediate)
            Invoke-<Name>Rollback       - phase 'Rollback'   (receives -Remediate)
        Returns $null if the module doesn't export a function for the requested phase.
    #>
    param(
        [Parameter(Mandatory)] [string]$ModuleName,
        [Parameter(Mandatory)] [ValidateSet('Status', 'PolicyFragment', 'Hardening', 'Rollback')] [string]$Phase,
        [switch]$Remediate
    )
    $functionName = switch ($Phase) {
        'Status'         { "Get-${ModuleName}Status" }
        'PolicyFragment' { "Get-${ModuleName}PolicyFragment" }
        'Hardening'      { "Invoke-${ModuleName}Hardening" }
        'Rollback'       { "Invoke-${ModuleName}Rollback" }
    }
    $cmd = Get-Command -Name $functionName -ErrorAction SilentlyContinue
    if (-not $cmd) { return $null }

    if ($Phase -in 'Hardening', 'Rollback') {
        return & $cmd -Remediate:$Remediate
    }
    return & $cmd
}

function Add-AppLockerPolicyFragment {
    <#
    .SYNOPSIS
        Appends a single rule node (as an XML string) into the matching RuleCollection of an
        in-memory AppLockerPolicy XmlDocument.
    #>
    param(
        [Parameter(Mandatory)] [System.Xml.XmlDocument]$PolicyDoc,
        [Parameter(Mandatory)] [ValidateSet('Dll', 'Exe', 'Msi', 'Script', 'Appx')] [string]$CollectionType,
        [Parameter(Mandatory)] [string]$RuleXml
    )
    $collectionNode = $PolicyDoc.SelectSingleNode("//RuleCollection[@Type='$CollectionType']")
    if (-not $collectionNode) {
        throw "RuleCollection type '$CollectionType' not found in policy."
    }
    $fragmentDoc = [xml]$RuleXml
    $importedNode = $PolicyDoc.ImportNode($fragmentDoc.DocumentElement, $true)
    $collectionNode.AppendChild($importedNode) | Out-Null
    $importedNode
}

function Set-AppLockerRuleCollectionEnforcement {
    <#
    .SYNOPSIS
        Flips RuleCollection EnforcementMode attributes to Enabled in-place on an in-memory
        AppLockerPolicy XmlDocument. Dll is left alone unless -EnableDllRules is passed.
    #>
    param(
        [Parameter(Mandatory)] [System.Xml.XmlDocument]$PolicyDoc,
        [switch]$EnableDllRules
    )
    foreach ($rc in $PolicyDoc.SelectNodes('//RuleCollection')) {
        if ($rc.Type -eq 'Dll' -and -not $EnableDllRules) { continue }
        $rc.EnforcementMode = 'Enabled'
    }
}

function Get-AppLockerDllPublisherInfo {
    <#
    .SYNOPSIS
        Given a DLL path, returns the publisher fields and a ready-to-paste FilePublisherRule XML
        fragment for adding it to the AppLocker Dll collection.

    .DESCRIPTION
        Part of the Dll allow-list workflow: after reviewing -ShowAuditHits Dll section, pipe the
        flagged DLL paths into this function to get the information needed to write a narrowly-scoped
        publisher rule. Publisher rules are mandatory for the Dll collection where at all possible -
        they verify the digital signature of the binary at load time, making them immune to DLL
        sideloading attacks. Path rules for DLLs are only defensible for OS-managed paths where
        standard users cannot write.

        This function uses Get-AuthenticodeSignature (a core cmdlet, no AppLocker module required)
        so it works in any elevated session regardless of whether the AppLocker module is loaded.
        It MUST be run on an account that can read the target file (elevation typically required for
        DLLs under System32 etc.).

    .EXAMPLE
        # Find the DLL from ShowAuditHits and get the rule suggestion
        Get-AppLockerDllPublisherInfo -Path 'C:\ProgramData\Microsoft\Windows\AppRepository\Packages\...\OpenConsoleProxy.dll'

    .EXAMPLE
        # Process multiple files from a list
        'C:\Path\To\A.dll','C:\Path\To\B.dll' | Get-AppLockerDllPublisherInfo
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Path
    )
    process {
        if (-not (Test-Path -LiteralPath $Path)) {
            return [PSCustomObject]@{
                FilePath      = $Path
                OriginalName  = $null
                ProductName   = $null
                PublisherName = $null
                SignatureStatus = 'FileNotFound'
                IsSideloadingRisk = $true
                Note          = "File not found at '$Path'. Verify the path from the audit event is accessible on this machine."
                SuggestedXml  = $null
            }
        }

        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
        $vi  = (Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue).VersionInfo

        $originalName = if ($vi -and $vi.InternalName) { $vi.InternalName.ToUpper() } `
                        elseif ($vi -and $vi.OriginalFilename) { $vi.OriginalFilename.ToUpper() } `
                        else { (Split-Path $Path -Leaf).ToUpper() }

        $productName  = if ($vi -and $vi.ProductName) { $vi.ProductName.ToUpper() } else { '' }

        if (-not $sig -or $sig.Status -ne 'Valid') {
            return [PSCustomObject]@{
                FilePath      = $Path
                OriginalName  = $originalName
                ProductName   = $productName
                PublisherName = $null
                SignatureStatus = if ($sig) { $sig.Status.ToString() } else { 'NoSignature' }
                IsSideloadingRisk = $true
                Note          = "UNSIGNED or untrusted: a publisher rule is not possible. A path rule is the only option but is sideloading-vulnerable - only add if you have confirmed the containing directory cannot be written to by standard users (use 'icacls ""$Path"" /verify' or check ACLs)."
                SuggestedXml  = $null
            }
        }

        $subject = $sig.SignerCertificate.Subject
        $parts   = @('O','L','S','C') | ForEach-Object {
            $k = $_
            if ($subject -match "(^|, )$k=([^,]+)") { "$k=$($Matches[2].Trim().ToUpper())" }
        }
        $publisherName = $parts -join ', '

        $id  = [guid]::NewGuid().ToString()
        $xml = @"
<FilePublisherRule Id="$id" Name="Allow $originalName ($publisherName)" Description="Publisher-verified: cannot be sideloaded without a valid $publisherName code-signing certificate. Add to the module that covers this software." UserOrGroupSid="S-1-1-0" Action="Allow">
    <Conditions>
        <FilePublisherCondition PublisherName="$publisherName" ProductName="$productName" BinaryName="$originalName">
            <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
    </Conditions>
</FilePublisherRule>
"@
        [PSCustomObject]@{
            FilePath      = $Path
            OriginalName  = $originalName
            ProductName   = $productName
            PublisherName = $publisherName
            SignatureStatus = $sig.Status.ToString()
            IsSideloadingRisk = $false
            Note          = "Publisher-verified by $publisherName. BinaryName=$originalName, ProductName=$productName. Widen BinaryName to '*' to cover all $productName DLLs from this publisher, or keep exact for maximum narrowness."
            SuggestedXml  = $xml
        }
    }
}
