<#
.SYNOPSIS
   Collects and enriches Entra ID and Azure IAM role assignments, producing output in HTML, TXT, and CSV formats.
#>

function Invoke-CheckRoles {

    ############################## Parameter section ########################
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$OutputFolder = ".",
        [Parameter(Mandatory=$false)][Object[]]$AdminUnitWithMembers,
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$false)][hashtable]$AzureIAMAssignments,
        [Parameter(Mandatory=$true)][hashtable]$TenantRoleAssignments,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp,
        [Parameter(Mandatory=$true)][hashtable]$AllGroupsDetails,
        [Parameter(Mandatory=$true)][hashtable]$EnterpriseApps,
        [Parameter(Mandatory=$true)][hashtable]$ManagedIdentities,
        [Parameter(Mandatory=$true)][hashtable]$AppRegistrations,
        [Parameter(Mandatory=$true)][hashtable]$Users
    )

    ############################## Function section ########################

    #Function to get details about specific objects
    function Get-ObjectDetails($ObjectID,$type="unknown"){

        if ($type -eq "unknown" -or $type -eq "user" ) {
            $MatchingUser = $Users[$($ObjectID)]
            if ($MatchingUser) {
                $object = [PSCustomObject]@{
                    DisplayName = $MatchingUser.UPN
                    DisplayNameLink = "<a href=Users_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($ObjectID)>$($MatchingUser.UPN)</a>"
                    Type = "User"
                }
                Return $object
            }
        }

        if ($type -eq "unknown" -or $type -eq "group" ) {
            $MatchingGroup = $AllGroupsDetails[$($ObjectID)]
            if ($MatchingGroup) {
                $object = [PSCustomObject]@{
                    DisplayName = $MatchingGroup.DisplayName
                    DisplayNameLink = "<a href=Groups_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($ObjectID)>$($MatchingGroup.DisplayName)</a>"
                    Type = "Group"
                }
                Return $object
            }
        }

        if ($type -eq "unknown" -or $type -eq "ServicePrincipal" ) {
            $MatchingEnterpriseApp = $EnterpriseApps[$($ObjectID)]
            if ($MatchingEnterpriseApp) {
                $object = [PSCustomObject]@{
                    DisplayName = $MatchingEnterpriseApp.DisplayName
                    DisplayNameLink = "<a href=EnterpriseApps_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($ObjectID)>$($MatchingEnterpriseApp.DisplayName)</a>"
                    Type = "Enterprise Application"
                }
                Return $object
            }
        }

        if ($type -eq "unknown" -or $type -eq "ManagedIdentity" -or $type -eq "ServicePrincipal" ) {
            $MatchingManagedIdentity = $ManagedIdentities[$($ObjectID)]
            if ($MatchingManagedIdentity) {
                $object = [PSCustomObject]@{
                    DisplayName = $MatchingManagedIdentity.DisplayName
                    DisplayNameLink = "<a href=ManagedIdentities_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($ObjectID)>$($MatchingManagedIdentity.DisplayName)</a>"
                    Type = "Managed Identity"
                }
                Return $object
            }
        }

        if ($type -eq "unknown" -or $type -eq "AppRegistration" ) {
            $MatchingAppRegistration = $AppRegistrations[$($ObjectID)]
            if ($MatchingAppRegistration) {
                $object = [PSCustomObject]@{
                    DisplayName = $MatchingAppRegistration.DisplayName
                    DisplayNameLink = "<a href=AppRegistration_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($ObjectID)>$($MatchingAppRegistration.DisplayName)</a>"
                    Type = "App Registration"
                }
                Return $object
            }
        }

        if ($type -eq "unknown" -or $type -eq "AdministrativeUnit" ) {
            $MatchingAdministrativeUnit = $AdminUnitWithMembers | Where-Object { $_.AuId -eq $ObjectID }
            if ($MatchingAdministrativeUnit) {
                $object = [PSCustomObject]@{
                    DisplayName = $MatchingAdministrativeUnit.DisplayName
                    DisplayNameLink = $MatchingAdministrativeUnit.DisplayName
                    Type = "Administrative Unit"
                }
                Return $object
            }
        }

        #Fallback for MS Enterprise App that has not been enumerated
        if ($type -eq "unknown") {

            $QueryParameters = @{
                '$select' = "Id,DisplayName"
            }
            $MatchingMSEnterpriseApp = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/servicePrincipals/$ObjectID" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)

            if ($MatchingMSEnterpriseApp) {
                $object = [PSCustomObject]@{
                    DisplayName = $MatchingMSEnterpriseApp.DisplayName
                    DisplayNameLink = $MatchingMSEnterpriseApp.DisplayName
                    Type = "Enterprise Application"
                }
                Return $object
            }
        }

        #Unknown Object
        if ($type -eq "unknown") {

            $object = [PSCustomObject]@{
                DisplayName = $ObjectID
                DisplayNameLink = $ObjectID
                Type = "Unknown Object"
            }
            Return $object
        }
    }

    ############################## Script section ########################

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    #Define basic variables
    $Title = "Role_Assignments"
    $WarningReport = @()
    if (-not $GLOBALGraphExtendedChecks) {$WarningReport += "Only active role assignments assessed!"}

    ########################################## SECTION: DATACOLLECTION ##########################################

    write-host "[*] Process Entra role assignments"

    # Flatten the merged hash table into a single array
    $FlattenedAssignments = $TenantRoleAssignments.GetEnumerator() | ForEach-Object {
        $_.Value
    } | ForEach-Object {
        $_
    }

    $EntraRoles = foreach ($item in $FlattenedAssignments) {
        $PrincipalDetails = Get-ObjectDetails -Object $item.PrincipalId

        $ScopeDetails = if ($item.DirectoryScopeId -eq "/") {
            [PSCustomObject]@{
                DisplayName = "/"
                DisplayNameLink = "/"
                Type        = "Tenant"
            }
        } elseif ($($item.DirectoryScopeId).Contains("administrativeUnits")) {
            $ObjectID = $($item.DirectoryScopeId).Replace("/administrativeUnits/", "")
            Get-ObjectDetails -Object $ObjectID -type AdministrativeUnit
        }else {
            $ObjectID = $item.DirectoryScopeId.Replace("/", "")
            Get-ObjectDetails -Object $ObjectID
        }
        #Convert Tier-Level to text
        switch ($item.RoleTier) {
            0 {$RoleTier = "Tier-0"; break}
            1 {$RoleTier = "Tier-1"; break}
            2 {$RoleTier = "Tier-2"; break}
            3 {$RoleTier = "Tier-3"; break}
            "?" {$RoleTier = "Uncategorized"}
        }
        [pscustomobject]@{
            "Role" = $($item.DisplayName)
            "PrincipalId" = $($item.PrincipalId)
            "PrincipalDisplayName" = $($PrincipalDetails.DisplayName)
            "PrincipalDisplayNameLink" = $($PrincipalDetails.DisplayNameLink)
            "PrincipalType" = $($PrincipalDetails.Type)
            "RoleTier" = $RoleTier
            "AssignmentType" = $($item.AssignmentType)
            "DirectoryScopeId" = $($item.DirectoryScopeId)
            "IsPrivileged" = $($item.IsPrivileged)
            "IsBuiltIn" = $($item.IsBuiltIn)
            "ScopeResolved" = "$($ScopeDetails.DisplayName) ($($ScopeDetails.Type))"
            "ScopeResolvedLink" = "$($ScopeDetails.DisplayNameLink) ($($ScopeDetails.Type))"
        }
    }

# Custom sort order
$SortedEntraRoles = $EntraRoles | Sort-Object @{
    Expression = { $_.Role -eq "Global Administrator" }
    Descending = $true
}, @{
    Expression = { $_.Role -match "privileged" }
    Descending = $true
}, @{
    Expression = { $_.Role -match "Application Administrator" }
    Descending = $true
}, @{
    Expression = { $_.Role -match "User Administrator" }
    Descending = $true
}, @{
    Expression = { $_.Role -match "Groups Administrator" }
    Descending = $true
}, @{
    Expression = { $_.Role -match "Reader" }
    Descending = $false
}, @{
    Expression = { $_.IsPrivileged }
    Descending = $true
}, @{
    Expression = { $_.Role }
    Descending = $false
}


write-host "[*] Process Azure role assignments"
# Convert hashtable to normal objects
$SortedAzureRoles = @()

$AzureIAMAssignments.GetEnumerator() | ForEach-Object {
    $PrincipalId = $_.Key
    $Assignments = $_.Value
    $PrincipalType = $_.Value.PrincipalType

    if ($PrincipalType -and $PrincipalType -notlike "Foreign*") {
        $PrincipalDetails = Get-ObjectDetails -Object $PrincipalId -type $_.Value.PrincipalType

        #Fallback
        if ($PrincipalDetails) {
            $PrincipalDetails = Get-ObjectDetails -Object $PrincipalId
        }
        if ($PrincipalDetails) {
            $PrincipalDisplayName = $($PrincipalDetails.DisplayName)
            $PrincipalDisplayNameLink = $($PrincipalDetails.DisplayNameLink)
        } else {
            $PrincipalDisplayName = "$PrincipalId (Unknown)"
            $PrincipalDisplayNameLink = "$PrincipalId (Unknown)"
        }

        foreach ($Assignment in $Assignments) {
            $SortedAzureRoles += [PSCustomObject]@{
                PrincipalId        = $PrincipalId
                "PrincipalDisplayName" = $PrincipalDisplayName
                "PrincipalDisplayNameLink" = $PrincipalDisplayNameLink
                "PrincipalType" = $Assignment.PrincipalType
                RoleType = $Assignment.RoleType
                Conditions = $Assignment.Conditions
                Role = $Assignment.RoleDefinitionName
                Scope              = $Assignment.Scope
                AssignmentType              = $Assignment.AssignmentType
            }
        }
    } elseif ($PrincipalType -like "*Foreign*") {
        foreach ($Assignment in $Assignments) {
            $SortedAzureRoles += [PSCustomObject]@{
                PrincipalId        = $PrincipalId
                "PrincipalDisplayName" = "$PrincipalId (Foreign)"
                "PrincipalDisplayNameLink" = "$PrincipalId (Foreign)"
                "PrincipalType" = $Assignment.PrincipalType
                RoleType = $Assignment.RoleType
                Conditions = $Assignment.Conditions
                Role = $Assignment.RoleDefinitionName
                Scope              = $Assignment.Scope
                AssignmentType              = $Assignment.AssignmentType
            }
        }

    } else {
        $PrincipalDetails = Get-ObjectDetails -Object $PrincipalId
        foreach ($Assignment in $Assignments) {
            $SortedAzureRoles += [PSCustomObject]@{
                PrincipalId        = $PrincipalId
                "PrincipalDisplayName" = $($PrincipalDetails.DisplayName)
                "PrincipalDisplayNameLink" = $($PrincipalDetails.DisplayNameLink)
                "PrincipalType" = $($PrincipalDetails.Type)
                RoleType = $Assignment.RoleType
                Conditions = $Assignment.Conditions
                Role = $Assignment.RoleDefinitionName
                Scope              = $Assignment.Scope
                AssignmentType     = $Assignment.AssignmentType
            }
        }
    }

}

# Define custom sorting logic for Scope
$SortedAzureRoles = $SortedAzureRoles | Sort-Object -Property @{
    # Primary sorting: Scope depth and specific path rules
    Expression = {
        if ($_['Scope'] -eq '/') {
            0  # Root path should come first
        } elseif ($_['Scope'] -like '/providers/Microsoft.Management/managementGroups/*') {
            1  # Management group paths come second
        } else {
            2 + ($_['Scope'] -split '/').Count  # Subscription paths sorted by depth
        }
    }
}, @{
    # Secondary sorting: Scope alphabetically (to maintain proper order within same depth)
    Expression = {$_.Scope}
}, @{
    # Tertiary sorting: RoleDefinitionName priority (within same Scope)
    Expression = {
        switch ($_.Role) {
            "Owner" { 0 }                      # Owner comes first
            "User Access Administrator" { 1 }
            "Contributor" { 2 }
            "Role Based Access Control Administrator" { 3 }
            "Reservations Administrator" { 4 }
            default { 5 + [string]::Compare($_.Role, '') } # Alphabetical for others
        }
    }
}



write-host "[*] Writing log files"

$mainEntraTable = $SortedEntraRoles | select-object -Property Role,RoleTier,IsPrivileged,IsBuiltIn,AssignmentType,@{Name = "Principal"; Expression = { $_.PrincipalDisplayNameLink}},PrincipalType,@{Name = "Scope"; Expression = { $_.ScopeResolvedLink}}
$mainEntraTableJson  = $mainEntraTable | ConvertTo-Json -Depth 5 -Compress

$mainEntraTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainEntraTableJson + "`n" + '</script>'


$mainAzureTable = $SortedAzureRoles | select-object -Property Scope,Role,RoleType,Conditions,AssignmentType,PrincipalType,@{Name = "Principal"; Expression = { $_.PrincipalDisplayNameLink}}
$mainAzureTableJson  = $mainAzureTable | ConvertTo-Json -Depth 5 -Compress

$mainAzureTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainAzureTableJson + "`n" + '</script>'



#Define header HTML
$headerHTML = [pscustomobject]@{
    "Executed in Tenant" = "$($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)"
    "Executed at" = "$StartTimestamp "
    "Execution Warnings" = $WarningReport -join ' / '
}
#Define header
$headerTXT = "************************************************************************************************************************
$Title Enumeration
Executed in Tenant: $($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)
Executed at: $StartTimestamp
Execution Warnings = $($WarningReport  -join ' / ')
************************************************************************************************************************
"
#Headers for the TXT output
$headerTXTEntraRoles = "
Entra Roles
****************************
"
$headerTXTAzureRoles = "
Azure Roles
****************************
"
    # Prepare HTML output
    $headerHTMLEntra = $headerHTML | ConvertTo-Html -Fragment -PreContent "<div id=`"loadingOverlay`"><div class=`"spinner`"></div><div class=`"loading-text`">Loading data...</div></div><nav id=`"topNav`"></nav><h1>Role Assignments Entra ID</h1>" -As List  -PostContent "<h2>$($Title) Overview</h2>"
    $headerHTMLAzure = $headerHTML | ConvertTo-Html -Fragment -PreContent "<div id=`"loadingOverlay`"><div class=`"spinner`"></div><div class=`"loading-text`">Loading data...</div></div><nav id=`"topNav`"></nav><h1>Role Assignments Azure IAM</h1>" -As List  -PostContent "<h2>$($Title) Overview</h2>"

    #Generate and write HTML Entra role report
    $Report = ConvertTo-HTML -Body "$headerHTMLEntra $mainEntraTableHTML" -Title "$Title Enumeration" -Head $GLOBALcss -PostContent $GLOBALJavaScript
    $Report | Out-File "$outputFolder\$($Title)_Entra_$($StartTimestamp)_$($CurrentTenant.DisplayName).html"

    #Write TXT and CSV files
    $headerTXT | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_Entra_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    $headerTXTEntraRoles | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_Entra_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    $SortedEntraRoles | format-table Role,RoleTier,IsPrivileged,IsBuiltIn,AssignmentType, PrincipalDisplayName, PrincipalType,ScopeResolved | Out-File -Width 512 "$outputFolder\$($Title)_Entra_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    $SortedEntraRoles | select-object Role,RoleTier,IsPrivileged,IsBuiltIn,AssignmentType, PrincipalDisplayName, PrincipalType,ScopeResolved | Export-Csv -Path "$outputFolder\$($Title)_Entra_$($StartTimestamp)_$($CurrentTenant.DisplayName).csv" -NoTypeInformation
    write-host "[+] Details of $($SortedEntraRoles.count) Entra ID role assignments stored in output files (CSV,TXT,HTML): $outputFolder\$($Title)_Entra_$($StartTimestamp)_$($CurrentTenant.DisplayName)"

    #Add information to the enumeration summary
    $EntraEligibleCount = 0
    $Tier0Count = 0
    $Tier1Count = 0
    $Tier2Count = 0
    $TierUncatCount = 0
    $AssignmentsBuiltInRoles = 0
    $AssignmentPrincipalTypUsers = 0
    $AssignmentPrincipalTypGroups = 0
    $AssignmentPrincipalTypApps = 0
    $AssignmentPrincipalTypMIs = 0
    $AssignmentPrincipalTypUnknown = 0

    foreach ($assignment in $SortedEntraRoles) {
        if ($assignment.AssignmentType -eq "eligible") {
            $EntraEligibleCount++
        }

        switch ($assignment.RoleTier) {
            "Tier-0" {$Tier0Count++; break}
            "Tier-1" {$Tier1Count++; break}
            "Tier-2" {$Tier2Count++; break}
            "Uncategorized" {$TierUncatCount++}
        }

        if ($Assignment.IsBuiltIn) {
            $AssignmentsBuiltInRoles++
        }

        switch ($assignment.PrincipalType) {
            "User" {$AssignmentPrincipalTypUsers++; break}
            "Group" {$AssignmentPrincipalTypGroups++; break}
            "Enterprise Application" {$AssignmentPrincipalTypApps++; break}
            "Managed Identity" {$AssignmentPrincipalTypMIs++; break}
            "Unknown Object" {$AssignmentPrincipalTypUnknown++}
        }
    }

    # Store in global var
    $GlobalAuditSummary.EntraRoleAssignments.Count = @($SortedEntraRoles).count
    $GlobalAuditSummary.EntraRoleAssignments.Eligible = $EntraEligibleCount
    $GlobalAuditSummary.EntraRoleAssignments.BuiltIn = $AssignmentsBuiltInRoles

    $GlobalAuditSummary.EntraRoleAssignments.PrincipalType.User = $AssignmentPrincipalTypUsers
    $GlobalAuditSummary.EntraRoleAssignments.PrincipalType.Group = $AssignmentPrincipalTypGroups
    $GlobalAuditSummary.EntraRoleAssignments.PrincipalType.App = $AssignmentPrincipalTypApps
    $GlobalAuditSummary.EntraRoleAssignments.PrincipalType.MI = $AssignmentPrincipalTypMIs
    $GlobalAuditSummary.EntraRoleAssignments.PrincipalType.Unknown = $AssignmentPrincipalTypUnknown

    $GlobalAuditSummary.EntraRoleAssignments.Tiers."Tier-0" = $Tier0Count
    $GlobalAuditSummary.EntraRoleAssignments.Tiers."Tier-1" = $Tier1Count
    $GlobalAuditSummary.EntraRoleAssignments.Tiers."Tier-2" = $Tier2Count
    $GlobalAuditSummary.EntraRoleAssignments.Tiers.Uncategorized = $TierUncatCount



    if ($SortedAzureRoles.count -ge 1) {
        $Report = ConvertTo-HTML -Body "$headerHTMLAzure $mainAzureTableHTML" -Title "$Title Enumeration" -Head $GLOBALcss -PostContent $GLOBALJavaScript
        $Report | Out-File "$outputFolder\$($Title)_Azure_$($StartTimestamp)_$($CurrentTenant.DisplayName).html"
        $headerTXTAzureRoles | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_Azure_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
        $SortedAzureRoles | format-table Scope,Role,RoleType,Conditions,AssignmentType,PrincipalDisplayName,PrincipalType | Out-File -Width 512 "$outputFolder\$($Title)_Azure_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
        $SortedAzureRoles | select-object Scope,Role,RoleType,Conditions,AssignmentType,PrincipalDisplayName,PrincipalType | Export-Csv -Path "$outputFolder\$($Title)_Azure_$($StartTimestamp)_$($CurrentTenant.DisplayName).csv" -NoTypeInformation
        write-host "[+] Details of $($SortedAzureRoles.count) Azure role assignments stored in output files (CSV,TXT,HTML): $outputFolder\$($Title)_Azure_$($StartTimestamp)_$($CurrentTenant.DisplayName)"

        #Add information to the enumeration summary
        $AzureEligibleCount = 0
        $AssignmentsBuiltInRoles = 0
        $AssignmentPrincipalTypUsers = 0
        $AssignmentPrincipalTypGroups = 0
        $AssignmentPrincipalTypSPs = 0
        $AssignmentPrincipalTypUnknown = 0

        foreach ($assignment in $SortedAzureRoles) {
            if ($assignment.AssignmentType -eq "eligible") {
                $AzureEligibleCount++
            }
            if ($Assignment.RoleType -match "BuiltInRole") {
                $AssignmentsBuiltInRoles++
            }

            switch ($assignment.PrincipalType) {
                "User" {$AssignmentPrincipalTypUsers++; break}
                "Group" {$AssignmentPrincipalTypGroups++; break}
                "ServicePrincipal" {$AssignmentPrincipalTypSPs++; break}
                "Unknown Object" {$AssignmentPrincipalTypUnknown++}
            }
        }

        #Add information to the enumeration summary
        $GlobalAuditSummary.AzureRoleAssignments.Count = $SortedAzureRoles.count
        $GlobalAuditSummary.AzureRoleAssignments.Eligible = $AzureEligibleCount
        $GlobalAuditSummary.AzureRoleAssignments.BuiltIn = $AssignmentsBuiltInRoles
        $GlobalAuditSummary.AzureRoleAssignments.PrincipalType.User = $AssignmentPrincipalTypUsers
        $GlobalAuditSummary.AzureRoleAssignments.PrincipalType.Group = $AssignmentPrincipalTypGroups
        $GlobalAuditSummary.AzureRoleAssignments.PrincipalType.SP = $AssignmentPrincipalTypSPs
        $GlobalAuditSummary.AzureRoleAssignments.PrincipalType.Unknown = $AssignmentPrincipalTypUnknown



    }

}

