<#
.SYNOPSIS
   Enumerate Managed Identities (including: API Permission, Source Tenant, Groups, Roles).
#>

function Invoke-CheckManagedIdentities {

    ############################## Parameter section ########################
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$OutputFolder = ".",
        [Parameter(Mandatory=$false)][switch]$includeMS = $false,
        [Parameter(Mandatory=$true)][hashtable]$AllGroupsDetails,
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$false)][hashtable]$AzureIAMAssignments,
        [Parameter(Mandatory=$true)][hashtable]$TenantRoleAssignments,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp
    )

    ############################## Function section ########################

    #Function to retrieve information about groups
    function Get-GroupDetails {
        param (
            [Parameter(Mandatory = $true)]
            [Object]$Group,
            [Parameter(Mandatory = $true)]
            [hashtable]$AllGroupsDetails
        )

        $GroupDetails = @()

        # Filtering assignments based on ObjectType and the associated IDs
        $MatchingGroup = $AllGroupsDetails[$($Group.id)]

        if (($MatchingGroup | Measure-Object).count -ge 1) {
            $GroupDetails = [PSCustomObject]@{
                Type = "Group"
                Id = $Group.Id
                DisplayName = $group.DisplayName
                Visibility= $MatchingGroup.Visibility
                GroupType = $MatchingGroup.Type
                SecurityEnabled = $MatchingGroup.SecurityEnabled
                RoleAssignable = $MatchingGroup.RoleAssignable
                AssignedRoleCount = $MatchingGroup.EntraRoles
                AssignedPrivilegedRoles = $MatchingGroup.EntraRolePrivilegedCount
                InheritedHighValue  = $MatchingGroup.InheritedHighValue
                AzureRoles  = $MatchingGroup.AzureRoles
                CAPs  = $MatchingGroup.CAPs
                ImpactOrg  = $MatchingGroup.ImpactOrg

            }
        }
        Return $GroupDetails
    }

    ############################## Script section ########################

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    #Define basic variables
    $Title = "ManagedIdentities"
    $ProgressCounter = 0
    $ManagedIdentitiesScriptWarningList = @()
    $AllServicePrincipal = [System.Collections.ArrayList]::new()
    $AllObjectDetailsHTML = [System.Collections.ArrayList]::new()
    $SPImpactScore = @{
        "Base"                     = 1
        "CAPGroupOwner"             = 100
        "InheritedHighValue"        = 200
        "APIDangerous"              = 300
        "APIHigh"                   = 200
        "APIMedium"                 = 100
        "APILow"                    = 50
        "ApiMisc"                   = 20
	    "GroupMember"               = 5
	    "GroupOwner"                = 5
        "AppRole"                   = 2
    }

    $SPLikelihoodScore = @{
        "Base"          	        = 1
    }

    ########################################## SECTION: DATACOLLECTION ##########################################
    # Get Managed Identity
    write-host "[*] Get Managed Identities"
    $QueryParameters = @{
        '$filter' = "ServicePrincipalType eq 'ManagedIdentity'"
        '$select' = "Id,DisplayName,AppId,AppRoles,servicePrincipalType,PasswordCredentials,KeyCredentials,AlternativeNames"
        '$top' = "999"
    }
    $ManagedIdentities = @(Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/servicePrincipals' -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name))


    $ManagedIdentitiesCount = $($ManagedIdentities.count)
    write-host "[+] Got $ManagedIdentitiesCount Managed Identities"

    # Check if Azure IAM role were checked
    if (-not ($GLOBALAzurePsChecks)) {
        $ManagedIdentitiesScriptWarningList += "Azure IAM assignments were not assessed"
    }

    if ($ManagedIdentitiesCount -ge 1) {
        # Get all App API Permissions (needed to resolve the ID to a human readable name)
        # It is required to do this on all MS apps to get the permissions of the custom apps
        write-host "[*] Get all API permissions"
        $QueryParameters = @{
            '$filter' = "ServicePrincipalType eq 'Application'"
            '$select' = "Id,DisplayName,AppRoles"
            '$top' = "999"
        }
        $EnterpriseApps = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/servicePrincipals' -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
        $AllPermissions = foreach ($item in $EnterpriseApps) {
            if ($null -ne $item.AppRoles) {
                $role = $item.AppRoles | Where-Object {$_.AllowedMemberTypes -contains "Application"} | select-object id,DisplayName,Value,Description
                foreach ($permission in $role) {
                    [PSCustomObject]@{
                        AppID = $item.Id
                        AppName = $item.DisplayName
                        ApiPermissionId = $permission.id
                        ApiPermissionValue = $permission.Value
                        ApiPermissionDisplayName = $permission.DisplayName
                        ApiPermissionDescription = $permission.Description
                        ApiPermissionCategorization = Get-APIPermissionCategory -InputPermission $permission.id -PermissionType "application"
                    }
                }
            }
        }

        Write-Host "[*] Get all applications API permissions assignments"
        $Requests = @()
        $ManagedIdentities | ForEach-Object {
            $Requests += @{
                "id"     = $($_.id)
                "method" = "GET"
                "url"    =   "/servicePrincipals/$($_.id)/appRoleAssignments?`$select=AppRoleId"
            }
        }
        # Send Batch request and create a hashtable
        $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name))
        $AppAssignmentsRaw = @{}
        foreach ($item in $RawResponse) {
            if ($item.response.value -and $item.response.value.Count -gt 0) {
                $AppAssignmentsRaw[$item.id] = $item.response.value
            }
        }



        Write-Host "[*] Get all applications group memberships"
        $Requests = @()
        $ManagedIdentities | ForEach-Object {
            $Requests += @{
                "id"     = $($_.id)
                "method" = "GET"
                "url"    =   "/servicePrincipals/$($_.id)/transitiveMemberOf/microsoft.graph.group?`$select=Id,displayName,visibility,securityEnabled,groupTypes,isAssignableToRole"
                "$top" = "999"
            }
        }
        # Send Batch request and create a hashtable
        $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name))
        $GroupMemberRaw = @{}
        foreach ($item in $RawResponse) {
            if ($item.response.value -and $item.response.value.Count -gt 0) {
                $GroupMemberRaw[$item.id] = $item.response.value
            }
        }

        Write-Host "[*] Get all applications objects ownerships"
        $Requests = @()
        $ManagedIdentities | ForEach-Object {
            $Requests += @{
                "id"     = $($_.id)
                "method" = "GET"
                "url"    =   "/servicePrincipals/$($_.id)/ownedObjects"
            }
        }
        # Send Batch request and create a hashtable
        $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name))
        $OwnedObjectsRaw = @{}
        foreach ($item in $RawResponse) {
            if ($item.response.value -and $item.response.value.Count -gt 0) {
                $OwnedObjectsRaw[$item.id] = $item.response.value
            }
        }
    }


    ########################################## SECTION: Managed Identity Processing ##########################################

    #Calc dynamic update interval
    $StatusUpdateInterval = [Math]::Max([Math]::Floor($ManagedIdentitiesCount / 10), 1)
    if ($ManagedIdentitiesCount -gt 0 -and $StatusUpdateInterval -gt 1) {
        Write-Host "[*] Status: Processing managed identity 1 of $ManagedIdentitiesCount (updates every $StatusUpdateInterval managed identities)..."
    }

    #Loop through each Managed Identity and get additional info and store it in a custom object
    foreach ($item in $ManagedIdentities) {
        $ProgressCounter++
        $ImpactScore = $SPImpactScore["Base"]
        $LikelihoodScore = $SPLikelihoodScore["Base"]
        $warnings = @()
        $WarningsHighPermission = $null
        $WarningsDangerousPermission = $null
        $AppCredentials = @()
        $OwnerSPDetails = @()


        # Display status based on the objects numbers (slightly improves performance)
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $ManagedIdentitiesCount) {
            Write-Host "[*] Status: Processing managed identity $ProgressCounter of $ManagedIdentitiesCount..."
        }

        #Get details
        $IsExplicit = ($item.AlternativeNames | Select-String -Pattern "isExplicit=").ToString().Split('=')[1].Trim()
        $MiPath = ($item.AlternativeNames | Select-String -NotMatch "isExplicit=").ToString().Trim()

        #Process API permissions (AKA. RoleAssignments) for this app
        $AppAssignments = [System.Collections.ArrayList]::new()
        if ($AppAssignmentsRaw.ContainsKey($item.Id)) {
            foreach ($AppAssignmentsRole in $AppAssignmentsRaw[$item.Id]) {
                [void]$AppAssignments.Add(
                    [PSCustomObject]@{
                        AppRoleId = $AppAssignmentsRole.AppRoleId
                    }
                )
            }
        }

        #Get the applications API permission
        $AppApiPermission = [System.Collections.ArrayList]::new()
        foreach ($AppSinglePermission in $AppAssignments) {

            $AssignedPermission =  $AllPermissions | where-object { $_.ApiPermissionId -eq $AppSinglePermission.AppRoleId}

            #Additional for loop because Office and MS Graph API have shared permission IDs
            foreach ($Permission in $AssignedPermission) {
                [void]$AppApiPermission.Add(
                    [pscustomobject]@{
                        Type = "Permission"
                        PermissionId = $Permission.ApiPermissionId
                        ApiPermission = $Permission.ApiPermissionValue
                        ApiName = $Permission.AppName
                        ApiPermissionDisplayname = $Permission.ApiPermissionDisplayname
                        ApiPermissionDescription = $Permission.ApiPermissionDescription
                        ApiPermissionCategorization = $Permission.ApiPermissionCategorization
                    }
                )
            }
        }

        # Define sort order
        $categorizationOrder = @{
            'Dangerous'     = 1
            'High'          = 2
            'Medium'        = 3
            'Low'           = 4
            'Uncategorized' = 5
        }

        # Sort
        $AppApiPermission = $AppApiPermission | Sort-Object ApiName, @{ Expression = { $categorizationOrder[$_.ApiPermissionCategorization] }; Ascending = $true }

        # Group once by categorization
        $grouped = $AppApiPermission | Group-Object ApiPermissionCategorization

        # Build counts dictionary
        $counts = @{}
        foreach ($group in $grouped) {
            $counts[$group.Name] = $group.Count
        }

        # Count by category (fallback to 0 if null/missing)
        $AppApiPermissionDangerous     = if ($counts.ContainsKey('Dangerous'))     { $counts['Dangerous'] }     else { 0 }
        $AppApiPermissionHigh          = if ($counts.ContainsKey('High'))          { $counts['High'] }          else { 0 }
        $AppApiPermissionMedium        = if ($counts.ContainsKey('Medium'))        { $counts['Medium'] }        else { 0 }
        $AppApiPermissionLow           = if ($counts.ContainsKey('Low'))           { $counts['Low'] }           else { 0 }
        $AppApiPermissionUncategorized = if ($counts.ContainsKey('Uncategorized')) { $counts['Uncategorized'] } else { 0 }


        # For all sp check if there are Azure IAM assignments
        if ($GLOBALAzurePsChecks) {
            #Use function to get the Azure Roles for each object
            $AzureRoleDetails = Get-AzureRoleDetails -AzureIAMAssignments $AzureIAMAssignments -ObjectId $item.Id
            # Update the Roles property only if there are matching roles
            $AzureRoleCount = ($AzureRoleDetails | Measure-Object).Count
        } else {
            $AzureRoleCount = "?"
        }

        # Enumerate all roles including scope the app is assigned to (note: Get-MgBetaServicePrincipalMemberOf do not return custom roles or scoped roles)
        $MatchingRoles = $TenantRoleAssignments[$item.Id]

        $AppEntraRoles = @()
        $AppEntraRoles = foreach ($Role in $MatchingRoles) {
            [PSCustomObject]@{
                Type = "Roles"
                DisplayName = $Role.DisplayName
                Enabled = $Role.IsEnabled
                IsBuiltin = $Role.IsBuiltIn
                RoleTier  = $role.RoleTier
                IsPrivileged = $Role.IsPrivileged
                Scoped = $Role.DirectoryScopeId
                ScopeResolved = $Role.ScopeResolved
            }
        }

        #Get all groups where the SP is member of
        $GroupMember = [System.Collections.ArrayList]::new()
        if ($GroupMemberRaw.ContainsKey($item.Id)) {
            foreach ($GroupMemberAssignment in $GroupMemberRaw[$item.Id]) {
                [void]$GroupMember.Add(
                    [PSCustomObject]@{
                        Id = $GroupMemberAssignment.Id
                        displayName = $GroupMemberAssignment.displayName
                        visibility = $GroupMemberAssignment.visibility
                        securityEnabled = $GroupMemberAssignment.securityEnabled
                        groupTypes = $GroupMemberAssignment.groupTypes
                        isAssignableToRole = $GroupMemberAssignment.isAssignableToRole
                    }
                )
            }
        }
        $GroupMember = foreach ($Group in $GroupMember) {
            Get-GroupDetails -Group $Group -AllGroupsDetails $AllGroupsDetails
        }

        #Get application owned objects (can own groups or applications)
        $OwnedApplications   = [System.Collections.ArrayList]::new()
        $OwnedGroups  	= [System.Collections.ArrayList]::new()
        $OwnedSP  	= [System.Collections.ArrayList]::new()
        if ($OwnedObjectsRaw.ContainsKey($item.Id)) {
            foreach ($OwnedObject in $OwnedObjectsRaw[$item.Id]) {
                switch ($OwnedObject.'@odata.type') {

                    '#microsoft.graph.servicePrincipal' {
                        [void]$OwnedSP.Add(
                            [PSCustomObject]@{
                                Id = $OwnedObject.Id
                                displayName = $OwnedObject.displayName
                                appId = $OwnedObject.appId
                            }
                        )
                    }

                    '#microsoft.graph.application' {
                        [void]$OwnedApplications.Add(
                            [PSCustomObject]@{
                                Id = $OwnedObject.Id
                                displayName = $OwnedObject.displayName
                                appId = $OwnedObject.appId
                            }
                        )
                    }

                    '#microsoft.graph.group' {
                        [void]$OwnedGroups.Add(
                            [PSCustomObject]@{
                                Id  = $OwnedObject.Id
                                displayName = $OwnedObject.displayName
                            }
                        )
                    }

                }
            }
        }

        #Process owned groups
        $OwnedGroups = foreach ($Group in $OwnedGroups) {
            Get-GroupDetails -Group $Group -AllGroupsDetails $AllGroupsDetails
        }

        $OwnedApplicationsCount = $OwnedApplications.count
        $OwnedSPCount = $OwnedSP.count


        #Check if sp has configured credentials
        $AppCredentialsSecrets = foreach ($creds in $item.PasswordCredentials) {
            [pscustomobject]@{
                Type = "Secret"
                DisplayName = $creds.DisplayName
                EndDateTime = $creds.EndDateTime
                StartDateTime = $creds.StartDateTime
            }
        }
        $AppCredentialsCertificates = foreach ($creds in $item.KeyCredentials) {
            [pscustomobject]@{
                Type = "Certificate"
                DisplayName = $creds.DisplayName
                EndDateTime = $creds.EndDateTime
                StartDateTime = $creds.StartDateTime
            }
        }
        $AppCredentials += $AppCredentialsSecrets
        $AppCredentials += $AppCredentialsCertificates


    ########################################## SECTION: RISK RATING AND WARNINGS ##########################################
        $AppCredentialsCount = ($AppCredentials | Measure-Object).count

        if ($AzureRoleCount -ge 1) {
            #Use function to get the impact score and warning message for assigned Azure roles
            $AzureRolesProcessedDetails = Invoke-AzureRoleProcessing -RoleDetails $azureRoleDetails
            $Warnings += $AzureRolesProcessedDetails.Warning
            $ImpactScore += $AzureRolesProcessedDetails.ImpactScore
        }

        #If SP owns App Registration
        if ($OwnedApplicationsCount -ge 1) {
            $Warnings += "SP owns $OwnedApplicationsCount App Registrations!"
        }

        #If SP owns App Registration
        if ($OwnedSPCount -ge 1) {
            $Warnings += "SP owns $OwnedSPCount Enterprise Applications!"
        }

        #Process group memberships
        if (($GroupMember | Measure-Object).count -ge 1) {
            $TotalAssignedRoleCount = 0
            $TotalAssignedPrivilegedRoles = 0
            $TotalInheritedHighValue = 0
            $AzureRoleValue = 0
            $TotalAzureRoles = 0

            #Basic score for being member of a group
            $ImpactScore += $SPImpactScore["GroupMember"]

                #Check each group
                foreach ($Groups in $GroupMember) {
                    $ImpactScore += $Groups.ImpactOrg
                    $TotalAssignedRoleCount += $Groups.AssignedRoleCount
                    $TotalAssignedPrivilegedRoles += $Groups.AssignedPrivilegedRoles
                    $TotalInheritedHighValue += $Groups.InheritedHighValue

                    #Special treatment if azure roles is not an int
                    $AzureRoleValue = 0
                    if ([int]::TryParse($Groups.AzureRoles, [ref]$AzureRoleValue)) {
                        $TotalAzureRoles += $AzureRoleValue
                    } else {
                        $TotalAzureRoles += 0
                    }
                }

                #Check Entra role assignments
                if ($TotalAssignedRoleCount -ge 1) {
                    if ($TotalAssignedPrivilegedRoles -ge 1) {
                        $privileged = "Privileged "
                    } else {
                        $privileged = ""
                    }
                    $Warnings += "$($privileged)Entra role(s) through group membership"
                }

                #Check Azure role assignments
                if ($TotalAzureRoles -ge 1) {
                    $Warnings += "$TotalAzureRoles Azure role(s) through group membership"
                }

                #Check membership of groups with inherited high value
                if ($TotalInheritedHighValue -ge 1) {
                    $Warnings += "Member of $TotalInheritedHighValue groups with high value"
                }
        }



        #Process Entra Role assignments
        #Use function to get the impact score and warning message for assigned Entra roles
        if (($AppEntraRoles | Measure-Object).count -ge 1) {
            $EntraRolesProcessedDetails = Invoke-EntraRoleProcessing -RoleDetails $AppEntraRoles
            $Warnings += $EntraRolesProcessedDetails.Warning
            $ImpactScore += $EntraRolesProcessedDetails.ImpactScore
        }


        #If SP owns groups
        if (($OwnedGroups | Measure-Object).count -ge 1) {
            $TotalAssignedRoleCount = 0
            $TotalAssignedPrivilegedRoles = 0
            $TotalInheritedHighValue = 0
            $AzureRoleValue = 0
            $TotalAzureRoles = 0
            $TotalCAPs = 0
            #Basic score for owning a group


                #Check each owned group
                foreach ($OwnedGroup in $OwnedGroups) {
                    $ImpactScore += $OwnedGroup.ImpactOrg
                    $TotalAssignedRoleCount += $OwnedGroup.AssignedRoleCount
                    $TotalAssignedPrivilegedRoles += $OwnedGroup.AssignedPrivilegedRoles
                    $TotalInheritedHighValue += $OwnedGroup.InheritedHighValue

                    #Special treatment if azure roles is not an int
                    $AzureRoleValue = 0
                    if ([int]::TryParse($OwnedGroup.AzureRoles, [ref]$AzureRoleValue)) {
                        $TotalAzureRoles += $AzureRoleValue
                    } else {
                        $TotalAzureRoles += 0
                    }

                    $TotalCAPs += $OwnedGroup.CAPs
                }

                #Check Entra role assignments
                if ($TotalAssignedRoleCount -ge 1) {
                    if ($TotalAssignedPrivilegedRoles -ge 1) {
                        $privileged = "Privileged "
                    } else {
                        $privileged = ""
                    }
                    $Warnings += "$($privileged)Entra role(s) through group ownership"
                }

                #Check Azure role assignments
                if ($TotalAzureRoles -ge 1) {
                    $Warnings += "$TotalAzureRoles Azure role(s) through group ownership"
                }

                #Check CAP group ownership
                if ($TotalCAPs -ge 1) {
                    $Warnings += "Owns $TotalCAPs groups used in CAPs"
                }

                #Check ownership of groups with inherited high value
                if ($TotalInheritedHighValue -ge 1) {
                    $Warnings += "Owns $TotalInheritedHighValue groups with high value"
                }
        }


        if (($AppApiPermission | Measure-Object).Count -ge 1) {
            foreach ($object in $AppApiPermission) {
                switch($object.ApiPermissionCategorization) {
                    "Dangerous" {$ImpactScore += $SPImpactScore["APIDangerous"]; $WarningsDangerousPermission = $true ; Break}
                    "High" {$ImpactScore += $SPImpactScore["APIHigh"]; $WarningsHighPermission = $true; Break}
                    "Medium" {$ImpactScore += $SPImpactScore["APIMedium"]; Break}
                    "Low" {$ImpactScore += $SPImpactScore["APILow"]; Break}
                    "Uncategorized" {$ImpactScore += $SPImpactScore["ApiMisc"]; Break}
                }
            }
        }

        # Build the warning parts dynamically
        [string[]]$severities = @()
        if ($WarningsDangerousPermission) { $severities += "dangerous" }
        if ($WarningsHighPermission)      { $severities += "high" }

        $severities = $severities | Select-Object -Unique

        # Generate joined warning
        if ($severities.Count -gt 0) {
            $lastIndex = $severities.Count - 1
            $last = $severities[$lastIndex]

            if ($severities.Count -gt 1) {
                $first = $severities[0..($lastIndex - 1)] -join ", "
                $joined = "$first and $last"
            } else {
                $joined = "$last"
            }
            $plural = ""
            if ($severities.Count -gt 1) { $plural = "s" }
            $Warnings += "Known $joined API permission$plural!"
        }

        #Format warning messages
        $Warnings = if ($null -ne $Warnings) {
            $Warnings -join ' / '
        } else {
            ''
        }

        #Write custom object
        $SPInfo = [PSCustomObject]@{
            Id = $item.Id
            DisplayName = $item.DisplayName
            DisplayNameLink = "<a href=#$($item.Id)>$($item.DisplayName)</a>"
            PublisherName = $item.PublisherName
            AppId = $item.AppId
            ServicePrincipalType = $item.servicePrincipalType
            SignInAudience = $item.signInAudience
            GroupMembership = ($GroupMember | Measure-Object).count
            EntraRoles = ($AppEntraRoles | Measure-Object).count
            PermissionCount = ($AppAssignments | Measure-Object).count
            GroupOwnership = ($OwnedGroups | Measure-Object).count
            AppOwnership = $OwnedApplicationsCount
            OwnedApplicationsDetails = $OwnedApplications
            SpOwn = $OwnedSPCount
            GroupMember = $GroupMember
            AppOwnerOrganizationId = $item.AppOwnerOrganizationId
            EntraRoleDetails = $AppEntraRoles
            GroupOwner = $OwnedGroups
            AppPermission = $AppAssignments
            IsExplicit = $IsExplicit
            MiPath = $MiPath
            AzureRoles = $AzureRoleCount
            AzureRoleDetails = $AzureRoleDetails
            OwnerSPDetails = $OwnerSPDetails
            AppRegObjectId = $AppRegObjectId
            AppCredentials = $AppCredentialsCount
            AppCredentialsDetails = $AppCredentials
            AppApiPermission = $AppApiPermission
            AppRoles = ($MatchingAppRoles | Measure-Object).count
            AppRolesDetails = $MatchingAppRoles
            ApiDangerous = $AppApiPermissionDangerous
            ApiHigh = $AppApiPermissionHigh
            ApiMedium = $AppApiPermissionMedium
            ApiLow = $AppApiPermissionLow
            ApiMisc = $AppApiPermissionUncategorized
            Impact = $ImpactScore
            Likelihood = $LikelihoodScore
            Risk = $ImpactScore * $LikelihoodScore
            Warnings = $Warnings
        }
        [void]$AllServicePrincipal.Add($SPInfo)
    }
    ########################################## SECTION: POST-PROCESSING ##########################################
    if ($ManagedIdentitiesCount -ge 1) {write-host "[*] Post-processing SP owns apps"}

    $SPOwningApps = $AllServicePrincipal | Where-Object { $_.AppOwnership -ge 1 }

    #For each object which owns an App registration
    foreach ($SpObject in $SPOwningApps) {

        # For each owned App Registration
        foreach ($AppRegistration in $SpObject.OwnedApplicationsDetails) {

            #For each corresponding SP object of the App Registration
            foreach ($OwnedSP in $AllServicePrincipal | Where-Object { $_.AppId -eq $AppRegistration.AppId }) {

                # Increment/Recalculate RiskScore of the SP objects which is indirectly
                $OwnedSP.Likelihood += [math]::Round($SpObject.Likelihood)
                $OwnedSP.Risk = [math]::Round(($OwnedSP.ImpactScore * $OwnedSP.Likelihood))

                # Append the Message to Warnings of the SP objects which is indirectly
                $warningMessage = "AppReg. owned by other SP"
                if ($OwnedSP.Warnings -and $OwnedSP.Warnings -notmatch $warningMessage) {
                    $OwnedSP.Warnings += " / $warningMessage"
                } else {
                    $OwnedSP.Warnings = $warningMessage
                }

                # Increment/Recalculate Impactscore of the SP which owns the other SP with it's impact score
                $SpObject.Impact += [math]::Round($OwnedSP.Impact)
                $SpObject.Risk = [math]::Round(($SpObject.Impact * $SpObject.Likelihood))
            }
        }
    }

   #For each object which owns an App registration
   foreach ($SpObject in $SPOwningApps) {

    # For each owned App Registration
    foreach ($AppRegistration in $SpObject.OwnedApplicationsDetails) {

        #For each corresponding SP get  object of the App Registration
        foreach ($OwnedSP in $AllServicePrincipal | Where-Object { $_.AppId -eq $AppRegistration.AppId }) {

            # Increment/Recalculate RiskScore of the SP objects which is indirectly
            $OwnedSP.Likelihood += [math]::Round($SpObject.Likelihood)
            $OwnedSP.Risk = [math]::Round(($OwnedSP.Impact * $OwnedSP.Likelihood))

            # Append the Message to Warnings of the SP objects which is indirectly
            $warningMessage = "AppReg. owned by other SP"
            if ($OwnedSP.Warnings -and $OwnedSP.Warnings -notmatch $warningMessage) {
                $OwnedSP.Warnings += " / $warningMessage"
            } else {
                $OwnedSP.Warnings = $warningMessage
            }

            # Increment/Recalculate Impactscore of the SP which owns the other SP with it's impact score
            $SpObject.Impact += [math]::Round($OwnedSP.Impact)
            $SpObject.Risk = [math]::Round(($SpObject.Impact * $SpObject.Likelihood))

        }
    }
}

    ########################################## SECTION: OUTPUT DEFINITION ##########################################
    write-host "[*] Generating reports"

    #Define output of the main table
    $tableOutput = $AllServicePrincipal | Sort-Object -Property risk -Descending | select-object DisplayName,DisplayNameLink,IsExplicit,GroupMembership,GroupOwnership,AppOwnership,SpOwn,EntraRoles,AppCredentials,AzureRoles,ApiDangerous, ApiHigh, ApiMedium, ApiLow, ApiMisc,Impact,Likelihood,Risk,Warnings

    #Define the apps to be displayed in detail and sort them by risk score
    $details = $AllServicePrincipal | Sort-Object Risk -Descending

    #Define stringbuilder to avoid performance impact
    $DetailTxtBuilder = [System.Text.StringBuilder]::new()

    #Enum the details for the apps in scope
    foreach ($item in $details) {
        $ReportingMIInfo = @()
        $ReportingRoles = @()
        $ReportingAzureRoles = @()
        $ReportingAppRoles = @()
        $ReportingAPIPermission = @()
        $ReportingAppOwner = @()
        $ReportingGroupMember = @()
        $ReportingGroupOwner = @()
        $ReportingCredentials = @()

        [void]$DetailTxtBuilder.AppendLine("############################################################################################################################################`n")

        ############### HEADER
        $ReportingMIInfo = [pscustomobject]@{
            "App Name" = $($item.DisplayName)
            "App Client-ID" = $($item.AppId)
            "App Object-ID" = $($item.Id)
            "Custom Identity" = $($item.IsExplicit)
            "Object Path" = $($item.MiPath)
            "RiskScore" = $($item.Risk)
        }

        #Build dynamic TXT report property list
        $TxtReportProps = @("App Name","App Client-ID","App Object-ID","Custom Identity","Object Path","RiskScore")

        if ($item.Warnings -ne '') {
            $ReportingMIInfo | Add-Member -NotePropertyName Warnings -NotePropertyValue $item.Warnings
            $TxtReportProps += "Warnings"
        }

        [void]$DetailTxtBuilder.AppendLine(($ReportingMIInfo | Select-Object $TxtReportProps | Out-String))

        ############### Entra Roles
        if ($($item.EntraRoleDetails | Measure-Object).count -ge 1) {
            $ReportingRoles = foreach ($object in $($item.EntraRoleDetails)) {
                [pscustomobject]@{
                    "Role name" = $($object.DisplayName)
                    "Tier Level" = $($object.RoleTier)
                    "Privileged" = $($object.isPrivileged)
                    "IsBuiltin" = $($object.IsBuiltin)
                    "Scoped to" = "$($object.ScopeResolved.DisplayName) ($($object.ScopeResolved.Type))"
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("Active Entra Role Assignments`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine(($ReportingRoles | Out-String))
        }


        ############### Azure Roles
        if ($($item.AzureRoleDetails | Measure-Object).count -ge 1) {
            $ReportingAzureRoles = foreach ($object in $($item.AzureRoleDetails)) {
                [pscustomobject]@{
                    "Role name" = $($object.RoleName)
                    "RoleType" = $($object.RoleType)
                    "Tier Level" = $($object.RoleTier)
                    "Conditions" = $($object.Conditions)
                    "Scoped to" = $($object.Scope)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("Azure IAM assignments`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAzureRoles | Out-String))
        }


        ############### Group Owner
        if ($($item.GroupOwner | Measure-Object).count -ge 1) {
            $ReportingGroupOwner = foreach ($object in $($item.GroupOwner)) {
                [pscustomobject]@{
                    "DisplayName" = $($object.DisplayName)
                    "DisplayNameLink" = "<a href=Groups_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.DisplayName)</a>"
                    "SecurityEnabled" = $($object.SecurityEnabled)
                    "RoleAssignable" = $($object.RoleAssignable)
                    "ActiveRoles" = $($object.AssignedRoleCount)
                    "ActivePrivilegedRoles" = $($object.AssignedPrivilegedRoles)
                    "AzureRoles" = $($object.AzureRoles)
                    "CAPs" = $($object.CAPs)
                    "ImpactOrg" = $($object.ImpactOrg)
                    "Warnings" = $($object.Warnings)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("Owner of Groups`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine(($ReportingGroupOwner | Format-Table DisplayName,SecurityEnabled,RoleAssignable,ActiveRoles,ActivePrivilegedRoles,AzureRoles,CAPs,ImpactOrg,Warnings | Out-String))

            $ReportingGroupOwner = foreach ($obj in $ReportingGroupOwner) {
                [pscustomobject]@{
                    DisplayName             = $obj.DisplayNameLink
                    SecurityEnabled         = $obj.SecurityEnabled
                    RoleAssignable          = $obj.RoleAssignable
                    ActiveRoles             = $obj.ActiveRoles
                    ActivePrivilegedRoles   = $obj.ActivePrivilegedRoles
                    AzureRoles              = $obj.AzureRoles
                    CAPs                    = $obj.CAPs
                    ImpactOrg               = $obj.ImpactOrg
                    Warnings                = $obj.Warnings
                }
            }
        }

        ############### App owner
        if ($($item.OwnedApplicationsDetails | Measure-Object).count -ge 1) {
            $ReportingAppOwner = foreach ($object in $($item.OwnedApplicationsDetails)) {
                [pscustomobject]@{
                    "DisplayName" = $($object.DisplayName)
                    "DisplayNameLink" = "<a href=AppRegistration_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.DisplayName)</a>"
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("Owned App Registrations`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAppOwner | Format-Table DisplayName | Out-String))
            $ReportingAppOwner = foreach ($obj in $ReportingAppOwner) {
                [pscustomobject]@{
                    UserName        = $obj.DisplayNameLink
                }
            }

        }


        ############### Group Member
        if ($($item.GroupMember | Measure-Object).count -ge 1) {
            $ReportingGroupMember = foreach ($object in $($item.GroupMember)) {
                [pscustomobject]@{
                    "DisplayName" = $($object.DisplayName)
                    "DisplayNameLink" = "<a href=Groups_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.DisplayName)</a>"
                    "SecurityEnabled" = $($object.SecurityEnabled)
                    "RoleAssignable" = $($object.RoleAssignable)
                    "ActiveRoles" = $($object.AssignedRoleCount)
                    "ActivePrivilegedRoles" = $($object.AssignedPrivilegedRoles)
                    "AzureRoles" = $($object.AzureRoles)
                    "CAPs" = $($object.CAPs)
                    "ImpactOrg" = $($object.ImpactOrg)
                    "Warnings" = $($object.Warnings)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("Member in Groups (transitive)`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine(($ReportingGroupMember | Format-Table DisplayName,SecurityEnabled,RoleAssignable,ActiveRoles,ActivePrivilegedRoles,AzureRoles,CAPs,ImpactOrg,Warnings | Out-String))
            $ReportingGroupMember  = foreach ($obj in $ReportingGroupMember) {
                [pscustomobject]@{
                    DisplayName             = $obj.DisplayNameLink
                    SecurityEnabled         = $obj.SecurityEnabled
                    RoleAssignable          = $obj.RoleAssignable
                    ActiveRoles             = $obj.ActiveRoles
                    ActivePrivilegedRoles   = $obj.ActivePrivilegedRoles
                    AzureRoles              = $obj.AzureRoles
                    CAPs                    = $obj.CAPs
                    ImpactOrg               = $obj.ImpactOrg
                    Warnings                = $obj.Warnings
                }
            }
        }

        ############### Managed Identity Credentials
        if ($($item.AppCredentialsDetails | Measure-Object).count -ge 1) {
            $ReportingCredentials = foreach ($object in $($item.AppCredentialsDetails)) {
                [pscustomobject]@{
                    "Type" = $($object.Type)
                    "DisplayName" = $($object.DisplayName)
                    "StartDateTime" = $($object.StartDateTime.ToString())
                    "EndDateTime" = $($object.EndDateTime.ToString())
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("Managed Identity Credentials`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine(($ReportingCredentials | Out-String))
        }

        ############### App Roles
        if ($($item.AppRolesDetails | Measure-Object).count -ge 1) {
            $ReportingAppRoles = foreach ($object in $($item.AppRolesDetails)) {
                [pscustomobject]@{
                    "AppRoleName" = $($object.AppRoleName)
                    "RoleEnabled" = $($object.RoleEnabled)
                    "AppRoleAssignmentType" = $($object.AppRoleAssignmentType)
                    "AppRoleMember" = $($object.AppRoleMember)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("Assigned App Roles`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAppRoles | Out-String))
        }



        ############### API permission
        if ($($item.AppApiPermission | Measure-Object).count -ge 1) {
            $ReportingAPIPermission = foreach ($object in $($item.AppApiPermission)) {
                [pscustomobject]@{
                    "API" = $($object.ApiName)
                    "Category" = $($object.ApiPermissionCategorization)
                    "Permission" = $($object.ApiPermission)
                    "Short Description" = $($object.ApiPermissionDisplayname)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine("API Permission (Application)`n")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================`n")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAPIPermission | Out-String))
        }


        $ObjectDetails = [pscustomobject]@{
            "Object Name"     = $item.DisplayName
            "Object ID"       = $item.Id
            "General Information" = $ReportingMIInfo
            "Active Entra Role Assignments" = $ReportingRoles
            "Azure IAM assignment" = $ReportingAzureRoles
            "Assigned App Roles" = $ReportingAppRoles
            "API Permission (Application)" = $ReportingAPIPermission
            "Owned App Registrations" = $ReportingAppOwner
            "Member in Groups (transitive)" = $ReportingGroupMember
            "Owner of Groups" = $ReportingGroupOwner
            "Credentials" = $ReportingCredentials
        }

        [void]$AllObjectDetailsHTML.Add($ObjectDetails)


    }

    $DetailOutputTxt = $DetailTxtBuilder.ToString()
    write-host "[*] Writing log files"
    write-host

    $mainTable = $tableOutput | select-object -Property @{Name = "DisplayName"; Expression = { $_.DisplayNameLink}},IsExplicit,GroupMembership,GroupOwnership,AppOwnership,SpOwn,EntraRoles,AzureRoles,ApiDangerous, ApiHigh, ApiMedium, ApiLow, ApiMisc,Impact,Likelihood,Risk,Warnings
    $mainTableJson  = $mainTable | ConvertTo-Json -Depth 5 -Compress

    $mainTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainTableJson + "`n" + '</script>'


    #Define header HTML
    $headerHTML = [pscustomobject]@{
        "Executed in Tenant" = "$($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)"
        "Executed at" = "$StartTimestamp "
        "Execution Warnings" = $ManagedIdentitiesScriptWarningList -join ' / '
    }

# Build Detail section as JSON for the HTML Report
$AllObjectDetailsHTML = $AllObjectDetailsHTML | ConvertTo-Json -Depth 5 -Compress
$ObjectsDetailsHEAD = @'
    <h2>Managed Identities Details</h2>
    <div style="margin: 10px 0;">
        <button id="toggle-expand">Expand All</button>
    </div>
    <div id="object-container"></div>
    <script id="object-data" type="application/json">
'@
$AllObjectDetailsHTML = $ObjectsDetailsHEAD + "`n" + $AllObjectDetailsHTML + "`n" + '</script>'

#Define header
$headerTXT = "************************************************************************************************************************
$Title Enumeration
Executed in Tenant: $($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)
Executed at: $StartTimestamp
Execution Warnings = $($ManagedIdentitiesScriptWarningList -join ' / ')
************************************************************************************************************************
"

#Define Appendix
$AppendixHeaderTXT = "

=======================================================================================================================
Appendix: Used API permission reference
=======================================================================================================================
"

    #It could be that the tenant does not contain managed identities.
    if ($ManagedIdentitiesCount -ge 1) {
        $ApiPermissionReference = $details | Select-Object -ExpandProperty AppApiPermission | select-object ApiName, ApiPermissionCategorization,ApiPermission, ApiPermissionDescription | Sort-Object -Property ApiName,ApiPermission -Unique

        # Prepare HTML output
        $headerHTML = $headerHTML | ConvertTo-Html -Fragment -PreContent "<div id=`"loadingOverlay`"><div class=`"spinner`"></div><div class=`"loading-text`">Loading data...</div></div><nav id=`"topNav`"></nav><h1>$($Title) Enumeration</h1>" -As List -PostContent "<h2>$($Title) Overview</h2>"

        #Write TXT and CSV files
        $headerTXT | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
        $tableOutput | format-table DisplayName,IsExplicit,GroupMembership,GroupOwnership,AppOwnership,SpOwn,EntraRoles,AzureRoles,ApiDangerous, ApiHigh, ApiMedium, ApiLow, ApiMisc,Impact,Likelihood,Risk,Warnings | Out-File -Width 512 "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
        $tableOutput | select-object DisplayName,IsExplicit,GroupMembership,GroupOwnership,AppOwnership,SpOwn,EntraRoles,AzureRoles,ApiDangerous, ApiHigh, ApiMedium, ApiLow, ApiMisc,Impact,Likelihood,Risk,Warnings | Export-Csv -Path "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).csv" -NoTypeInformation
        $DetailOutputTxt | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
        $AppendixHeaderTXT | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
        $ApiPermissionReference | Format-Table -AutoSize | Out-File -Width 512 "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append

        #Write HTML
        $ApiPermissionReferenceHTML += $ApiPermissionReference | ConvertTo-Html -Fragment -PreContent "<h2>Appendix: Used API Permission Reference</h2>"
        $PostContentCombined = $GLOBALJavaScript + "`n" + $ApiPermissionReferenceHTML
        $Report = ConvertTo-HTML -Body "$headerHTML $mainTableHTML" -Title "$Title Enumeration" -Head $GLOBALcss -PostContent $PostContentCombined -PreContent $AllObjectDetailsHTML
        $Report | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).html"
        write-host "[+] Details of $ManagedIdentitiesCount Managed Identity stored in output files (CSV,TXT,HTML): $outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName)"
    } else {
        write-host "[-] No managed Identities exist."
        write-host "[-] No logs have been written."
    }

    #Add information to the enumeration summary
    $IsExplicit = 0
    $AppApiDangerous = 0
    $AppApiHigh = 0
    $AppApiMedium = 0
    $AppApiLow = 0
    $AppApiMisc = 0

    foreach ($app in $AllServicePrincipal) {
        if ($app.IsExplicit) {
            $IsExplicit++
        }

        if ($app.ApiDangerous) {$AppApiDangerous++}
        if ($app.ApiHigh) {$AppApiHigh++}
        if ($app.ApiMedium) {$AppApiMedium++}
        if ($app.ApiLow) {$AppApiLow++}
        if ($app.ApiMisc) {$AppApiMisc++}
    }

    # Store in global var
    $GlobalAuditSummary.ManagedIdentities.Count = $ManagedIdentitiesCount
    $GlobalAuditSummary.ManagedIdentities.IsExplicit = $IsExplicit
    $GlobalAuditSummary.ManagedIdentities.ApiCategorization.Dangerous = $AppApiDangerous
    $GlobalAuditSummary.ManagedIdentities.ApiCategorization.High = $AppApiHigh
    $GlobalAuditSummary.ManagedIdentities.ApiCategorization.Medium = $AppApiMedium
    $GlobalAuditSummary.ManagedIdentities.ApiCategorization.Low = $AppApiLow
    $GlobalAuditSummary.ManagedIdentities.ApiCategorization.Misc = $AppApiMisc


    #Convert to Hashtable for faster searches
    $AllServicePrincipalHT = @{}
    foreach ($item in $AllServicePrincipal) {
        $AllServicePrincipalHT[$item.Id] = $item
    }

    Return $AllServicePrincipalHT

}
