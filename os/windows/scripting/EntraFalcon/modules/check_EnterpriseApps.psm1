<#
.SYNOPSIS
   Enumerate Enterprise Applications (including: API Permission, Source Tenant, Groups, Roles).

.DESCRIPTION
   This script will enumerate all Enterprise Applications (including: API Permission, Source Tenant, Groups, Roles).
   By default, MS applications are filtered out.

#>

function Invoke-CheckEnterpriseApps {

    ############################## Parameter section ########################
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$OutputFolder = ".",
        [Parameter(Mandatory=$false)][switch]$IncludeMsApps = $false,
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
                Warnings  = $MatchingGroup.Warnings
            }
        }
        Return $GroupDetails
    }

    ############################## Script section ########################

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    #Define basic variables
    $Title = "EnterpriseApps"
    $ProgressCounter = 0
    $Inactive = $false
    $EnterpriseAppsScriptWarningList = @()
    $ApiAppDisplayNameCache = @{}
    $AppRegistrations = @{}
    $AppLastSignIns = @{}
    $AllServicePrincipal = [System.Collections.ArrayList]::new()
    $AllObjectDetailsHTML = [System.Collections.ArrayList]::new()
    $global:GLOBALUserAppRoles = @{}
    $SPImpactScore = @{
        "Base"                      = 1
        "APIDangerous"              = 800
        "APIHigh"                   = 400
        "APIMedium"                 = 100
        "APILow"                    = 50
        "ApiMisc"                   = 20
        "APIDelegatedDangerous"     = 100
        "APIDelegatedHigh"          = 80
        "APIDelegatedMedium"        = 60
        "APIDelegatedLow"           = 20
        "ApiDelegatedMisc"          = 20
        "AppRoleRequired"           = 10
        "AppRole"                   = 2
    }

    $SPLikelihoodScore = @{
        "SpWithCredentials"         = 5
        "ForeignApp"                = 30
        "InternApp"                 = 5
        "Owners"          	        = 5
	    "UnknownAppLock"            = 1
        "NoAppLock"                 = 2
    }

    ########################################## SECTION: DATACOLLECTION ##########################################
    # Get Enterprise Apps
    write-host "[*] Get Enterprise Apps"
    $QueryParameters = @{
        '$filter' = "ServicePrincipalType eq 'Application'"
        '$select' = "Id,DisplayName,PublisherName,accountEnabled,AppRoles,AppId,servicePrincipalType,signInAudience,AppOwnerOrganizationId,PasswordCredentials,KeyCredentials,AppRoleAssignmentRequired"
        '$top' = "999"
    }
    $EnterpriseApps = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/servicePrincipals' -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)


    $EnterpriseAppsCount = $($EnterpriseApps.count)
    write-host "[+] Got $EnterpriseAppsCount Enterprise Applications "

    # Check if Azure IAM role were checked
    if (-not ($GLOBALAzurePsChecks)) {
        $EnterpriseAppsScriptWarningList += "Group Azure IAM assignments were not assessed"
    }

    # Get all App API Permissions (needed to resolve the ID to a human readable name)
    # It is required to do this on all MS apps to get the permissions of the custom apps
    write-host "[*] Get all API permissions"
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

    # Filter out MS enterprise apps
    if (!$IncludeMsApps) {
        $EnterpriseApps = $EnterpriseApps | where-object {-not($GLOBALMsTenantIds -contains $_.AppOwnerOrganizationId) -and $_.DisplayName -ne "O365 LinkedIn Connection" -and $_.DisplayName -ne "P2P Server"} | select-object Id,DisplayName,accountEnabled,PublisherName,AppRoles,AppId,servicePrincipalType,signInAudience,AppOwnerOrganizationId,PasswordCredentials,KeyCredentials,AppRoleAssignmentRequired
        $EnterpriseAppsCount = $($EnterpriseApps.count)
        write-host "[i] Filtered out Microsoft Applications. $EnterpriseAppsCount left (use -IncludeMsApps to include them)"
    } else {
        #Add information to the enumeration summary
        $GlobalAuditSummary.EnterpriseApps.IncludeMsApps = $true
    }

    #Abort if no apps are present
    if (@($EnterpriseApps).count -eq 0) {
        $AllServicePrincipalHT = @{}
        Return $AllServicePrincipalHT
    }

    write-host "[*] Get App Registrations for lookups"
    $QueryParameters = @{
        '$select' = "id,AppId,ServicePrincipalLockConfiguration"
    }
    $AllAppRegistrations = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/applications' -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    foreach ($app in $AllAppRegistrations) {
        $AppRegistrations[$app.AppId] = @{
            id = $app.id
            ServicePrincipalLockConfiguration = $app.ServicePrincipalLockConfiguration
        }
    }

    write-host "[*] Get last app last sign-in dates"
    $AppLastSignInsRaw = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/reports/servicePrincipalSignInActivities" -BetaAPI -QueryParameters @{ '$top' = "999" } -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    foreach ($app in $AppLastSignInsRaw) {
        $AppLastSignIns[$app.appId] = @{
            id = $app.appId
            lastSignIn = if ($app.lastSignInActivity.lastSignInDateTime) {$app.lastSignInActivity.lastSignInDateTime} else { "-" }
            lastSignInDays = if ($app.lastSignInActivity.lastSignInDateTime) { (New-TimeSpan -Start $app.lastSignInActivity.lastSignInDateTime).Days } else { "-" }

            lastSignInAppAsClient = if ($app.applicationAuthenticationClientSignInActivity.lastSignInDateTime) {$app.applicationAuthenticationClientSignInActivity.lastSignInDateTime} else { "-" }
            lastSignInAppAsClientDays = if ($app.applicationAuthenticationClientSignInActivity.lastSignInDateTime) { (New-TimeSpan -Start $app.applicationAuthenticationClientSignInActivity.lastSignInDateTime).Days } else { "-" }

            lastSignInAppAsResource = if ($app.applicationAuthenticationResourceSignInActivity.lastSignInDateTime) {$app.applicationAuthenticationResourceSignInActivity.lastSignInDateTime} else { "-" }
            lastSignInAppAsResourceDays = if ($app.applicationAuthenticationResourceSignInActivity.lastSignInDateTime) { (New-TimeSpan -Start $app.applicationAuthenticationResourceSignInActivity.lastSignInDateTime).Days } else { "-" }

            lastSignInDelegatedAsClient = if ($app.delegatedClientSignInActivity.lastSignInDateTime) {$app.delegatedClientSignInActivity.lastSignInDateTime} else { "-" }
            lastSignInDelegatedAsClientDays = if ($app.delegatedClientSignInActivity.lastSignInDateTime) { (New-TimeSpan -Start $app.delegatedClientSignInActivity.lastSignInDateTime).Days } else { "-" }

            lastSignInDelegatedAsResource = if ($app.delegatedResourceSignInActivity.lastSignInDateTime) {$app.delegatedResourceSignInActivity.lastSignInDateTime} else { "-" }
            lastSignInDelegatedAsResourceDays = if ($app.delegatedResourceSignInActivity.lastSignInDateTime) { (New-TimeSpan -Start $app.delegatedResourceSignInActivity.lastSignInDateTime).Days } else { "-" }
        }
    }

    Write-Host "[*] Get all applications API permissions assignments"
    $Requests = @()
    $EnterpriseApps | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    =   "/servicePrincipals/$($_.id)/appRoleAssignments?`$select=AppRoleId"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI  -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $AppAssignmentsRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $AppAssignmentsRaw[$item.id] = $item.response.value
        }
    }

    Write-Host "[*] Get all delegate API permissions"
    $Requests = @()
    $EnterpriseApps | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    =   "/servicePrincipals/$($_.id)/oauth2PermissionGrants?`$select=ResourceId,Scope,ConsentType,PrincipalId"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI  -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $DelegatedPermissionRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $DelegatedPermissionRaw[$item.id] = $item.response.value
        }
    }

    Write-Host "[*] Get all applications group memberships"
    $Requests = @()
    $EnterpriseApps | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    =   "/servicePrincipals/$($_.id)/transitiveMemberOf/microsoft.graph.group?`$select=Id,displayName,visibility,securityEnabled,groupTypes,isAssignableToRole"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI  -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $GroupMemberRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $GroupMemberRaw[$item.id] = $item.response.value
        }
    }

    Write-Host "[*] Get all applications objects ownerships"
    $Requests = @()
    $EnterpriseApps | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    =   "/servicePrincipals/$($_.id)/ownedObjects"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI  -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $OwnedObjectsRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $OwnedObjectsRaw[$item.id] = $item.response.value
        }
    }

    Write-Host "[*] Get all owners"
    $Requests = @()
    $EnterpriseApps | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    =   "/servicePrincipals/$($_.id)/owners"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI  -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $OwnersRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $OwnersRaw[$item.id] = $item.response.value
        }
    }

    Write-Host "[*] Get all app roles assignments"
    $Requests = @()
    $EnterpriseApps | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    =   "/servicePrincipals/$($_.id)/appRoleAssignedTo"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI  -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $AppRolesAssignedToRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $AppRolesAssignedToRaw[$item.id] = $item.response.value
        }
    }

    ########################################## SECTION: Enterprise App Processing ##########################################




    #Enumerate all AppRoles configured (only of the apps in scope)
    $AppRoles = [System.Collections.ArrayList]::new()

    foreach ($app in $EnterpriseApps) {
        if (-not $AppRolesAssignedToRaw.ContainsKey($app.Id)) { continue }

        $userRoles = $app.AppRoles | Where-Object { $_.AllowedMemberTypes -contains 'User' }

        foreach ($assignment in $AppRolesAssignedToRaw[$app.Id]) {

            # Handle default access assignments
            if ($assignment.appRoleId -eq '00000000-0000-0000-0000-000000000000') {
                [void]$AppRoles.Add([PSCustomObject]@{
                    AppID                         = $app.Id
                    AppName                       = $app.DisplayName
                    AppRoleId                     = $assignment.appRoleId
                    AppRoleAssignmentDisplayName  = $assignment.PrincipalDisplayName
                    AppRoleAssignmentPrincipalId  = $assignment.PrincipalId
                    AppRoleAssignmentType         = $assignment.PrincipalType
                    AppRoleValue                  = $null
                    AppRoleDisplayName            = "Default Access"
                    AppRoleDescription            = "Default app role"
                    AppRoleEnabled                = $false
                })
                continue
            }

            # Handle explicitly assigned roles
            $matchedRole = $userRoles | Where-Object { $_.Id -eq $assignment.appRoleId }

            if ($matchedRole) {
                foreach ($role in $matchedRole) {
                    [void]$AppRoles.Add([PSCustomObject]@{
                        AppID                         = $app.Id
                        AppName                       = $app.DisplayName
                        AppRoleId                     = $role.Id
                        AppRoleAssignmentDisplayName  = $assignment.PrincipalDisplayName
                        AppRoleAssignmentPrincipalId  = $assignment.PrincipalId
                        AppRoleAssignmentType         = $assignment.PrincipalType
                        AppRoleValue                  = $role.Value
                        AppRoleDisplayName            = $role.DisplayName
                        AppRoleDescription            = $role.Description
                        AppRoleEnabled                = $role.IsEnabled
                    })
                }
            } else {
                Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "No matching AppRole for ID $($assignment.appRoleId) in App $($app.DisplayName)"
            }
        }
    }

    # Add AppRoles assigned to users to a global var to use it in the check_user script
    $filteredAppRoles = $AppRoles | Where-Object { $_.AppRoleAssignmentType -eq "User" }

    # Loop through each filtered object
    foreach ($role in $filteredAppRoles) {
        $key = $role.AppRoleAssignmentPrincipalId
        $value = [PSCustomObject]@{
            AppRoleDisplayName  = $role.AppRoleDisplayName
            AppRoleDescription  = $role.AppRoleDescription
            AppRoleEnabled      = $role.AppRoleEnabled
            AppID               = $role.AppID
            AppName             = $role.AppName
        }

        # Check if the key already exists
        if ($GLOBALUserAppRoles.ContainsKey($key)) {
            # Append to the existing array
            $GLOBALUserAppRoles[$key] += $value
        } else {
            # Create a new array for this key
            $GLOBALUserAppRoles[$key] = @($value)
        }
    }

    #Calc dynamic update interval
    $StatusUpdateInterval = [Math]::Max([Math]::Floor($EnterpriseAppsCount / 10), 1)
    if ($EnterpriseAppsCount -gt 0 -and $StatusUpdateInterval -gt 1) {
        Write-Host "[*] Status: Processing app 1 of $EnterpriseAppsCount (updates every $StatusUpdateInterval apps)..."
    }

    #Loop through each enterprise app, retrieve additional info, and store it in a custom object
    foreach ($item in $EnterpriseApps) {
        $ProgressCounter++
        $ImpactScore = $SPImpactScore["Base"]
        $LikelihoodScore = 0
        $warnings = @()
        $WarningsHighPermission = $null
        $WarningsDangerousPermission = $null
        $WarningsMediumPermission = $null
        $Owners = $null
        $AppCredentials = @()
        $OwnerUserDetails = @()
        $OwnerSPDetails = @()
        $AppRegObjectId = ""


        # Display status based on the objects numbers (slightly improves performance)
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $EnterpriseAppsCount) {
            Write-Host "[*] Status: Processing app $ProgressCounter of $EnterpriseAppsCount..."
        }

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

        #Get the application's API permission
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

        #Check the assigned App roles for each app
        $MatchingAppRoles = @()
        # Loop through each role in $Approles and compare with $item.id
        foreach ($role in $Approles) {
            if ($role.AppID -eq $item.id) {

                #Shorten description if it is the same as the display name
                if ($role.AppRoleAssignmentDisplayName -eq $role.AppRoleDescription ) {
                    $description = "-"
                } else {
                    $description = $role.AppRoleDescription
                }

                # Create a new custom object with the relevant properties
                $newRole = [pscustomobject]@{
                    Type = "AppRole"
                    AppRoleName = $role.AppRoleDisplayName
                    AppRoleMember  = $role.AppRoleAssignmentDisplayName
                    AppRoleMemberId  = $role.AppRoleAssignmentPrincipalId
                    RoleValue     = $role.AppRoleValue
                    RoleEnabled   = $role.AppRoleEnabled
                    AppRoleValue = $role.AppRoleValue
                    AppRoleAssignmentType = $role.AppRoleAssignmentType
                    AppRoleDescription = $description
                }

                # Add the new object to the array
                $MatchingAppRoles += $newRole
            }
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

        #Get the Delegated permissions
        $DelegatedPermission = [System.Collections.ArrayList]::new()
        if ($DelegatedPermissionRaw.ContainsKey($item.Id)) {
            foreach ($DelegatedPermissionAssignment in $DelegatedPermissionRaw[$item.Id]) {
                [void]$DelegatedPermission.Add(
                    [PSCustomObject]@{
                        ResourceId = $DelegatedPermissionAssignment.ResourceId
                        Scope = $DelegatedPermissionAssignment.Scope
                        ConsentType = $DelegatedPermissionAssignment.ConsentType
                        PrincipalId = $DelegatedPermissionAssignment.PrincipalId
                    }
                )
            }
        }

        $DelegatedPermissionDetails = foreach ($permission in $DelegatedPermission) {

            # Check if DisplayName for the ResourceId is already cached
            if (-not $ApiAppDisplayNameCache.ContainsKey($permission.ResourceId)) {

                # Retrieve and cache the DisplayName if not cached
                $QueryParameters = @{
                    '$select' = "DisplayName"
                }
                #Set odata.metadata=none to avoid having metadata in the response
                $headers = @{
                    'Accept' = 'application/json;odata.metadata=none'
                }
                $ApiAppDisplayNameCache[$permission.ResourceId] = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/servicePrincipals/$($permission.ResourceId)" -QueryParameters $QueryParameters -AdditionalHeaders $headers -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
            }

            # Split the Scope field by spaces to get individual permissions. Ignores whitespece at the start of the string
            $scopes = $permission.Scope.Trim() -split " "

            if ($permission.ConsentType -eq "Principal") {
                $principal = $permission.PrincipalId
            } else {
                $principal = "-"
            }
            # Create a custom object for each scope with ResourceId, ConsentType, Scope, and DisplayName
            foreach ($scope in $scopes) {
                [pscustomobject]@{
                    ResourceId  = $permission.ResourceId
                    ConsentType = $permission.ConsentType
                    Scope       = $scope
                    APIName = $ApiAppDisplayNameCache[$permission.ResourceId].displayname  # Get the cached DisplayName
                    Principal = $principal
                    ApiPermissionCategorization = Get-APIPermissionCategory -InputPermission $scope -PermissionType "delegated"
                }
            }
        }


        #Store unique permission to show in table
        $DelegatedPermissionDetailsUnique = ($DelegatedPermissionDetails | Select-Object -ExpandProperty Scope | Sort-Object -Unique).count


        # Sort by Principal, then by custom Categorization order
        $DelegatedPermissionDetails = $DelegatedPermissionDetails | Sort-Object Principal, @{ Expression = { $categorizationOrder[$_.ApiPermissionCategorization] }; Ascending = $true }

        #Count by severity
        $ApiPermissionSeverity = @('Dangerous', 'High', 'Medium', 'Low', 'Uncategorized')
        $DelegateApiPermssionCount = @{}
        foreach ($severity in $ApiPermissionSeverity) {
            $count = ($DelegatedPermissionDetails | Where-Object { $_.ApiPermissionCategorization -eq $severity } | Measure-Object ).Count
            $DelegateApiPermssionCount[$severity] = $count
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

        #Process Last sign-in date for each App
        if ($AppLastSignIns.ContainsKey($item.AppId)) {
            $AppsignInData = $AppLastSignIns[$item.AppId]
        } else {
            $AppsignInData = $Null
        }

    ########################################## SECTION: RISK RATING AND WARNINGS ##########################################
        $AppCredentialsCount = ($AppCredentials | Measure-Object).count

        if ($AppCredentialsCount -ge 1) {
            $Warnings += "SP with credentials!"
            $LikelihoodScore += $SPLikelihoodScore["SpWithCredentials"]
        }

        #Check if it is an SP of a foreign tenant
        if ($item.AppOwnerOrganizationId -eq $($CurrentTenant).id) {
            $ForeignTenant = $false

            #If not set corresponding SP object ID
            $AppRegObjectId = $AppRegistrations[$($item.AppId)].id

        } else {
            $ForeignTenant = $true
        }

        if ($AzureRoleCount -ge 1) {
            #Use function to get the impact score and warning message for assigned Azure roles
            $AzureRolesProcessedDetails = Invoke-AzureRoleProcessing -RoleDetails $azureRoleDetails
            $Warnings += $AzureRolesProcessedDetails.Warning
            $ImpactScore += $AzureRolesProcessedDetails.ImpactScore
        }

        #Get owners of the sp
        $OwnerUserDetails  	= [System.Collections.ArrayList]::new()
        $OwnerSPDetails  	= [System.Collections.ArrayList]::new()
        if ($OwnersRaw.ContainsKey($item.Id)) {
            foreach ($OwnedObject in $OwnersRaw[$item.Id]) {
                switch ($OwnedObject.'@odata.type') {

                    '#microsoft.graph.user' {
                        #If not synced set to false for nicer output
                        if ($null -eq $OwnedObject.onPremisesSyncEnabled) {
                            $OwnedObject.onPremisesSyncEnabled = $false
                        }
                        [void]$OwnerUserDetails.Add(
                            [PSCustomObject]@{
                                Id             = $OwnedObject.Id
                                UPN            = $OwnedObject.userPrincipalName
                                Enabled        = $OwnedObject.accountEnabled
                                Type           = $OwnedObject.userType
                                Department     = $OwnedObject.department
                                JobTitle       = $OwnedObject.jobTitle
                                OnPremSync     = $OwnedObject.onPremisesSyncEnabled
                                AssignmentType = 'Active'
                            }
                        )
                    }

                    '#microsoft.graph.servicePrincipal' {
                        [void]$OwnerSPDetails.Add(
                            [PSCustomObject]@{
                                Id                     = $OwnedObject.Id
                                displayName            = $OwnedObject.displayName
                                Enabled                = $OwnedObject.accountEnabled
                                appOwnerOrganizationId = $OwnedObject.appOwnerOrganizationId
                                publisherName          = $OwnedObject.publisherName
                                servicePrincipalType   = $OwnedObject.servicePrincipalType
                            }
                        )
                    }
                }
            }
        }

        $OwnersCount = $OwnerUserDetails.count + $OwnerSPDetails.count
        #Check owners of the SP.
        if ($OwnersCount -ge 1) {

            #Check if SP is protected by app instance locking
            #Cannot be checked for foreign apps
            if ($ForeignTenant) {
                $LikelihoodScore += $SPLikelihoodScore["UnknownAppLock"]
                $Warnings += "SP with owner (unknown AppLock)!"
            } else {
                $AppLockConfiguration = $AppRegistrations[$($item.AppId)].ServicePrincipalLockConfiguration

                #App instance property lock can be completely disabled or more granular
                if ($AppLockConfiguration.IsEnabled -ne $true -or ($AppLockConfiguration.AllProperties -ne $true -and $AppLockConfiguration.credentialsWithUsageVerify -ne $true)) {
                    $LikelihoodScore += $SPLikelihoodScore["NoAppLock"]
                    $Warnings += "SP with owner and no AppLock!"
                } else {
                    $Warnings += "SP with owner but app protected by AppLock!"
                }
            }
        }

        #Increase likelihood for each owner (user) SP ownership is calculated in the post-processing part
        $LikelihoodScore = $OwnerUserDetails.count * $SPLikelihoodScore["Owners"]

        #Increase impact for each App role
        $AppRolesCount = ($MatchingAppRoles | Measure-Object).count
        if ($AppRolesCount -ge 1) {
            $ImpactScore += $AppRolesCount * $SPImpactScore["AppRole"]
        }

        #Increase impact if App Roles needs to be assigned
        if ($item.AppRoleAssignmentRequired) {
            $ImpactScore += $SPImpactScore["AppRoleRequired"]
        }

        #If SP owns App Registration
        if ($OwnedApplicationsCount -ge 1) {
            $Warnings += "SP owns $OwnedApplicationsCount App Registrations!"
        }

        #If SP owns another SP
        if ($OwnedSPCount -ge 1) {
            $Warnings += "SP owns $OwnedSPCount Enterprise Applications!"
        }


        #Check if it is one of the MS default SPs
        if ($GLOBALMsTenantIds -contains $item.AppOwnerOrganizationId -or $item.DisplayName -eq "O365 LinkedIn Connection" -and $_.DisplayName -ne "P2P Server") {
            $DefaultMS = $true
        } else {
            $DefaultMS = $false
        }


        #Process group memberships
        if (($GroupMember | Measure-Object).count -ge 1) {
            $TotalAssignedRoleCount = 0
            $TotalAssignedPrivilegedRoles = 0
            $TotalInheritedHighValue = 0
            $AzureRoleValue = 0
            $TotalAzureRoles = 0

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

        #Process Application API permission
        if (($AppApiPermission | Measure-Object).Count -ge 1) {
            foreach ($object in $AppApiPermission) {
                switch($object.ApiPermissionCategorization) {
                    "Dangerous" {$ImpactScore += $SPImpactScore["APIDangerous"]; $WarningsDangerousPermission = $true ; Break}
                    "High" {$ImpactScore += $SPImpactScore["APIHigh"]; $WarningsHighPermission = $true; Break}
                    "Medium" {$ImpactScore += $SPImpactScore["APIMedium"]; if ($ForeignTenant) { $WarningsMediumPermission = $true }; Break}
                    "Low" {$ImpactScore += $SPImpactScore["APILow"]; Break}
                    "Uncategorized" {$ImpactScore += $SPImpactScore["ApiMisc"]; Break}
                }
            }
        }

        #Mark foreign non-default apps as risky
        if ($DefaultMS -eq $false -and $ForeignTenant -eq $true) {
            $LikelihoodScore += $SPLikelihoodScore["ForeignApp"]
            if ($ImpactScore -gt 0) {
                $Warnings += "Foreign with permission"
            }
        } elseif ($DefaultMS -eq $false -and $ForeignTenant -eq $false) {
            $LikelihoodScore += $SPLikelihoodScore["InternApp"]
        }

        # Build the warning parts dynamically
        [string[]]$severities = @()
        if ($WarningsDangerousPermission) { $severities += "dangerous" }
        if ($WarningsHighPermission)      { $severities += "high" }
        if ($WarningsMediumPermission)    { $severities += "medium" }

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

        #Check if app is inactive
        if ($AppsignInData.lastSignInDays -ge 180 -or $AppsignInData.lastSignInDays -eq "-" -or $Null -eq $AppsignInData) {
            $Inactive = $true
        } else {
            $Inactive = $false
        }

        #Process Delegated API permission. Only increase the score once (independet of how many principal or how many of each category are assigned)
        if ($DelegatedPermissionDetailsUnique -ge 1) {

            if ($DelegateApiPermssionCount.Dangerous -ge 1) {
                $ImpactScore += $SPImpactScore["APIDelegatedDangerous"]
                $WarningsDangerousDelegatedPermission = $true
            } else {
                $WarningsDangerousDelegatedPermission = $false
            }

            if ($DelegateApiPermssionCount.High -ge 1) {
                $ImpactScore += $SPImpactScore["APIDelegatedHigh"]
                $WarningsHighDelegatedPermission = $true
            }else {
                $WarningsHighDelegatedPermission = $false
            }

            if ($DelegateApiPermssionCount.Medium -ge 1) {
                $ImpactScore += $SPImpactScore["APIDelegatedMedium"]
                #Show warnings only for foreign apps
                if ($ForeignTenant) {
                    $WarningsMediumDelegatedPermission = $true
                }
            } else {
                $WarningsMediumDelegatedPermission = $false
            }

            if ($DelegateApiPermssionCount.Low -ge 1) {
                $ImpactScore += $SPImpactScore["APIDelegatedLow"]
            }
            if ($DelegateApiPermssionCount.Uncategorized -ge 1) {
                $ImpactScore += $SPImpactScore["ApiDelegatedMisc"]
            }

            # Build the warning parts dynamically
            [string[]]$severities = @()
            if ($WarningsDangerousDelegatedPermission) { $severities += "dangerous" }
            if ($WarningsHighDelegatedPermission)      { $severities += "high" }
            if ($WarningsMediumDelegatedPermission)    { $severities += "medium" }
            $severities = $severities | Select-Object -Unique

            # Generate joined warning for delegate permissions
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
                $Warnings += "Known $joined delegated API permission$plural!"
            }
        }

        #Format warning messages
        $Warnings = if ($null -ne $Warnings) {
            $Warnings -join ' / '
        } else {
            ''
        }

        # if
        if ($AppsignInData.lastSignInDays) {
            $LastSignInDays = $AppsignInData.lastSignInDays
        } else {
            $LastSignInDays = "?"
        }

        #Write custom object
        $SPInfo = [PSCustomObject]@{
            Id = $item.Id
            DisplayName = $item.DisplayName
            Enabled = $item.accountEnabled
            DisplayNameLink = "<a href=#$($item.Id)>$($item.DisplayName)</a>"
            PublisherName = $item.PublisherName
            AppId = $item.AppId
            ServicePrincipalType = $item.servicePrincipalType
            SignInAudience = $item.signInAudience
            GrpMem = ($GroupMember | Measure-Object).count
            EntraRoles = ($AppEntraRoles | Measure-Object).count
            PermissionCount = ($AppAssignments | Measure-Object).count
            GrpOwn = ($OwnedGroups | Measure-Object).count
            AppOwn = $OwnedApplicationsCount
            OwnedApplicationsDetails = $OwnedApplications
            SpOwn = $OwnedSPCount
            OwnedSPDetails = $OwnedSP
            GroupMember = $GroupMember
            AppOwnerOrganizationId = $item.AppOwnerOrganizationId
            EntraRoleDetails = $AppEntraRoles
            GroupOwner = $OwnedGroups
            AppPermission = $AppAssignments
            Foreign = $ForeignTenant
            DefaultMS = $DefaultMS
            AzureRoles = $AzureRoleCount
            Inactive = $Inactive
            LastSignInDays = $LastSignInDays
            AppsignInData = $AppsignInData
            AzureRoleDetails = $AzureRoleDetails
            Owners = $OwnersCount
            OwnerUserDetails = $OwnerUserDetails
            OwnerSPDetails = $OwnerSPDetails
            AppRegObjectId = $AppRegObjectId
            AppRoleRequired = $item.AppRoleAssignmentRequired
            Credentials = $AppCredentialsCount
            AppCredentialsDetails = $AppCredentials
            AppApiPermission = $AppApiPermission
            AppRoles = ($MatchingAppRoles | Measure-Object).count
            AppRolesDetails = $MatchingAppRoles
            ApiDelegated = $DelegatedPermissionDetailsUnique
            ApiDelegatedDetails  = $DelegatedPermissionDetails
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
    write-host "[*] Post-processing SP ownership relation with other apps"

    #Process indirect App ownerships (SP->AppReg->SP) (take over Impact, inherit likelihood)
    $SPOwningApps = $AllServicePrincipal | Where-Object { $_.AppOwn -ge 1 }
    # For each object which owns an App registration
    foreach ($SpObject in $SPOwningApps) {

        # For each owned App Registration
        foreach ($AppRegistration in $SpObject.OwnedApplicationsDetails) {

            #For each corresponding SP object of the App Registration
            foreach ($OwnedSP in $AllServicePrincipal | Where-Object { $_.AppId -eq $AppRegistration.AppId }) {

                # Increment/Recalculate RiskScore of the SP objects which is indirectly owned (SP->AppReg->SP*)
                $OwnedSP.Likelihood += [math]::Round($SpObject.Likelihood)
                $OwnedSP.Risk = [math]::Round(($OwnedSP.Impact * $OwnedSP.Likelihood))

                # Append the Message to Warnings of the SP objects which is indirectly owned (SP->AppReg->SP*)
                $warningMessage = "AppReg. owned by other SP"
                if ($OwnedSP.Warnings -and $OwnedSP.Warnings -notmatch $warningMessage) {
                    $OwnedSP.Warnings += " / $warningMessage"
                } else {
                    $OwnedSP.Warnings = $warningMessage
                }

                # Increment/Recalculate impact score of the SP which owns the other SP with it's impact score (SP*->AppReg->SP*)
                $SpObject.Impact += [math]::Round($OwnedSP.Impact)
                $SpObject.Risk = [math]::Round(($SpObject.Impact * $SpObject.Likelihood))

            }
        }
    }

    #Process direct App ownerships (SP->SP) (take over Impact, inherit likelihood)
    $SPOwningSPs = $AllServicePrincipal | Where-Object { $_.SpOwn -ge 1 }
    #For each object which owns an App registration
    foreach ($SpOwnerObject in $SPOwningSPs) {

        # For each owned App Registration
        foreach ($OwnedSPObject in $SpOwnerObject.OwnedSPDetails) {

            # Get the details of the owned SP by looping over matching objects
            foreach ($OwnedSPObjectDetails in $AllServicePrincipal | Where-Object { $_.id -eq $OwnedSPObject.id }) {

                # Increment/Recalculate RiskScore of the SP objects which is indirectly owned (SP->SP*)
                $OwnedSPObjectDetails.Likelihood += [math]::Round($SpOwnerObject.Likelihood)
                $OwnedSPObjectDetails.Risk = [math]::Round(($OwnedSPObjectDetails.Impact * $OwnedSPObjectDetails.Likelihood))

                # Append the Message to Warnings of the SP objects which is indirectly owned (SP->SP*)
                $warningMessage = "SP owned by another SP"
                if ($OwnedSPObjectDetails.Warnings -and $OwnedSPObjectDetails.Warnings -notmatch $warningMessage) {
                    $OwnedSPObjectDetails.Warnings += " / $warningMessage"
                } else {
                    $OwnedSPObjectDetails.Warnings = $warningMessage
                }

                # Increment/Recalculate Impactscore of the SP which owns the other SP with it's impact score (SP*->SP)
                $SpOwnerObject.Impact += [math]::Round($OwnedSPObjectDetails.Impact)
                $SpOwnerObject.Risk = [math]::Round(($SpOwnerObject.Impact * $SpOwnerObject.Likelihood))
                $OwnedSPObject | Add-Member -NotePropertyName Impact -NotePropertyValue $OwnedSPObjectDetails.Impact
                $OwnedSPObject | Add-Member -NotePropertyName Foreign -NotePropertyValue $OwnedSPObjectDetails.Foreign
            }
        }
    }

    ########################################## SECTION: OUTPUT DEFINITION ##########################################
    write-host "[*] Generating reports"

    #Define output of the main table
    $tableOutput = $AllServicePrincipal | Sort-Object -Property risk -Descending | select-object DisplayName,DisplayNameLink,AppRoleRequired,PublisherName,DefaultMS,Foreign,Enabled,Inactive,LastSignInDays,AppRoles,GrpMem,GrpOwn,AppOwn,SpOwn,EntraRoles,Owners,Credentials,AzureRoles,ApiDangerous, ApiHigh, ApiMedium, ApiLow, ApiMisc,ApiDelegated,Impact,Likelihood,Risk,Warnings

    #Define the apps to be displayed in detail and sort them by risk score
    $details = $AllServicePrincipal | Sort-Object Risk -Descending

    #Define stringbuilder to avoid performance impact
    $DetailTxtBuilder = [System.Text.StringBuilder]::new()

    #Enum the details for the apps in scope
    foreach ($item in $details) {

        $ReportingEntAppInfo = @()
        $ReportingRoles = @()
        $ReportingAzureRoles = @()
        $ReportingGroupOwner = @()
        $ReportingAppOwner = @()
        $ReportingSPOwner = @()
        $ReportingGroupMember = @()
        $ReportingCredentials = @()
        $ReportingAppRoles = @()
        $ReportingAppOwnersUser = @()
        $ReportingAppOwnersSP = @()
        $ReportingAPIPermission = @()
        $ReportingDelegatedApiPermission = @()

        [void]$DetailTxtBuilder.AppendLine("############################################################################################################################################")

        ############### HEADER
        $ReportingEntAppInfo = [pscustomobject]@{
            "App Name" = $($item.DisplayName)
            "Publisher Name" = $($item.PublisherName)
            "Publisher TenantId" = $($item.AppOwnerOrganizationId)
            "Enabled" = $($item.Enabled)
            "App Client-ID" = $($item.AppId)
            "App Object-ID" = $($item.Id)
            "MS Default" = $($item.DefaultMS)
            "Foreign" = $($item.Foreign)
            "Require AppRole" = $($item.AppRoleRequired)
            "RiskScore" = $($item.Risk)
        }
        #If it is not a foreign app, add the link to the appreg
        if (-not $item.Foreign) {
            $ReportingEntAppInfo | Add-Member -NotePropertyName AppRegistration -NotePropertyValue "<a href=AppRegistration_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($item.AppRegObjectId)>$($item.DisplayName)</a>"
        }

        #Build dynamic TXT report property list
        $TxtReportProps = @("App Name","Publisher Name","Publisher TenantId","Enabled", "App Client-ID","App Object-ID","MS Default","Foreign","Require AppRole","RiskScore")

        if ($item.Warnings -ne '') {
            $ReportingEntAppInfo | Add-Member -NotePropertyName Warnings -NotePropertyValue $item.Warnings
            $TxtReportProps += "Warnings"
        }

        [void]$DetailTxtBuilder.AppendLine(($ReportingEntAppInfo| Select-Object $TxtReportProps | Out-String))

        ############### Last Sing-Ins
        $lastSignIn = if ($($item.AppsignInData.lastSignIn) -and $($item.AppsignInData.lastSignIn) -ne "-") {"$($item.AppsignInData.lastSignIn) ($($item.AppsignInData.lastSignInDays) days ago)"} else {"-"}
        $lastSignInAppAsClient = if ($($item.AppsignInData.lastSignInAppAsClient) -and $($item.AppsignInData.lastSignInAppAsClient) -ne "-") {"$($item.AppsignInData.lastSignInAppAsClient) ($($item.AppsignInData.lastSignInAppAsClientDays) days ago)"} else {"-"}
        $lastSignInAppAsResource = if ($($item.AppsignInData.lastSignInAppAsResource) -and $($item.AppsignInData.lastSignInAppAsResource) -ne "-") {"$($item.AppsignInData.lastSignInAppAsResource) ($($item.AppsignInData.lastSignInAppAsResourceDays) days ago)"} else {"-"}
        $lastSignInDelegatedAsClient = if ($($item.AppsignInData.lastSignInDelegatedAsClient) -and $($item.AppsignInData.lastSignInDelegatedAsClient) -ne "-") {"$($item.AppsignInData.lastSignInDelegatedAsClient) ($($item.AppsignInData.lastSignInDelegatedAsClientDays) days ago)"} else {"-"}
        $lastSignInDelegatedAsResource = if ($($item.AppsignInData.lastSignInDelegatedAsResource) -and $($item.AppsignInData.lastSignInDelegatedAsResource) -ne "-") {"$($item.AppsignInData.lastSignInDelegatedAsResource) ($($item.AppsignInData.lastSignInDelegatedAsResourceDays) days ago)"} else {"-"}
        $ReportingLastSignIns = [pscustomobject]@{
            "Last sign-in overall" = $lastSignIn
            "Last sign-in as application (client)" = $lastSignInAppAsClient
            "Last sign-in as application (resource)" = $lastSignInAppAsResource
            "Last sign-in delegated (client)" = $lastSignInDelegatedAsClient
            "Last sign-in delegated (resource)" = $lastSignInDelegatedAsResource
        }
        [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
        [void]$DetailTxtBuilder.AppendLine("Last Sign-Ins Details")
        [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
        [void]$DetailTxtBuilder.AppendLine("Last sign-in overall: $lastSignIn")
        [void]$DetailTxtBuilder.AppendLine("Last sign-in as application (client): $lastSignInAppAsClient")
        [void]$DetailTxtBuilder.AppendLine("Last sign-in as application (resource): $lastSignInAppAsResource")
        [void]$DetailTxtBuilder.AppendLine("Last sign-in delegated (client): $lastSignInDelegatedAsClient")
        [void]$DetailTxtBuilder.AppendLine("Last sign-in delegated (resource): $lastSignInDelegatedAsResource ")


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

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Active Entra Role Assignments")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
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

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Azure IAM assignments")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
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

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Owner of Groups")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingGroupOwner | Format-Table DisplayName,SecurityEnabled,RoleAssignable,ActiveRoles,ActivePrivilegedRoles,AzureRoles,CAPs,ImpactOrg,Warnings | Out-String))
            $ReportingGroupOwner  = foreach ($obj in $ReportingGroupOwner) {
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

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Owned App Registrations")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAppOwner | Format-Table DisplayName | Out-String))
            $ReportingAppOwner = foreach ($obj in $ReportingAppOwner) {
                [pscustomobject]@{
                    DisplayName        = $obj.DisplayNameLink
                }
            }
        }

        ############### SP owner
        if ($($item.OwnedSPDetails | Measure-Object).count -ge 1) {
            $ReportingSPOwner = foreach ($object in $($item.OwnedSPDetails)) {
                [pscustomobject]@{
                    "DisplayName" = $($object.DisplayName)
                    "DisplayNameLink" = "<a href=#$($object.id)>$($object.DisplayName)</a>"
                    "Foreign" = $($object.Foreign)
                    "Impact" = $($object.Impact)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Owned Enterprise Applications")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingSPOwner | Format-Table DisplayName,Foreign,Impact | Out-String))
            $ReportingSPOwner = foreach ($obj in $ReportingSPOwner) {
                [pscustomobject]@{
                    DisplayName     = $obj.DisplayNameLink
                    Foreign          =$object.Foreign
                    Impact          = $object.Impact
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

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Member in Groups (transitive)")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
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

        ############### Enterprise Application Credentials
        if ($($item.AppCredentialsDetails | Measure-Object).count -ge 1) {
            $ReportingCredentials = foreach ($object in $($item.AppCredentialsDetails)) {
                [pscustomobject]@{
                    "Type" = $($object.Type)
                    "DisplayName" = $($object.DisplayName)
                    "StartDateTime" = $($object.StartDateTime.ToString())
                    "EndDateTime" = $($object.EndDateTime.ToString())
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Enterprise Application Credentials")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingCredentials | Out-String))
        }

        ############### App Roles
        if ($($item.AppRolesDetails | Measure-Object).count -ge 1) {
            $ReportingAppRoles = foreach ($object in $($item.AppRolesDetails)) {
                # Build link for HTML report based on the object type
                switch ($object.AppRoleAssignmentType) {
                    'User' {
                        $AppRoleMemberLink = "<a href=Users_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.AppRoleMemberId)>$($object.AppRoleMember)</a>"
                        break
                    }
                    'Group' {
                        $AppRoleMemberLink = "<a href=Groups_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.AppRoleMemberId)>$($object.AppRoleMember)</a>"
                        break
                    }
                    Default {
                        $AppRoleMemberLink = $object.AppRoleMember
                    }
                }
                [pscustomobject]@{
                    "AppRoleName" = $($object.AppRoleName)
                    "RoleEnabled" = $($object.RoleEnabled)
                    "AppRoleAssignmentType" = $($object.AppRoleAssignmentType)
                    "AppRoleMember" = $($object.AppRoleMember)
                    "AppRoleMemberLink" = $AppRoleMemberLink
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Assigned App Roles")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAppRoles | format-table -Property AppRoleName,RoleEnabled,AppRoleAssignmentType,AppRoleMember | Out-String))

            #Rebuild for HTML report
            $ReportingAppRoles = foreach ($obj in $ReportingAppRoles) {
                [pscustomobject]@{
                    AppRoleName             = $obj.AppRoleName
                    RoleEnabled             = $obj.RoleEnabled
                    AppRoleAssignmentType   = $obj.AppRoleAssignmentType
                    AppRoleMember           = $obj.AppRoleMemberLink
                }
            }
        }

        ############### Owners of the SP Object
        if ($($item.OwnerUserDetails | Measure-Object).count -ge 1 -or $($item.OwnerSPDetails | Measure-Object).count -ge 1) {
            if ($($item.OwnerUserDetails | Measure-Object).count -ge 1) {
                $ReportingAppOwnersUser = foreach ($object in $($item.OwnerUserDetails)) {
                    [pscustomobject]@{
                        "UPN" = $($object.UPN)
                        "UPNLink" = "<a href=Users_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.UPN)</a>"
                        "Enabled" = $($object.Enabled)
                        "Type" = $($object.Type)
                        "OnPremSync" = $($object.OnPremSync)
                        "Department" = $($object.Department)
                        "JobTitle" = $($object.JobTitle)
                    }
                }
                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine("Owners (Users)")
                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine(($ReportingAppOwnersUser | format-table -Property UPN,Enabled,Type,OnPremSync,Department,JobTitle | Out-String))

                #Rebuild for HTML report
                $ReportingAppOwnersUser = foreach ($obj in $ReportingAppOwnersUser) {
                    [pscustomobject]@{
                        UserName        = $obj.UPNLink
                        Enabled         = $obj.Enabled
                        Type            = $obj.Type
                        OnPremSync      = $obj.OnPremSync
                        Department      = $obj.Department
                        JobTitle        = $obj.JobTitle
                    }
                }
            }

            if ($($item.OwnerSPDetails | Measure-Object).count -ge 1) {
                $ReportingAppOwnersSP = foreach ($object in $($item.OwnerSPDetails)) {
                    [pscustomobject]@{
                        "DisplayName" = $($object.DisplayName)
                        "DisplayNameLink" = "<a href=#$($object.id)>$($object.DisplayName)</a>"
                        "Enabled" = $($object.Enabled)
                        "PublisherName" = $($object.publisherName)
                        "ServicePrincipalType" = $($object.ServicePrincipalType)
                    }
                }
                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine("Owners (Service Principals)")
                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine(($ReportingAppOwnersSP | format-table -Property DisplayName,Enabled,PublisherName,ServicePrincipalType | Out-String))
                $ReportingAppOwnersSP = foreach ($obj in $ReportingAppOwnersSP) {
                    [pscustomobject]@{
                        DisplayName             = $obj.DisplayNameLink
                        Enabled                 = $obj.Enabled
                        PublisherName           = $obj.PublisherName
                        ServicePrincipalType    = $obj.ServicePrincipalType
                    }
                }
            }
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

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("API Permission (Application)")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAPIPermission | Out-String))
        }


        ############### API Delegated Permissions
        if ($($item.ApiDelegatedDetails | Measure-Object).count -ge 1) {
            $ReportingDelegatedApiPermission = foreach ($object in $($item.ApiDelegatedDetails)) {
                [pscustomobject]@{
                    "API Name" = $($object.APIName)
                    "Permission" = $($object.Scope)
                    "Categorization" = $($object.ApiPermissionCategorization)
                    "ConsentType" = $($object.ConsentType)
                    "Principal" = $($object.Principal)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("API Permission (Delegated)")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingDelegatedApiPermission | format-table | Out-String))
        }

        $ObjectDetails = [pscustomobject]@{
            "Object Name"     = $item.DisplayName
            "Object ID"       = $item.Id
            "General Information" = $ReportingEntAppInfo
            "Last Sign-Ins Details" = $ReportingLastSignIns
            "Active Entra Role Assignments" = $ReportingRoles
            "Azure IAM assignments" = $ReportingAzureRoles
            "Owner of Groups" = $ReportingGroupOwner
            "Owned App Registrations" = $ReportingAppOwner
            "Owned Enterprise Applications" = $ReportingSPOwner
            "Member in Groups (transitive)" = $ReportingGroupMember
            "Enterprise Application Credentials" = $ReportingCredentials
            "Assigned App Roles" = $ReportingAppRoles
            "Owners (Users)" = $ReportingAppOwnersUser
            "Owners (Service Principals)" = $ReportingAppOwnersSP
            "API Permission (Application)" = $ReportingAPIPermission
            "API Permission (Delegated)" = $ReportingDelegatedApiPermission
        }

        [void]$AllObjectDetailsHTML.Add($ObjectDetails)

    }

    $DetailOutputTxt = $DetailTxtBuilder.ToString()

    write-host "[*] Writing log files"
    write-host

    $mainTable = $tableOutput | select-object -Property @{Name = "DisplayName"; Expression = { $_.DisplayNameLink}},AppRoleRequired,PublisherName,DefaultMS,Foreign,Enabled,Inactive,LastSignInDays,Owners,Credentials,AppRoles,GrpMem,GrpOwn,AppOwn,SpOwn,EntraRoles,AzureRoles,ApiDangerous, ApiHigh, ApiMedium, ApiLow, ApiMisc,ApiDelegated,Impact,Likelihood,Risk,Warnings
    $mainTableJson  = $mainTable | ConvertTo-Json -Depth 5 -Compress

    $mainTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainTableJson + "`n" + '</script>'



    #Define header HTML
    $headerHTML = [pscustomobject]@{
        "Executed in Tenant" = "$($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)"
        "Executed at" = "$StartTimestamp "
        "Execution Warnings" = $EnterpriseAppsScriptWarningList -join ' / '
    }

# Build Detail section as JSON for the HTML Report
$AllObjectDetailsHTML = $AllObjectDetailsHTML | ConvertTo-Json -Depth 5 -Compress
$ObjectsDetailsHEAD = @'
    <h2>Enterprise Applications Details</h2>
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
Execution Warnings = $($EnterpriseAppsScriptWarningList -join ' / ')
************************************************************************************************************************
"

#Define Appendix
$AppendixHeaderTXT = "

=======================================================================================================================
Appendix: Used API Permission Reference
=======================================================================================================================
"



    $ApiPermissionReference = $details | Select-Object -ExpandProperty AppApiPermission | select-object ApiName, ApiPermissionCategorization,ApiPermission, ApiPermissionDescription | Sort-Object -Property ApiName,ApiPermission -Unique

    # Prepare HTML output
    $headerHTML = $headerHTML | ConvertTo-Html -Fragment -PreContent "<div id=`"loadingOverlay`"><div class=`"spinner`"></div><div class=`"loading-text`">Loading data...</div></div><nav id=`"topNav`"></nav><h1>$($Title) Enumeration</h1>" -As List -PostContent "<h2>$($Title) Overview</h2>"

    #Write TXT and CSV files
    $headerTXT | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    $tableOutput | format-table DisplayName,AppRoleRequired,PublisherName,DefaultMS,Foreign,Enabled,Inactive,LastSignInDays,Owners,Credentials,AppRoles,GrpMem,GrpOwn,AppOwn,SpOwn,EntraRoles,AzureRoles,ApiDangerous, ApiHigh, ApiMedium, ApiLow, ApiMisc,ApiDelegated,Impact,Likelihood,Risk,Warnings | Out-File -Width 512 "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    $tableOutput | select-object DisplayName,AppRoleRequired,PublisherName,DefaultMS,Foreign,Enabled,Inactive,LastSignInDays,Owners,Credentials,AppRoles,GrpMem,GrpOwn,AppOwn,SpOwn,EntraRoles,AzureRoles,ApiDangerous, ApiHigh, ApiMedium, ApiLow, ApiMisc,ApiDelegated,Impact,Likelihood,Risk,Warnings | Export-Csv -Path "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).csv" -NoTypeInformation
    $DetailOutputTxt | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    $AppendixHeaderTXT | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    $ApiPermissionReference | Format-Table -AutoSize | Out-File -Width 512 "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append

    #Write HTML
    $ApiPermissionReferenceHTML += $ApiPermissionReference | ConvertTo-Html -Fragment -PreContent "<h2>Appendix: Used API Permission Reference</h2>"
    $PostContentCombined = $GLOBALJavaScript + "`n" + $ApiPermissionReferenceHTML
    $Report = ConvertTo-HTML -Body "$headerHTML $mainTableHTML" -Title "$Title Enumeration" -Head $GLOBALcss -PostContent $PostContentCombined -PreContent $AllObjectDetailsHTML
    $Report | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).html"

     write-host "[+] Details of $EnterpriseAppsCount Enterprise Application stored in output files (CSV,TXT,HTML): $outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName)"

    #Add information to the enumeration summary
    $ForeignCount = 0
    $CredentialCount = 0
    $AppApiDangerous = 0
    $AppApiHigh = 0
    $AppApiMedium = 0
    $AppApiLow = 0
    $AppApiMisc = 0

    foreach ($app in $tableOutput) {
        if ($app.Foreign) {
            $ForeignCount++
        }
        if ($app.Credentials) {
            $CredentialCount++
        }
        if ($app.ApiDangerous) {$AppApiDangerous++}
        if ($app.ApiHigh) {$AppApiHigh++}
        if ($app.ApiMedium) {$AppApiMedium++}
        if ($app.ApiLow) {$AppApiLow++}
        if ($app.ApiMisc) {$AppApiMisc++}
    }

    # Store in global var
    $GlobalAuditSummary.EnterpriseApps.Count = $EnterpriseAppsCount
    $GlobalAuditSummary.EnterpriseApps.Foreign = $ForeignCount
    $GlobalAuditSummary.EnterpriseApps.Credentials = $CredentialCount


    $GlobalAuditSummary.EnterpriseApps.ApiCategorization.Dangerous = $AppApiDangerous
    $GlobalAuditSummary.EnterpriseApps.ApiCategorization.High = $AppApiHigh
    $GlobalAuditSummary.EnterpriseApps.ApiCategorization.Medium = $AppApiMedium
    $GlobalAuditSummary.EnterpriseApps.ApiCategorization.Low = $AppApiLow
    $GlobalAuditSummary.EnterpriseApps.ApiCategorization.Misc = $AppApiMisc

    #Convert to Hashtable for faster searches
    $AllServicePrincipalHT = @{}
    foreach ($item in $AllServicePrincipal) {
        $AllServicePrincipalHT[$item.Id] = $item
    }

    Return $AllServicePrincipalHT

}
