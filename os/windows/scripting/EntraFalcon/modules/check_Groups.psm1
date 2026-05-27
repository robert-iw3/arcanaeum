<#
	.SYNOPSIS
	   Enumerates groups and evaluates their configurations, ownership, roles, and risk posture.
#>

function Invoke-CheckGroups {

    ############################## Parameter section ########################
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$OutputFolder = ".",
        [Parameter(Mandatory=$false)][int]$HTMLMemberLimit = 20,
        [Parameter(Mandatory=$false)][int]$LimitResults,
        [Parameter(Mandatory=$false)][int]$HTMLNestedGroupsLimit = 40,
        [Parameter(Mandatory=$false)][switch]$SkipAutoRefresh = $false,
        [Parameter(Mandatory=$false)][switch]$QAMode = $false,
        [Parameter(Mandatory=$false)][Object[]]$AdminUnitWithMembers,
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$false)][Object[]]$ConditionalAccessPolicies,
        [Parameter(Mandatory=$false)][hashtable]$AzureIAMAssignments,
        [Parameter(Mandatory=$true)][hashtable]$TenantRoleAssignments,
        [Parameter(Mandatory=$true)][hashtable]$Devices,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp,
        [Parameter(Mandatory=$false)][Object[]]$TenantPimForGroupsAssignments
    )

    ############################## Function section ########################

    #Function to check if SP is foreign.
    function CheckSP {
        param($Object)

        $sp = $AllSPBasicHT[$Object.id]
        if (-not $sp) { return }

        $ForeignTenant = ($sp.servicePrincipalType -ne "ManagedIdentity" -and $sp.AppOwnerOrganizationId -ne $CurrentTenant.id)
        $DefaultMS     = ($sp.servicePrincipalType -ne "ManagedIdentity" -and $GLOBALMsTenantIds -contains $sp.AppOwnerOrganizationId)

        [PSCustomObject]@{
            Id            = $sp.id
            DisplayName   = $sp.displayName
            Foreign       = $ForeignTenant
            PublisherName = $sp.publisherName
            SPType        = $sp.servicePrincipalType
            DefaultMS     = $DefaultMS
        }
    }


    #Function to create transitive members
    function Get-TransitiveMembers {
        param (
            [string]$GroupId,
            [hashtable]$AdjList,
            [hashtable]$VisitedGlobal
        )

        $Transitive = [System.Collections.Generic.List[object]]::new()
        $Stack = [System.Collections.Stack]::new()
        $VisitedLocal = @{}

        $Stack.Push($GroupId)
        while ($Stack.Count -gt 0) {
            $Current = $Stack.Pop()
            if (-not $VisitedLocal.ContainsKey($Current)) {
                $VisitedLocal[$Current] = $true
                if ($AdjList.ContainsKey($Current)) {
                    foreach ($memberObj in $AdjList[$Current]) {
                        $memberId = $memberObj.id
                        $memberType = $memberObj.'@odata.type'

                        if ($VisitedGlobal.ContainsKey($memberId)) { continue }
                        $VisitedGlobal[$memberId] = $true

                        if ($memberType -eq "#microsoft.graph.group") {
                            $Stack.Push($memberId)
                            $Transitive.Add($memberObj)
                        } else {
                            $Transitive.Add($memberObj)
                        }
                    }
                }
            }
        }
        return $Transitive
    }

    #Function to create transitive parents
    $TransitiveParentCache = @{}

    function Get-TransitiveParentsCached {
        param (
            [string]$GroupId,
            [hashtable]$ReverseAdjList,
            [hashtable]$AllGroupsHT
        )

        if ($TransitiveParentCache.ContainsKey($GroupId)) {
            return $TransitiveParentCache[$GroupId]
        }

        $Visited = @{}
        $Stack = New-Object System.Collections.Stack
        $ResultHT = @{}

        $Stack.Push($GroupId)
        while ($Stack.Count -gt 0) {
            $Current = $Stack.Pop()

            if (-not $Visited.ContainsKey($Current)) {
                $Visited[$Current] = $true

                if ($ReverseAdjList.ContainsKey($Current)) {
                    foreach ($parent in $ReverseAdjList[$Current]) {
                        $parentId = $parent.id

                        if ($AllGroupsHT.ContainsKey($parentId)) {
                            # Only add to result if not already added
                            if (-not $ResultHT.ContainsKey($parentId)) {
                                $ResultHT[$parentId] = $AllGroupsHT[$parentId]
                            }

                            # Continue walking up only if we haven’t seen this parent
                            if (-not $Visited.ContainsKey($parentId)) {
                                $Stack.Push($parentId)
                            }
                        }
                    }
                }
            }
        }

        # Cache the result
        $TransitiveParentCache[$GroupId] = $ResultHT.Values
        return $ResultHT.Values
    }


    $NestedGroupCache = @{}
    function Expand-NestedGroups-Cached {
        param (
            [Parameter(Mandatory = $true)]
            [object]$StartGroup,

            [Parameter(Mandatory = $true)]
            [hashtable]$GroupLookup,

            [Parameter(Mandatory = $true)]
            [System.Management.Automation.PSCmdlet]$CallerPSCmdlet
        )

        # Return cached if available
        if ($NestedGroupCache.ContainsKey($StartGroup.Id)) {
            return $NestedGroupCache[$StartGroup.Id]
        }

        $allNestedGroups = [System.Collections.Generic.List[object]]::new()
        $toProcess = [System.Collections.Queue]::new()
        $visited = [System.Collections.Generic.HashSet[string]]::new()

        $null = $toProcess.Enqueue($StartGroup)
        $null = $visited.Add($StartGroup.Id)

        while ($toProcess.Count -gt 0) {
            $current = $toProcess.Dequeue()

            $nestedGroups = $current.NestedGroupsDetails
            if ($null -eq $nestedGroups -or $nestedGroups.Count -eq 0) { continue }

            foreach ($nested in $nestedGroups) {
                $nestedId = $nested.Id
                if (-not $nestedId) { continue }

                if ($visited.Add($nestedId)) {
                    $resolvedGroup = $GroupLookup[$nestedId]
                    if ($resolvedGroup) {
                        $allNestedGroups.Add($resolvedGroup)
                        $toProcess.Enqueue($resolvedGroup)
                    }
                }
            }
        }

        $NestedGroupCache[$StartGroup.Id] = $allNestedGroups
        return $allNestedGroups
    }

    # Function to help built the TXT report (avoiding using slow stuff like format-table)
    function Format-ReportSection {
        param (
            [string]$Title,
            [array]$Objects,
            [string[]]$Properties,
            [hashtable]$ColumnWidths
        )

        $sb = New-Object System.Text.StringBuilder

        $line = "=" * 120
        [void]$sb.AppendLine($line)
        [void]$sb.AppendLine($Title)
        [void]$sb.AppendLine($line)

        # Header
        $header = ""
        foreach ($prop in $Properties) {
            $header += ("{0,-$($ColumnWidths[$prop])} " -f $prop)
        }
        [void]$sb.AppendLine($header)

        # Rows
        foreach ($obj in $Objects) {
            $row = ""
            foreach ($prop in $Properties) {
                $val = $obj.$prop
                $row += ("{0,-$($ColumnWidths[$prop])} " -f $val)
            }
            [void]$sb.AppendLine($row)
        }

        return $sb.ToString()
    }


    ############################## Script section ########################
    $PmScript = [System.Diagnostics.Stopwatch]::StartNew()
    $PmInitTasks = [System.Diagnostics.Stopwatch]::StartNew()


    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "Start group script"

    # Check token and trigger refresh if required
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    # Define basic variables
    $Title = "Groups"
    $ProgressCounter = 0
    $TokenCheckLimit = 5000  # Define recheck limit for token lifetime. In large environments the access token might expire during the test.
    $GroupScriptWarningList = [System.Collections.Generic.List[string]]::new()
    $NestedGroupsHighvalue = [System.Collections.Generic.List[object]]::new()
	$AllGroupsDetails = [System.Collections.Generic.List[object]]::new()
    $AllObjectDetailsHTML = [System.Collections.ArrayList]::new()
    $DetailOutputTxt = ""
    if (-not $GLOBALGraphExtendedChecks) {$GroupScriptWarningList.Add("Only active role assignments assessed!")}

    $GroupImpactScore = @{
        "M365Group"                 = 1
        "HiddenGAL"                 = 1
        "Distribution"              = 0.5
        "SecurityEnabled"           = 2
        "AzureRole"                 = 100
        "AppRole"                   = 10
        "CAP"                       = 50
    }
    $GroupLikelihoodScore = @{
        "PublicM365Group"           = 100
        "Member"                    = 0.1
        "DirectOwnerCloud"          = 1
        "DirectOwnerOnprem"         = 2
        "PIMforGroupsOwnersGroup"   = 3
        "NestedGroup"               = 2
        "DynamicGroup"              = 5
        "DynamicGroupDangerous"     = 20
        "ExternalSPMemberOwner"     = 50
        "InternalSPMemberOwner"     = 5
        "BaseNotProtected"          = 5
        "GuestMemberOwner"          = 5
    }


    if ($TenantPimForGroupsAssignments) {
        Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "Processing $($TenantPimForGroupsAssignments.Count) PIM for Groups Assignments"
        # Hashtable for all owners for faster lookup in each group
        $PimForGroupsEligibleOwnersHT = @{}
        $PimForGroupsEligibleOwnerParentGroupHT = @{}
        foreach ($assignment in $TenantPimForGroupsAssignments) {
            if ($assignment.accessId -eq "owner") {
                # Check if groupId already exists in the hashtable
                if (-not $PimForGroupsEligibleOwnersHT.ContainsKey($assignment.groupId)) {
                    $PimForGroupsEligibleOwnersHT[$assignment.groupId] = @()  # Initialize as an empty array
                }

                #Add Properties depending on the object type
                if ($assignment.Type -eq "User") {
                    $OwnerInfo = [PSCustomObject]@{
                        Id  =                   $assignment.principalId
                        UserType         =      $assignment.UserType
                        type                  = $assignment.Type
                        OnPremisesSyncEnabled = $assignment.OnPremisesSyncEnabled
                        AssignmentType     =    "Eligible"
                    }
                } elseif ($assignment.Type -eq "Group") {
                    $OwnerInfo = [PSCustomObject]@{
                        Id  = $assignment.principalId
                        type               = $assignment.Type
                        AssignmentType     =    "Eligible"
                    }

                    #Match "parent" infos. Needed to link from eligible to parent groups
                    $ParentInfo = [PSCustomObject]@{
                        Id  = $assignment.groupId
                        DisplayName  = $GLOBALPimForGroupsHT[$assignment.groupId]
                        AssignmentType     =    "Eligible"
                    }

                    # Store the object in the Parent Group hashtable by principalId used to lookup in which group a group has ownership of
                    if (-not $PimForGroupsEligibleOwnerParentGroupHT.ContainsKey($assignment.principalId)) {
                        $PimForGroupsEligibleOwnerParentGroupHT[$assignment.principalId] = @()  # Initialize as an empty array
                    }
                    $PimForGroupsEligibleOwnerParentGroupHT[$assignment.principalId] += $ParentInfo

                } else {
                    #This should never be triggered
                    $OwnerInfo = [PSCustomObject]@{
                        Id  = $assignment.principalId
                        Type         = $assignment.Type
                        AssignmentType     =    "Eligible"
                    }
                }

                # Add the object to the array for that groupId
                $PimForGroupsEligibleOwnersHT[$assignment.groupId] += $OwnerInfo
            }
        }

        # Hashtable for all members for faster lookup in each group
        $PimForGroupsEligibleMembersHT = @{}
        $PimForGroupsEligibleMemberParentGroupHT = @{}
        foreach ($assignment in $TenantPimForGroupsAssignments) {
            if ($assignment.accessId -eq "member") {
                # Check if groupId already exists in the hashtable
                if (-not $PimForGroupsEligibleMembersHT.ContainsKey($assignment.groupId)) {
                    $PimForGroupsEligibleMembersHT[$assignment.groupId] = @()  # Initialize as an empty array
                }

                #Add Properties depending on the object type
                if ($assignment.Type -eq "User") {
                    $MemberInfo = [PSCustomObject]@{
                        Id  =                   $assignment.principalId
                        UserType         =      $assignment.UserType
                        type                  = $assignment.Type
                        OnPremisesSyncEnabled = $assignment.OnPremisesSyncEnabled
                        AssignmentType     =    "Eligible"
                    }
                } elseif ($assignment.Type -eq "Group") {
                    $MemberInfo = [PSCustomObject]@{
                        Id  = $assignment.principalId
                        type         = $assignment.Type
                        AssignmentType     =    "Eligible"
                    }

                    #Match "parent" infos. Needed to link from eligible to parent groups
                    $ParentInfo = [PSCustomObject]@{
                        Id  = $assignment.groupId
                        DisplayName  = $GLOBALPimForGroupsHT[$assignment.groupId]
                        AssignmentType     =    "Eligible"
                    }

                    # Store the object in the Parent Group hashtable by principalId used to lookup in which group a group is nested in
                    if (-not $PimForGroupsEligibleMemberParentGroupHT.ContainsKey($assignment.principalId)) {
                        $PimForGroupsEligibleMemberParentGroupHT[$assignment.principalId] = @()  # Initialize as an empty array
                    }
                    $PimForGroupsEligibleMemberParentGroupHT[$assignment.principalId] += $ParentInfo

                } else {
                    #Fallback: This should never be triggered
                    $MemberInfo = [PSCustomObject]@{
                        Id  = $assignment.principalId
                        DisplayName  = $assignment.DisplayName
                        Type         = $assignment.Type
                        AssignmentType     =    "Eligible"
                    }
                }

                # Add the object to the array for that groupId
                $PimForGroupsEligibleMembersHT[$assignment.groupId] += $MemberInfo

            }
        }

    }

    # Build the lookup for AU Units
    $GroupToAUMap = @{}

    foreach ($au in $AdminUnitWithMembers) {
        $members = $au.MembersGroup

        if ($members -is [System.Collections.IDictionary]) {
            $members = @($members)
        }

        foreach ($member in $members) {
            $id = $member.id
            if ($null -ne $id) {
                if (-not $GroupToAUMap.ContainsKey($id)) {
                    $GroupToAUMap[$id] = [System.Collections.Generic.List[object]]::new()
                }

                $auLite = [pscustomobject]@{
                    DisplayName                  = $au.DisplayName
                    IsMemberManagementRestricted = $au.IsMemberManagementRestricted
                }

                $GroupToAUMap[$id].Add($auLite)
            }
        }
    }

    $PmInitTasks.Stop()
    ########################################## SECTION: DATACOLLECTION ##########################################
    $PmDataCollection = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Host "[*] Get Groups"
    $QueryParameters = @{
        '$select' = 'Id,DisplayName,Visibility,GroupTypes,SecurityEnabled,IsAssignableToRole,OnPremisesSyncEnabled,MailEnabled,Description,MembershipRule'
        '$top' = "999"
    }
    $AllGroups = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/groups' -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)

    $GroupsTotalCount = @($AllGroups).Count
    Write-Host "[+] Got $($GroupsTotalCount) groups"

    #Abort if no groups are present
    if (@($AllGroups).count -eq 0) {
        $AllGroupsDetailsHT = @{}
        Return $AllGroupsDetailsHT
    }



    #Build Hashtable with basic group info. Needed in nesting scenarios to git information about parent / child group
    $AllGroupsHT = @{}
    foreach ($group in $AllGroups) {
        $id = $group.id
        $DisplayName = $group.DisplayName
        $securityEnabled = $group.securityEnabled
        $isAssignableToRole = if ($null -eq $group.isAssignableToRole) { $false } else { $group.isAssignableToRole }

        $AllGroupsHT[$id] = [PSCustomObject]@{
            id           = $id
            DisplayName    = $DisplayName
            securityEnabled     = $securityEnabled
            isAssignableToRole  = $isAssignableToRole
        }
    }

    # Check if Azure IAM roles were checked
    if (-not ($GLOBALAzurePsChecks)) {
        $GroupScriptWarningList.Add("Group Azure IAM assignments were not assessed")
    }

    #Check if CAP have been assessed
    if (-not ($GLOBALPermissionForCaps)) {
        $GroupScriptWarningList.Add("Group CAPs assignments were not assessed")
    }

    #Check if PIM for groups was checked
    if (-not ($GLOBALPimForGroupsChecked)) {
        $GroupScriptWarningList.Add("Pim for Groups was not assessed!")
    }

    Write-Host "[*] Getting all group memberships"
    $GroupMembers = @{}
    $BatchSize = 10000
    $ChunkCount = [math]::Ceiling($GroupsTotalCount / $BatchSize)

    for ($chunkIndex = 0; $chunkIndex -lt $ChunkCount; $chunkIndex++) {
        Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "Processing batch $($chunkIndex + 1) of $ChunkCount..."

        $StartIndex = $chunkIndex * $BatchSize
        $EndIndex = [math]::Min($StartIndex + $BatchSize - 1, $GroupsTotalCount - 1)
        $GroupBatch = $AllGroups[$StartIndex..$EndIndex]
        $Requests = New-Object System.Collections.Generic.List[Hashtable]
        foreach ($group in $GroupBatch) {
            $req = @{
                "id"     = $group.id
                "method" = "GET"
                "url"    = "/groups/$($group.id)/members"
            }
            $Requests.Add($req)
        }

        # Send the batch
        $Response = Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -QueryParameters @{'$select' = 'id,userType,onPremisesSyncEnabled' ;'$top'='999'}

        # Store results
        foreach ($item in $Response) {
            if ($item.response.value) {
                $GroupMembers[$item.id] = @($item.response.value)
            }
        }
    }


    foreach ($group in $GroupMembers.Values) {
        $TotalGroupMembers += $group.Count
    }
    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "Got $TotalGroupMembers direct member relationships"
    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "Build transitive member relationships"

    # Build transitive members for each group
    $TransitiveMembersRaw = @{}
    foreach ($groupId in $GroupMembers.Keys) {
        $Visited = @{}
        $TransitiveMembersRaw[$groupId] = Get-TransitiveMembers -GroupId $groupId -AdjList $GroupMembers -VisitedGlobal $Visited
    }

    $TotalTransitiveMemberRelations = 0
    foreach ($members in $TransitiveMembersRaw.Values) {
        $TotalTransitiveMemberRelations += $members.Count
    }

    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "Calculated $TotalTransitiveMemberRelations transitive member relationships"
    #Show warning in large tenants
    if (-not $LimitResults) {
        if ($TotalTransitiveMemberRelations -ge 1500000 -or $GroupsTotalCount -ge 100000) {
            Write-Warning "In large tenants, consider using -LimitResults (e.g., 30000) to reduce report size and improve report building performance."
        }
    }

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    Write-Host "[*] Get all group ownerships"
    #Get owners of all groups for later lookup
    $Requests = New-Object System.Collections.Generic.List[Hashtable]
    foreach ($item in $AllGroups) {
        $req = @{
            "id"     = $item.id
            "method" = "GET"
            "url"    =   "/groups/$($item.id)/owners"
        }
        $Requests.Add($req)
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI  -UserAgent $($GlobalAuditSummary.UserAgent.Name) -QueryParameters @{'$select' = 'id,userType,onPremisesSyncEnabled'})
    $GroupOwnersRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $GroupOwnersRaw[$item.id] = $item.response.value
        }
    }

    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "Got $($GroupOwnersRaw.Count) group ownerships"

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    Write-Host "[*] Get all group app role assignments"
    #Get group AppRole Assignments of all groups for later lookup
    $Requests = New-Object System.Collections.Generic.List[Hashtable]
    foreach ($item in $AllGroups) {
        $req = @{
            "id"     = $item.id
            "method" = "GET"
            "url"    =   "/groups/$($item.id)/appRoleAssignments"
        }
        $Requests.Add($req)
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI  -UserAgent $($GlobalAuditSummary.UserAgent.Name) -QueryParameters @{'$select' = 'ResourceDisplayName,ResourceId,AppRoleId' ;'$top'='999'})
    $AppRoleAssignmentsRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $AppRoleAssignmentsRaw[$item.id] = $item.response.value
        }
    }

    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "Got $($AppRoleAssignmentsRaw.Count) app group role assignments"

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    Write-Host "[*] Calculate all groups parent groups relation"

    # Build reverse group membership map: child -> parent
    $ReverseGroupMembershipMap = @{}
    foreach ($parentGroupId in $GroupMembers.Keys) {
        foreach ($member in $GroupMembers[$parentGroupId]) {
            if ($member.'@odata.type' -eq '#microsoft.graph.group') {
                $childGroupId = $member.id

                if (-not $ReverseGroupMembershipMap.ContainsKey($childGroupId)) {
                    $ReverseGroupMembershipMap[$childGroupId] = [System.Collections.Generic.List[object]]::new()
                }

                if ($AllGroupsHT.ContainsKey($parentGroupId)) {
                    $ReverseGroupMembershipMap[$childGroupId].Add($AllGroupsHT[$parentGroupId])
                }
            }
        }
    }

    $GroupNestedInRaw = @{}
    foreach ($group in $AllGroups) {
        $parents = Get-TransitiveParentsCached -GroupId $group.id -ReverseAdjList $ReverseGroupMembershipMap -AllGroupsHT $AllGroupsHT
        if (@($parents).Count -gt 0) {
            $GroupNestedInRaw[$group.id] = $parents
        }
    }

    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "Got $($GroupNestedInRaw.Count) groups with parent group relationship"


    #Basic User Info to avoid storing the information in a large object
    $QueryParameters = @{
        '$select' = "Id,UserPrincipalName,UserType,accountEnabled,onPremisesSyncEnabled"
        '$top' = "999"
      }
      $RawResponse = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/users" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    $AllUsersBasicHT = @{}
    foreach ($user in $RawResponse) {
        $AllUsersBasicHT[$user.id] = $user
    }

    #Basic ServicePrincipal Info to avoid storing the information in a large object
    $QueryParameters = @{
        '$select' = "id,displayName,accountEnabled,appOwnerOrganizationId,publisherName,servicePrincipalType"
        '$top' = "999"
    }
    $RawResponse = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/servicePrincipals' -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    $AllSPBasicHT = @{}
    foreach ($app in $RawResponse) {
        $AllSPBasicHT[$app.id] = $app
    }


    #Remove Variables
    remove-variable parents -ErrorAction SilentlyContinue
    remove-variable RawResponse -ErrorAction SilentlyContinue
    remove-variable Requests -ErrorAction SilentlyContinue
    remove-variable AllUsersBasic -ErrorAction SilentlyContinue
    remove-variable GroupMembers -ErrorAction SilentlyContinue

    $PmDataCollection.Stop()
    ########################################## SECTION: Group Processing ##########################################
    $PmDataProcessing = [System.Diagnostics.Stopwatch]::StartNew()

    #Calc dynamic update interval
    $StatusUpdateInterval = [Math]::Max([Math]::Floor($GroupsTotalCount / 10), 1)
    Write-Host "[*] Status: Processing group 1 of $GroupsTotalCount (updates every $StatusUpdateInterval groups)..."


    # Loop through each group and get additional info
    foreach ($group in $AllGroups) {

        #Loop init section
        $ProgressCounter++
        $ImpactScore = 0
        $LikelihoodScore = 0
        $Warnings = [System.Collections.Generic.HashSet[string]]::new()
        $ownerGroup = @()
        $PfGOwnedGroups = @()
        $GroupNestedIn = [System.Collections.Generic.List[psobject]]::new()
        $AppRoleAssignments = [System.Collections.Generic.List[object]]::new()
		$AzureRoleDetails = @()

        # Check the token lifetime after a specific amount of objects
        if (($ProgressCounter % $TokenCheckLimit) -eq 0 -and $SkipAutoRefresh -eq $false) {
            if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}
        }

        # Display status based on the objects numbers (slightly improves performance)
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $GroupsTotalCount) {
            Write-Host "[*] Status: Processing group $ProgressCounter of $GroupsTotalCount..."
        }

        #Find parent groups if actual group
        if ($GroupNestedInRaw.ContainsKey($group.Id)) {
            foreach ($member in $GroupNestedInRaw[$group.Id]) {
                $GroupNestedIn.Add([PSCustomObject]@{
                    Id              = $member.id
                    AssignmentType  = 'Active'
                    EntraRoles = 0 #Might be changed in post processing
                    AzureRoles = 0 #Might be changed in post processing
                    CAPs = 0 #Might be changed in post processing
                })
            }
        }


        #Check if group has an app role
        if ($AppRoleAssignmentsRaw.ContainsKey($group.Id)) {
            foreach ($AppRole in $AppRoleAssignmentsRaw[$group.Id]) {
                $AppRoleAssignments.Add([PSCustomObject]@{
                    ResourceDisplayName = $AppRole.ResourceDisplayName
                    ResourceId     = $AppRole.ResourceId
                    AppRoleId = $AppRole.AppRoleId
                })
            }
        }

		# Initialize ArrayLists
        $memberUser    = [System.Collections.Generic.List[psobject]]::new()
        $memberGroup   = [System.Collections.Generic.List[psobject]]::new()
        $memberSP      = [System.Collections.Generic.List[psobject]]::new()
        $memberDevices = [System.Collections.Generic.List[psobject]]::new()
        $owneruser     = [System.Collections.Generic.List[psobject]]::new()
        $ownersp       = [System.Collections.Generic.List[psobject]]::new()

        # Process group members
        if ($TransitiveMembersRaw.ContainsKey($group.Id)) {
            foreach ($member in $TransitiveMembersRaw[$group.Id]) {
                switch ($member.'@odata.type') {

                    '#microsoft.graph.user' {
                        [void]$memberUser.Add(
                            [PSCustomObject]@{
                                Id                    = $member.Id
                                userType              = $member.userType
                                onPremisesSyncEnabled = $member.onPremisesSyncEnabled
                                AssignmentType        = 'Active'
                            }
                        )
                    }

                    '#microsoft.graph.group' {

                        [void]$memberGroup.Add(
                            [PSCustomObject]@{
                                Id             = $member.Id
                                AssignmentType = 'Active'
                            }
                        )
                    }

                    '#microsoft.graph.servicePrincipal' {
                        [void]$memberSP.Add(
                            [PSCustomObject]@{
                                Id = $member.Id
                            }
                        )
                    }

                    '#microsoft.graph.device' {
                        [void]$memberDevices.Add(
                            [PSCustomObject]@{
                                Id = $member.Id
                            }
                        )
                    }
                }
            }
        }

        #Process group owners
        if ($GroupOwnersRaw.ContainsKey($group.Id)) {
            foreach ($Owner in $GroupOwnersRaw[$group.Id]) {
                switch ($Owner.'@odata.type') {

                    '#microsoft.graph.user' {
                        [void]$owneruser.Add(
                            [PSCustomObject]@{
                                Id                    = $Owner.Id
                                userType              = $Owner.userType
                                onPremisesSyncEnabled = $Owner.onPremisesSyncEnabled
                                AssignmentType        = 'Active'
                            }
                        )
                    }

                    '#microsoft.graph.servicePrincipal' {
                        [void]$ownersp.Add(
                            [PSCustomObject]@{
                                Id = $Owner.Id
                            }
                        )
                    }

                    default {
                        # Optional: log or handle unexpected owner types
                        Write-host "Unknown owner type: $($Owner.'@odata.type') for group $($group.Id)"
                    }
                }
            }
        }

       #Process pim for groups. Assignments will be added to the normal $memberGroup, $memberUser, $owneruser array and proccessed like active assignments
        if ($TenantPimForGroupsAssignments) {

            # Check if the group exists in the hashtable
            if ($PimForGroupsEligibleOwnersHT.ContainsKey($group.Id)) {
                # Retrieve all owners for this group
                $PfGownersGroup = @($PimForGroupsEligibleOwnersHT[$group.Id] | Where-Object { $_.type -eq "group" })
                $PfGownersUser = @($PimForGroupsEligibleOwnersHT[$group.Id] | Where-Object { $_.type -eq "user" })

                # Merge with normal owner list
                foreach ($user in $PfGownersUser) {
                    [void]$owneruser.Add($user)
                }
                $ownerGroup = $PfGownersGroup
            }

            #Find groups where this group is an eligible owner
            if ($PimForGroupsEligibleOwnerParentGroupHT.ContainsKey($group.Id)) {
                $PfGOwnedGroupsRaw = @($PimForGroupsEligibleOwnerParentGroupHT[$group.Id])
                $PfGOwnedGroups = foreach ($OwnedGroup in $PfGOwnedGroupsRaw) {
                    #Get additonal proprties for the group
                    if ($AllGroupsHT.ContainsKey($group.Id)) {
                        $info = $AllGroupsHT[$OwnedGroup.Id]
                        [PSCustomObject]@{
                            Id                  = $OwnedGroup.Id
                            DisplayName         = $OwnedGroup.DisplayName
                            AssignmentType      = $OwnedGroup.AssignmentType
                            SecurityEnabled     = $info.SecurityEnabled
                            isAssignableToRole  = $info.isAssignableToRole
                            EntraRoles = 0 #Might be changed in post processing
                            AzureRoles = 0 #Might be changed in post processing
                            CAPs = 0 #Might be changed in post processing
                        }
                    }
                }
             }


            # Check if the group exists in the hashtable
            if ($PimForGroupsEligibleMembersHT.ContainsKey($group.Id)) {
                # Retrieve all members of the groups for this group
				 foreach ($pimMember in $PimForGroupsEligibleMembersHT[$group.Id]) {
					if ($pimMember.type -eq "group") { [void]$memberGroup.Add($pimMember) }
					elseif ($pimMember.type -eq "user") { [void]$memberUser.Add($pimMember) }
				}
            }

            #Find groups where this group is an eligible member
            if ($PimForGroupsEligibleMemberParentGroupHT.ContainsKey($group.Id)) {
                $PfGnestedGroupsRaw = @($PimForGroupsEligibleMemberParentGroupHT[$group.Id])
                $PfGnestedGroups = foreach ($ParentGroup in $PfGnestedGroupsRaw) {
                    #Get additonal proprties for the group
                    if ($AllGroupsHT.ContainsKey($group.Id)) {
                        $info = $AllGroupsHT[$ParentGroup.Id]
                        [PSCustomObject]@{
                            Id                  = $ParentGroup.Id
                            AssignmentType      = $ParentGroup.AssignmentType
                            EntraRoles = 0 #Might be changed in post processing
                            AzureRoles = 0 #Might be changed in post processing
                            CAPs = 0 #Might be changed in post processing
                        }
                    }
                }

                # Merge with normal nested list
                foreach ($item in $PfGnestedGroups) {
                    $GroupNestedIn.Add($item)
                }
            }
        }

        # If PIM for Group has been evaluated: Check if group is onboarded in PIM for Groups
        $PIM = if (-not $GLOBALPimForGroupsChecked) {
            "?"
        } elseif ($GLOBALPimForGroupsHT -and $GLOBALPimForGroupsHT.ContainsKey($group.Id)) {
            $true
        } else {
            $false
        }


        #Count the owners to show in table
        $ownersynced = 0
        foreach ($user in $owneruser) {
            if ($user.onPremisesSyncEnabled -eq $true) {
                $ownersynced++
            }
        }

        #check guest counts
        $GuestsCount = 0
        foreach ($user in $memberUser) {
            if ($user.userType -eq 'Guest') {
                $GuestsCount++
            }
        }

        #Get details for service principals
        $memberSpDetails = foreach ($object in $memberSP) {
            CheckSP $object
        }
        $ownerSpDetails = foreach ($object in $ownersp) {
            CheckSP $object
        }

        # Determine group type
        if ($group.GroupTypes -eq "Unified") {
            $groupType = "M365 Group"
            $ImpactScore += $GroupImpactScore["M365Group"]
        } elseif ($group.SecurityEnabled -eq $false -and $group.MailEnabled -eq $true) {
            $groupType = "Distribution"
            $ImpactScore += $GroupImpactScore["Distribution"]
        } else {
            $groupType = "Security Group"
        }

        # Check if dynamic
        if ($group.GroupTypes -eq "DynamicMembership") {
            $group | Add-Member -NotePropertyName Dynamic -NotePropertyValue $true
        } else {
            $group | Add-Member -NotePropertyName Dynamic -NotePropertyValue $false
        }

        # Add visibility default value if empty
        If ($null -eq $group.Visibility) {
            $group.Visibility = "Private"
        }

        # Add sync default value if empty
        If ($null -eq $group.OnPremisesSyncEnabled) {
            $group.OnPremisesSyncEnabled = $false
        }

        # For all security enabled groups check if there are Azure IAM assignments
        if ($GLOBALAzurePsChecks) {
            if ($group.SecurityEnabled -eq $true) {

                    #Use function to get the Azure Roles for each object
                    $azureRoleDetails = Get-AzureRoleDetails -AzureIAMAssignments $AzureIAMAssignments -ObjectId $group.Id

                    # Update the Roles property only if there are matching roles
                    $AzureRoleCount = @($azureRoleDetails).Count
                } else {
                $AzureRoleCount = 0
            }
        } else {
            $AzureRoleCount = "?"
        }



        # Check if the group is assignable to a role
        if ($group.IsAssignableToRole -eq $true) {

            # Find matching roles in $TenantRoleAssignments where the PrincipalId matches the group's Id
            $MatchingRoles = $TenantRoleAssignments[$group.Id]

            # Array to hold the role information for this group
            $roleDetails = [System.Collections.Generic.List[object]]::new()

            foreach ($role in $MatchingRoles) {
                $roleInfo = [PSCustomObject]@{
                    DisplayName       = $role.DisplayName
                    Id                = $role.Id
                    AssignmentType    = $role.AssignmentType
                    IsPrivileged      = $role.IsPrivileged
                    RoleTier          = $role.RoleTier
                    IsEnabled         = $role.IsEnabled
                    IsBuiltIn         = $role.IsBuiltIn
                    DirectoryScopeId  = $role.DirectoryScopeId
                    ScopeResolved     = $role.ScopeResolved
                }
                # Add the role information to the RoleDetails array
                $roleDetails.Add($roleInfo)
            }

            # Update the Roles property only if there are matching roles
            if ($roleDetails.Count -gt 0) {
                $RoleCount = $roleDetails.Count
                $RolePrivilegedCount = @($roleDetails | Where-Object { $_.IsPrivileged -eq $true }).Count
            }

        } else {
            $RoleCount = 0
            $RolePrivilegedCount  = 0
            $roleDetails = [System.Collections.Generic.List[object]]::new()
            $group.IsAssignableToRole = $false
        }

        #Check AU assignment
        $GroupAdminUnits = [System.Collections.Generic.List[object]]::new()
        if ($GroupToAUMap.ContainsKey($group.Id)) {
            $GroupAdminUnits = $GroupToAUMap[$group.Id]
            if ($GroupAdminUnits | Where-Object { $_.IsMemberManagementRestricted }) {
                [void]$Warnings.Add("Group protected by restricted AU")
            }
        }

        # Check if the script has permission to enumerate CAPs
        if ($GLOBALPermissionForCaps) {

            # Initialize a list to store CAP information for this group
            $groupCAPs = [System.Collections.Generic.List[object]]::new()

            # Loop through each conditional access policy in $CapGroups
            foreach ($cap in $ConditionalAccessPolicies) {
                # Check if the group ID is in the ExcludedGroup or IncludedGroup of the CAP
                $isExcluded = $cap.ExcludedGroup -contains $group.Id
                $isIncluded = $cap.IncludedGroup -contains $group.Id

                if ($isExcluded -or $isIncluded) {

                    # Determine if the group is "Included" or "Excluded"
                    $groupUsage = if ($isExcluded) { "Excluded" } elseif ($isIncluded) { "Included" }

                    # Add CAP information to the list for this group
                    $groupCAPs.Add([PSCustomObject]@{
                        Id         = $cap.Id
                        CAPName    = $cap.CAPName
                        CAPExOrIn  = $groupUsage
                        CAPStatus  = $cap.CAPStatus
                    })
                }
            }

            # Add the CAP information to the group properties if any CAPs were found
            if ($groupCAPs.Count -ge 1) {
                $CAPCount = $groupCAPs.Count
            } else {
                $CAPCount = 0
                $groupCAPs = $null

            }
        } else {
            # If no permission for CAPs, set CAPCount to "?"
            $CAPCount = "?"
        }



    ########################################## SECTION: RISK RATING AND WARNINGS ##########################################
        if ($GLOBALAzurePsChecks -and $AzureRoleCount -ge 1) {

            #Use function to get the impact score and warning message for assigned Azure roles
            $AzureRolesProcessedDetails = Invoke-AzureRoleProcessing -RoleDetails $azureRoleDetails
            [void]$Warnings.Add($AzureRolesProcessedDetails.Warning)
            $ImpactScore += $AzureRolesProcessedDetails.ImpactScore
            $AzureRoleScore = $AzureRolesProcessedDetails.ImpactScore

            #Add group to list for re-processing
            if ($memberGroup.count -ge 1) {
	            $NestedGroupsHighvalue.Add([pscustomobject]@{
	                "Group" = $group.DisplayName
	                "GroupID" = $group.Id
	                "Message" = "Eligible member or nested in group with AzureRole"
	                "AzureRoles" = $AzureRoleCount
	                "TargetGroups" = $memberGroup.Id
	            })
            }
            if (@($ownerGroup).count -ge 1) {
	            $NestedGroupsHighvalue.Add([pscustomobject]@{
	                "Group" = $group.DisplayName
	                "GroupID" = $group.Id
	                "Message" = "Eligible owner of with AzureRole"
                    "AzureRoles" = $AzureRoleCount
	                "Score" = $AzureRoleScore
	                "TargetGroups" = $ownerGroup.Id
	            })
            }
        }


        #Direct owner
        if ($owneruser.count -ge 1) {

            #Check if there is an owner synced from on-prem
            if ($null -ne $owneruser.onPremisesSyncEnabled) {
                $LikelihoodScore += $GroupLikelihoodScore["DirectOwnerOnprem"]
            } else {
                $LikelihoodScore += $GroupLikelihoodScore["DirectOwnerCloud"]
            }
        }

        #PimForGroupsOwners
        if (@($ownerGroup).count -ge 1) {
            $LikelihoodScore += $GroupLikelihoodScore["PIMforGroupsOwnersGroup"]
        }

        #Process Entra Role assignments
        #Use function to get the impact score and warning message for assigned Entra roles
        if ($RoleCount -ge 1) {
            $EntraRolesProcessedDetails = Invoke-EntraRoleProcessing -RoleDetails $RoleDetails
            [void]$Warnings.Add($EntraRolesProcessedDetails.Warning)
            $ImpactScore += $EntraRolesProcessedDetails.ImpactScore
            $RoleScore = $EntraRolesProcessedDetails.ImpactScore
        }

        if ($RoleCount -ge 1) {
            #Add group to list for re-processing
            if ($memberGroup.count -ge 1) {
	            $NestedGroupsHighvalue.Add([pscustomobject]@{
	                "Group" = $group.DisplayName
	                "GroupID" = $group.Id
	                "Message" = "Eligible member or nested in group with EntraRole"
                    "EntraRoles" = $RoleCount
	                "Score" = $RoleScore
	                "TargetGroups" = $memberGroup.Id
	            })
            }
            if (@($ownerGroup).count -ge 1) {
	            $NestedGroupsHighvalue.Add([pscustomobject]@{
	                "Group" = $group.DisplayName
	                "GroupID" = $group.Id
	                "Message" = "Eligible owner of group with EntraRole"
                    "EntraRoles" = $RoleCount
	                "Score" = $RoleScore
	                "TargetGroups" = $ownerGroup.Id
	            })
            }
        }


        #Check if groups can be modified by low-tier admins or SPs
        if ($group.OnPremisesSyncEnabled -or $group.IsAssignableToRole -or $GroupAdminUnits.IsMemberManagementRestricted -contains $true) {
            $Protected = $true
        } else {
            $Protected = $false
            $LikelihoodScore += $GroupLikelihoodScore["BaseNotProtected"] #Group base score if not protected
        }


        #Check if assigned to Caps
        if ($CAPCount -ge 1) {
            $ImpactScore += $GroupImpactScore["CAP"]
            if ($group.IsAssignableToRole -eq $true) {
                [void]$Warnings.Add("Group is used in CAP")
            } elseif ($group.Dynamic -eq $true) {
                [void]$Warnings.Add("Group is used in CAP and is dynamic")
            } elseif ($group.OnPremisesSyncEnabled -eq $true) {
                [void]$Warnings.Add("Group is used in CAP and from on-prem")
            } elseif ($group.Visibility -eq "Public" -and $groupDynamic -eq $false -and $grouptype -contains "M365 Group") {
                [void]$Warnings.Add("Public M365 group in CAP")
            } elseif (-not $Protected) {
                [void]$Warnings.Add("Group is used in CAP and is not protected")
            }

            #Add group to list for re-processing
            $score = $GroupImpactScore["CAP"]
            if ($memberGroup.count -ge 1) {
	            $NestedGroupsHighvalue.Add([pscustomobject]@{
	                "Group" = $group.DisplayName
	                "GroupID" = $group.Id
	                "Message" = "Eligible member or nested in group used in CAP"
                    "CAPs" = $CAPCount
	                "Score" = $score
	                "TargetGroups" = $memberGroup.Id
	            })
            }
            if (@($ownerGroup).count -ge 1) {
	            $NestedGroupsHighvalue.Add([pscustomobject]@{
	                "Group" = $group.DisplayName
	                "GroupID" = $group.Id
	                "Message" = "Eligible owner of group used in CAP"
                    "CAPs" = $CAPCount
	                "Score" = $score
	                "TargetGroups" = $ownerGroup.Id
	            })
            }

        }

        #Check if M365 group is public
        if ($group.visibility -eq "Public" -and $grouptype -eq "M365 Group" -and $group.Dynamic -eq $false) {
            If ($group.SecurityEnabled) {
                [void]$Warnings.Add("Public security enabled M365 group")
            } else {
                [void]$Warnings.Add("Public M365 group")
            }

            $LikelihoodScore += $GroupLikelihoodScore["PublicM365Group"]

            if ($AppRoleAssignments.count -ge 1) {
                [void]$Warnings.Add("Used for AppRoles")
            }
        }

        #Check for guests as owner
        if ($owneruser.userType -contains "Guest") {
            [void]$Warnings.Add("Guest as owner")
            $LikelihoodScore += $GroupLikelihoodScore["GuestMemberOwner"]
        }

        #Check if group is dynamic
        if ($group.Dynamic -eq $true) {
            if ($AppRoleAssignments.count -ge 1) {
                $ForAppRoles = " used for AppRoles"
            } else {
                $ForAppRoles = ""
            }

            #Search for potential dangerous queries
            if ($group.MembershipRule -match "user.userPrincipalName " -or $group.MembershipRule -match "user.otherMail " -or $group.MembershipRule -match "user.mail" -or $group.MembershipRule -match "user.PreferredLanguage" -or $group.MembershipRule -match "user.MobilePhone" -or $group.MembershipRule -match "user.BusinessPhones") {
                $DangerousQuery = "with potentially dangerous query"
                $LikelihoodScore += $GroupLikelihoodScore["DynamicGroupDangerous"]
            } else {
                $DangerousQuery = ""
                $LikelihoodScore += $GroupLikelihoodScore["DynamicGroup"]
            }
            [void]$Warnings.Add("Dynamic group $DangerousQuery $ForAppRoles")
        }

        #Check app roles
        if ($AppRoleAssignments.count -ge 1) {
            $ImpactScore += $GroupImpactScore["AppRole"]
        }

        #SP as member
        if ($memberSP.count -ge 1) {
            if ($memberSpDetails.Foreign -contains $true -and $memberSpDetails.DefaultMS -contains $false) {
                [void]$Warnings.Add("External (non-MS) SP as member")
                $LikelihoodScore += $GroupLikelihoodScore["ExternalSPMemberOwner"]
            } elseif ($memberSpDetails.Foreign -contains $false -and $memberSpDetails.DefaultMS -contains $false) {
                [void]$Warnings.Add("Internal SP as member")
                $LikelihoodScore += $GroupLikelihoodScore["InternalSPMemberOwner"]
            } else {
                $LikelihoodScore += 1
            }
        }

        #SP as owner
        if (@($ownersp).count -ge 1) {
            if ($ownerSpDetails.Foreign -contains $true -and $ownerSpDetails.DefaultMS -contains $false) {
                [void]$Warnings.Add("External (non-MS) SP as owner")
                $LikelihoodScore += $GroupLikelihoodScore["ExternalSPMemberOwner"]
            } elseif ($ownerSpDetails.Foreign -contains $false -and $ownerSpDetails.DefaultMS -contains $false) {
                [void]$Warnings.Add("Internal SP as owner")
                $LikelihoodScore += $GroupLikelihoodScore["InternalSPMemberOwner"]
            }
        }

        #Has members
		$MemberUserCount = $memberuser.count
        if ($MemberUserCount -ge 1) {
            # Use Square Root Scaling to avoid likelihood inflation in large tenants
            $LikelihoodScore += [math]::Sqrt($MemberUserCount) * $GroupLikelihoodScore["Member"]
        }

        #Is security enabled and has any members/owners, is dynamic etc
        if ($group.SecurityEnabled) {
            $ImpactScore += $GroupImpactScore["SecurityEnabled"]
        }


        #Format warning messages
        $Warnings = ($Warnings -join ' / ')

        #Creating HT to speed-up the post-processing part
        $PfGOwnedGroupsById = @{}
        $NestedInGroupsById = @{}
        foreach ($owned in $PfGOwnedGroups) {
            $PfGOwnedGroupsById[$owned.Id] = $owned
        }
        foreach ($nestedIn in $GroupNestedIn) {
            $NestedInGroupsById[$nestedIn.Id] = $nestedIn
        }

        #Remove properties to save some RAM
        foreach ($user in $memberUser) {
            if ($user -is [PSObject]) {
                $user.PSObject.Properties.Remove('userType')
                $user.PSObject.Properties.Remove('onPremisesSyncEnabled')
            }
        }
        foreach ($user in $owneruser) {
            if ($user -is [PSObject]) {
                $user.PSObject.Properties.Remove('userType')
                $user.PSObject.Properties.Remove('onPremisesSyncEnabled')
            }
        }


        # Create custom object
        $groupDetails = [PSCustomObject]@{
            Id = $group.Id
            DisplayName = $group.DisplayName
            DisplayNameLink = "<a href=#$($group.id)>$($group.DisplayName)</a>"
            Type = $groupType
            Visibility = $group.Visibility
            RoleAssignable = $group.IsAssignableToRole
            SecurityEnabled = $group.SecurityEnabled
            OnPrem = $group.OnPremisesSyncEnabled
            Description = $group.Description
            Dynamic = $group.dynamic
            MembershipRule = $group.MembershipRule
            EntraRoles  = $RoleCount
            EntraRolePrivilegedCount = $RolePrivilegedCount
            EntraRoleDetails = $roleDetails
            GroupCAPsDetails = $groupCAPs
            CAPs = $CAPCount
            AzureRoles = $AzureRoleCount
            AzureRoleDetails = $azureRoleDetails
            AppRoles = $AppRoleAssignments.count
            AppRolesDetails = $AppRoleAssignments
            Users = $MemberUserCount
            Userdetails = $memberuser
            Guests = $GuestsCount
            PIM = $PIM
            NestedGroups = $membergroup.count
            NestedGroupsDetails = $membergroup
            NestedInGroups = $GroupNestedIn.count
            NestedInGroupsDetails = $GroupNestedIn
            NestedInGroupsById = $NestedInGroupsById
            PfGOwnedGroupsDetails = $PfGOwnedGroups
            PfGOwnedGroupsById = $PfGOwnedGroupsById
            AuUnits = $GroupAdminUnits.count
            AuUnitsDetails = $GroupAdminUnits
            SPCount = $memberSP.count
            MemberSpDetails = $memberSpDetails
            Devices = $memberdevices.count
            DevicesDetails = $memberdevices
            DirectOwners = @($owneruser).count + @($ownersp).count + @($OwnerGroup).count
            NestedOwners = 0 #Will be adjusted in port-processing
            OwnerUserDetails = $owneruser
            OwnerGroupDetails = $OwnerGroup
            OwnersSynced = $ownersynced
            ownerSpDetails = $ownerSpDetails
            BaseOwnerUserDetails = $owneruser       #Used for nesting calculations
            BaseOwnerSpDetails   = $ownerSpDetails  #Used for nesting calculations
            InheritedHighValue = 0
            Protected = $Protected
            NestedOwnerUserDetails = [System.Collections.Generic.List[object]]::new()
            NestedOwnerSPDetails = @()
            UsedNestedGroupIds = @()
            Risk = [math]::Ceiling($ImpactScore * $LikelihoodScore)
            Impact = [math]::Round($ImpactScore,1)
            ImpactOrg = [math]::Round($ImpactScore) #Will be required in the user script
            Likelihood = [math]::Round($LikelihoodScore,1)
            BaseLikelihood = [math]::Round($LikelihoodScore,1) #Used for nesting calculations
            Warnings = $Warnings
        }
		[void]$AllGroupsDetails.Add($groupDetails)


    }

    $PmDataProcessing.Stop()
    ########################################## SECTION: POST-PROCESSING ##########################################
    $PmDataPostProcessing = [System.Diagnostics.Stopwatch]::StartNew()
    write-host "[*] Post-processing group nesting"

    # Create a hashtable for faster group lookup by ID (used throughout post-processing)
    $GroupLookup = @{}
    foreach ($group in $AllGroupsDetails) {
        $GroupLookup[$group.Id] = $group
    }

    #Additional helper HT for faster post-processing
    $GroupLookup2 = @{}
    foreach ($group in $AllGroupsDetails) {
        $GroupLookup2[$group.Id] = [PSCustomObject]@{
            Id                 = $group.Id
            Protected        = $group.Protected
            Warnings = $group.Warnings
            NestedOwnerUserDetails = $group.NestedOwnerUserDetails
            NestedOwners = $group.NestedOwners
            OwnersSynced = $group.OwnersSynced
            NestedOwnerSPDetails = $group.NestedOwnerSPDetails
            Likelihood = $group.Likelihood
            Risk = $group.Risk
            Impact = $group.Impact
        }
    }

    # Pre-initialize the property once for all parent groups
    foreach ($g in $GroupLookup.Values) {
        if (-not $g.PSObject.Properties.Match('UsedNestedGroupIdsSet')) {
            $g.UsedNestedGroupIdsSet = [System.Collections.Generic.HashSet[string]]::new()
        }
    }

    # Reprocessing nested groups in groups which give access to potential critical ressources -> Nested group is adjusted
    # Note: Nested groups do not inherit AppRoles
    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "Processing $($NestedGroupsHighvalue.Count) high value groups with nestings"
    # Tracks already processed groupID→targetID combinations
    $processedGroupHighValuePairs = New-Object System.Collections.Generic.HashSet[string]

    foreach ($highValueGroup in $NestedGroupsHighvalue) {

        $targetIds = $highValueGroup.TargetGroups -split ','

        foreach ($targetIdRaw in $targetIds) {
            $targetId = $targetIdRaw.Trim()

            # Skip self-nesting
            if ($highValueGroup.GroupID -eq $targetId) { continue }

            # Deduplicate highValueGroup → targetId
            $pairKey = "$($highValueGroup.GroupID)|$targetId"
            if ($processedGroupHighValuePairs.Contains($pairKey)) { continue }
            $null = $processedGroupHighValuePairs.Add($pairKey)

            $group = $GroupLookup[$targetId]
            if (-not $group) { continue }

            # Adjust impact + risk
            $group.Impact += [math]::Round($highValueGroup.Score, 1)
            $group.Risk = [math]::Ceiling($group.Impact * $group.Likelihood)

            # Add role/CAP counts
            if ($highValueGroup.CAPs)       { $group.CAPs       += $highValueGroup.CAPs }
            if ($highValueGroup.EntraRoles) { $group.EntraRoles += $highValueGroup.EntraRoles }
            if ($highValueGroup.AzureRoles) { $group.AzureRoles += $highValueGroup.AzureRoles }

            # Update owned group (fast lookup through)
            if ($group.PfGOwnedGroupsById.ContainsKey($highValueGroup.GroupID)) {
                $ownedGroup = $group.PfGOwnedGroupsById[$highValueGroup.GroupID]
                if ($highValueGroup.CAPs)       { $ownedGroup.CAPs       += $highValueGroup.CAPs }
                if ($highValueGroup.EntraRoles) { $ownedGroup.EntraRoles += $highValueGroup.EntraRoles }
                if ($highValueGroup.AzureRoles) { $ownedGroup.AzureRoles += $highValueGroup.AzureRoles }
            }

            # Update parent group (fast lookup through HT)
            if ($group.NestedInGroupsById.ContainsKey($highValueGroup.GroupID)) {
                $parentGroup = $group.NestedInGroupsById[$highValueGroup.GroupID]
                if ($highValueGroup.CAPs)       { $parentGroup.CAPs       += $highValueGroup.CAPs }
                if ($highValueGroup.EntraRoles) { $parentGroup.EntraRoles += $highValueGroup.EntraRoles }
                if ($highValueGroup.AzureRoles) { $parentGroup.AzureRoles += $highValueGroup.AzureRoles }
            }

            # Append warning
            $message = $highValueGroup.Message
            if ([string]::IsNullOrWhiteSpace($group.Warnings)) {
                $group.Warnings = $message
            } elseif ($group.Warnings -notmatch [regex]::Escape($message)) {
                $group.Warnings += " / $message"
            }

            $group.InheritedHighValue += 1
        }
    }


    $GroupsWithNestings = $AllGroupsDetails | Where-Object { $_.NestedGroups -ge 1 }

    $GroupsWithNestingsCount = $($GroupsWithNestings.Count)
    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "Processing $GroupsWithNestingsCount groups with nesting"
    $StatusUpdateInterval = [Math]::Max([Math]::Floor($GroupsWithNestingsCount / 10), 1)
    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "Status: Processing group 1 of $GroupsWithNestingsCount (updates every $StatusUpdateInterval groups)..."
    $ProgressCounter = 0


    #Reprocessing groups which have a nested group to include their owners  -> Parent group is adjusted
   # Pre-create hash sets for faster containment checks
   foreach ($Group in $GroupsWithNestings) {
        $ProgressCounter++

        # Display status based on the objects numbers (slightly improves performance)
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $GroupsWithNestingsCount) {
            Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "[*] Status: Processing group $ProgressCounter of $GroupsWithNestingsCount ..."
        }


        # Step 1: Expand nested groups
        $allNestedGroups = Expand-NestedGroups-Cached -StartGroup $Group -GroupLookup $GroupLookup2 -CallerPSCmdlet $PSCmdlet
        $targetGroup = $GroupLookup[$Group.Id]


        # Step 2: Aggregate owners from nested groups

        foreach ($match in $allNestedGroups) {
            $matchingGroup = $GroupLookup[$match.Id]
            if (-not $matchingGroup) { continue }
            # Risky nesting warning
            if ($targetGroup.Protected -and -not $matchingGroup.Protected) {
                if ($targetGroup.Warnings -notcontains "Protected group has nested / is owned by unprotected group") {
                    $targetGroup.Warnings += " / Protected group has nested / is owned by unprotected group"
                }
            }

            # Owner aggregation
            if ($matchingGroup.DirectOwners -ge 1) {
                $userOwners = $matchingGroup.BaseOwnerUserDetails
                $spOwners   = $matchingGroup.BaseOwnerSpDetails

                if ($userOwners.Count -ge 1) {
                    $targetGroup.NestedOwnerUserDetails.AddRange($userOwners)

                    # Count on-prem owners only once
                    $onPremCount = 0
                    foreach ($u in $userOwners) {
                        if ($u.onPremisesSyncEnabled) { $onPremCount++ }
                    }
                    $targetGroup.NestedOwners += $userOwners.Count
                    $targetGroup.OwnersSynced += $onPremCount
                }

                if ($spOwners.Count -ge 1) {
                    $targetGroup.NestedOwnerSPDetails += $spOwners
                    $targetGroup.NestedOwners += $spOwners.Count
                }
            }

            # Accumulate likelihood score
            $baseLikelihood = $matchingGroup.BaseLikelihood
            if ($null -ne $baseLikelihood) {
                $targetGroup.Likelihood += [math]::Round($baseLikelihood, 1)
            }
        }

        # Finalize scores: round once and recalculate risk
        $targetGroup.Likelihood = [math]::Round($targetGroup.Likelihood, 1)
        $targetGroup.Risk = [math]::Ceiling($targetGroup.Likelihood * $targetGroup.Impact)
    }


    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "Processed all groups with nestings"

    $PmDataPostProcessing.Stop()
    ########################################## SECTION: OUTPUT DEFINITION ##########################################
    $PmGeneratingDetails = [System.Diagnostics.Stopwatch]::StartNew()

    write-host "[*] Generating Details Section"

    #Define output of the main table
    $tableOutput = $AllGroupsDetails | Sort-Object Risk -Descending | select-object DisplayName,DisplayNameLink,Type,SecurityEnabled,RoleAssignable,OnPrem,Dynamic,Visibility,Protected,PIM,AuUnits,DirectOwners,NestedOwners,OwnersSynced,Users,Guests,SPCount,Devices,NestedGroups,NestedInGroups,AppRoles,CAPs,EntraRoles,AzureRoles,Impact,Likelihood,Risk,Warnings

    # Apply result limit for the main table
    if ($LimitResults -and $LimitResults -gt 0) {
        $tableOutput = $tableOutput | Select-Object -First $LimitResults
    }

    #Generate Appendix with Dynamic Groups
    $AppendixDynamic = [System.Collections.Generic.List[object]]::new()
    foreach ($group in $AllGroupsDetails) {
        if ($group.Dynamic -eq $true) {
            $AppendixDynamic.Add([PSCustomObject]@{
                DisplayName     = $group.DisplayName
                Description     = $group.Description
                type            = $group.type
                SecurityEnabled = $group.SecurityEnabled
                AzureRoles      = $group.AzureRoles
                CAPs            = $group.CAPs
                AppRoles        = $group.AppRoles
                MembershipRule  = $group.MembershipRule
                Warnings        = $group.Warnings
            })
        }
    }
    $DynamicGroupsCount = $AppendixDynamic.count

    $mainTable = $tableOutput | select-object -Property @{Name = "DisplayName"; Expression = { $_.DisplayNameLink}},type,SecurityEnabled,RoleAssignable,OnPrem,Dynamic,Visibility,Protected,PIM,AuUnits,DirectOwners,NestedOwners,OwnersSynced,Users,Guests,SPCount,Devices,NestedGroups,NestedInGroups,AppRoles,CAPs,EntraRoles,AzureRoles,Impact,Likelihood,Risk,Warnings
    $mainTableJson  = $mainTable | ConvertTo-Json -Depth 5 -Compress

    $mainTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainTableJson + "`n" + '</script>'


    #Define the apps to be displayed in detail and sort them by risk score
    $details = $AllGroupsDetails | Sort-Object Risk -Descending

    # Apply limit for details
    if ($LimitResults -and $LimitResults -gt 0) {
        $details = $details | Select-Object -First $LimitResults
    }

    #Define stringbuilder to avoid performance impact
    $DetailTxtBuilder = [System.Text.StringBuilder]::new()

    # Progress status in verbose mode
    $detailsCount = $details.count
    $StatusUpdateInterval = [Math]::Max([Math]::Floor($detailsCount / 10), 1)
    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "Status: Processing group 1 of $detailsCount (updates every $StatusUpdateInterval groups)..."
    $ProgressCounter = 0

    foreach ($item in $details) {

        # Progress status in verbose mode
        $ProgressCounter++
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $detailsCount) {
            Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "[*] Status: Processing group $ProgressCounter of $detailsCount ..."
        }

        $ReportingAU = [System.Collections.Generic.List[object]]::new()
        $ReportingRoles = [System.Collections.Generic.List[object]]::new()
        $ReportingAzureRoles = [System.Collections.Generic.List[object]]::new()
        $ReportingCAPs = [System.Collections.Generic.List[object]]::new()
        $AppRoles = [System.Collections.Generic.List[object]]::new()
        $OwnerUser = [System.Collections.Generic.List[object]]::new()
        $OwnerGroups = [System.Collections.Generic.List[object]]::new()
        $OwnerSP = [System.Collections.Generic.List[object]]::new()
        $NestedOwnerUser = [System.Collections.Generic.List[object]]::new()
        $NestedOwnerSP = [System.Collections.Generic.List[object]]::new()
        $NestedGroups = [System.Collections.Generic.List[object]]::new()
        $NestedUsers = [System.Collections.Generic.List[object]]::new()
        $NestedSP = [System.Collections.Generic.List[object]]::new()
        $NestedDevices = [System.Collections.Generic.List[object]]::new()
        $NestedInGroups = [System.Collections.Generic.List[object]]::new()
        $OwnedGroups = [System.Collections.Generic.List[object]]::new()

        [void]$DetailTxtBuilder.AppendLine("#" * 120)

        ############### HEADER
        $ReportingGroupInfo = [pscustomobject]@{
            "Group Name" = $($item.DisplayName)
            "Group ObjectID" = $($item.Id)
            "Type" = $($item.Type)
            "SecurityEnabled" = $($item.SecurityEnabled)
            "Protected" = $($item.Protected)
            "Synced from on-prem" = $($item.OnPrem)
            "RiskScore" = $($item.Risk)
        }
        if ($item.Dynamic) {
            $ReportingGroupInfo | Add-Member -NotePropertyName DynamicRule -NotePropertyValue $item.MembershipRule
        }

        if ($item.Warnings -ne '') {
            $ReportingGroupInfo | Add-Member -NotePropertyName Warnings -NotePropertyValue $item.Warnings
        }

        [void]$DetailTxtBuilder.AppendLine(($ReportingGroupInfo | Out-String))

        ############### Administrative Units
        if (@($item.AuUnitsDetails).Count -ge 1) {
            foreach ($object in $item.AuUnitsDetails) {
                [void]$ReportingAU.Add([pscustomobject]@{
                    "Administrative Unit"         = $object.Displayname
                    "IsMemberManagementRestricted" = $object.IsMemberManagementRestricted
                })
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Administrative Units")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAU | Out-String))
        }

        ############### Entra Roles
        if (@($item.EntraRoleDetails).count -ge 1) {
            foreach ($object in $item.EntraRoleDetails) {
                [void]$ReportingRoles.Add([pscustomobject]@{
                    "Role name"   = $object.DisplayName
                    "Assignment"  = $object.AssignmentType
                    "Tier Level"  = $object.RoleTier
                    "Privileged"  = $object.isPrivileged
                    "Builtin"     = $object.IsBuiltin
                    "Scoped to"   = "$($object.ScopeResolved.DisplayName) ($($object.ScopeResolved.Type))"
                })
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Entra Role Assignments")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingRoles | Out-String))
        }

        ############### Azure Roles
        if (@($item.AzureRoleDetails).Count -ge 1) {
            foreach ($role in $item.AzureRoleDetails) {
                [void]$ReportingAzureRoles.Add([pscustomobject]@{
                    "Role name"   = $role.RoleName
                    "Assignment"  = $role.AssignmentType
                    "RoleType"    = $role.RoleType
                    "Tier Level"  = $role.RoleTier
                    "Conditions"  = $role.Conditions
                    "Scoped to"   = $role.Scope
                })
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Azure IAM assignments")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAzureRoles | Out-String))
        }

        ############### CAPs
        if (@($item.GroupCAPsDetails).Count -ge 1) {
            $ReportingCAPsRaw = [System.Collections.Generic.List[object]]::new()

            foreach ($object in $item.GroupCAPsDetails) {
                $txtObj = [pscustomobject]@{
                    CAPName     = $object.CAPName
                    Usage       = $object.CAPExOrIn
                    Status      = $object.CAPStatus
                }

                [void]$ReportingCAPsRaw.Add($txtObj)

                [void]$ReportingCAPs.Add([pscustomobject]@{
                    CAPName = "<a href=ConditionalAccessPolicies_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.Id)>$($object.CAPName)</a>"
                    Usage   = $object.CAPExOrIn
                    Status  = $object.CAPStatus
                })
            }

            $formattedText = Format-ReportSection -Title "Linked Conditional Access Policies" `
            -Objects $ReportingCAPsRaw `
            -Properties @("CAPName", "Usage", "Status") `
            -ColumnWidths @{ CAPName = 50; Usage = 9; Status = 8}

            [void]$DetailTxtBuilder.AppendLine($formattedText)
        }

        ############### App Roles
        if (@($item.AppRolesDetails).Count -ge 1) {
            $AppRolesRaw = [System.Collections.Generic.List[object]]::new()

            foreach ($object in $item.AppRolesDetails) {
                $appObj = [pscustomobject]@{
                    UsedIn     = $object.ResourceDisplayName
                    UsedInLink = "<a href=EnterpriseApps_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.ResourceId)>$($object.ResourceDisplayName)</a>"
                    AppRoleId  = $object.AppRoleId
                }
                [void]$AppRolesRaw.Add($appObj)
            }

            # Output for TXT report
            $formattedText = Format-ReportSection -Title "App Roles" `
            -Objects $AppRolesRaw `
            -Properties @("UsedIn", "AppRoleId") `
            -ColumnWidths @{ UsedIn = 40; AppRoleId = 40 }

            [void]$DetailTxtBuilder.AppendLine($formattedText)

            # Rebuild for HTML report
            foreach ($obj in $AppRolesRaw) {
                [void]$AppRoles.Add([pscustomobject]@{
                    UsedInApp = $obj.UsedInLink
                    AppRoleId = $obj.AppRoleId
                })
            }
        }

        ############### Owners (Users)
        if (@($item.OwnerUserDetails).Count -ge 1) {
            # Initialize list for raw user data
            $OwnerUserRaw = [System.Collections.Generic.List[object]]::new()

            foreach ($object in $item.OwnerUserDetails) {
                $userDetails = $AllUsersBasicHT[$object.id]
                if (-not $userDetails.onPremisesSyncEnabled) { $userDetails.onPremisesSyncEnabled = "False" }

                # Add raw user data to the list
                $userObj = [pscustomobject]@{
                    "AssignmentType" = $object.AssignmentType
                    "Username" = $userDetails.userPrincipalName
                    "UsernameLink" = "<a href=Users_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($userDetails.id)>$($userDetails.userPrincipalName)</a>"
                    "Enabled" = $userDetails.accountEnabled
                    "Type" = $userDetails.userType
                    "Synced" = $userDetails.onPremisesSyncEnabled
                }

                [void]$OwnerUserRaw.Add($userObj)
            }

            # Output for TXT report
            $formattedText = Format-ReportSection -Title "Nested Members: Users" `
            -Objects $OwnerUserRaw `
            -Properties @("AssignmentType", "Username", "Enabled", "Type", "Synced") `
            -ColumnWidths @{ AssignmentType = 14; Username = 50; Enabled = 7; Type = 7; Synced = 6}

            [void]$DetailTxtBuilder.AppendLine($formattedText)

            # Rebuild for HTML report
            $OwnerUserHtml = [System.Collections.Generic.List[object]]::new()

            foreach ($obj in $OwnerUserRaw) {
                # Add only the necessary HTML fields
                [void]$OwnerUserHtml.Add([pscustomobject]@{
                    AssignmentType  = $obj.AssignmentType
                    Username        = $obj.UsernameLink
                    Enabled         = $obj.Enabled
                    Type            = $obj.Type
                    Synced          = $obj.Synced
                })
            }

            # Final assignment for HTML report
            $OwnerUser = $OwnerUserHtml
        }

        ############### Owners (Groups) (only possible with PIM for Groups)
        if (@($item.OwnerGroupDetails).count -ge 1) {
            $OwnerGroupsRaw = [System.Collections.Generic.List[object]]::new()

            foreach ($object in $item.OwnerGroupDetails) {
                $groupDetails = $AllGroupsHT[$object.id]
                $groupObj = [pscustomobject]@{
                    "AssignmentType" = $($object.AssignmentType)
                    "Displayname" = $($groupDetails.displayName)
                    "DisplayNameLink" = "<a href=#$($object.id)>$($groupDetails.displayName)</a>"
                    "SecurityEnabled" = $($groupDetails.SecurityEnabled)
                    "IsAssignableToRole" = $($groupDetails.IsAssignableToRole)
                }
                [void]$OwnerGroupsRaw.Add($groupObj)
            }

            # Build TXT
            $formattedText = Format-ReportSection -Title "Eligible Owners (Groups)" `
            -Objects $OwnerGroupsRaw `
            -Properties @("AssignmentType", "Displayname", "SecurityEnabled", "IsAssignableToRole") `
            -ColumnWidths @{ AssignmentType = 15; Displayname = 60; SecurityEnabled = 16; IsAssignableToRole = 19 }
            [void]$DetailTxtBuilder.AppendLine($formattedText)

            #Rebuild for HTML report
            foreach ($obj in $OwnerGroups) {
                [void]$OwnerGroups.Add([pscustomobject]@{
                    AssignmentType      = $obj.AssignmentType
                    DisplayName         = $obj.DisplayNameLink
                    SecurityEnabled     = $obj.SecurityEnabled
                    IsAssignableToRole  = $obj.IsAssignableToRole
                })
            }
        }

        ############### Owners (SP)
        if (@($item.ownerSpDetails).Count -ge 1) {
            $OwnerSPRaw = [System.Collections.Generic.List[object]]::new()

            foreach ($object in $item.ownerSpDetails) {
                $ownerObj = [pscustomobject]@{
                    DisplayName     = $object.displayName
                    DisplayNameLink = "<a href=EnterpriseApps_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.displayName)</a>"
                    Type            = $object.SPType
                    Org             = $object.publisherName
                    Foreign         = $object.Foreign
                    DefaultMS       = $object.DefaultMS
                }
                [void]$OwnerSPRaw.Add($ownerObj)
            }

            # Build TXT
            $formattedText = Format-ReportSection -Title "Direct Owners (Service Principals" `
            -Objects $OwnerSPRaw `
            -Properties @("DisplayName", "Type", "Org", "Foreign", "DefaultMS") `
            -ColumnWidths @{ DisplayName = 45; Type = 20; Org = 45; Foreign = 8; DefaultMS = 10 }
            [void]$DetailTxtBuilder.AppendLine($formattedText)

            # Rebuild for HTML report
            foreach ($obj in $OwnerSPRaw) {
                [void]$OwnerSP.Add([pscustomobject]@{
                    DisplayName  = $obj.DisplayNameLink
                    Type         = $obj.Type
                    Organization = $obj.Org
                    Foreign      = $obj.Foreign
                    DefaultMS    = $obj.DefaultMS
                })
            }
        }

        ############### Nested Owners (Users)
        if (@($item.NestedOwnerUserDetails).count -ge 1) {
            $NestedOwnerUserHtml = [System.Collections.Generic.List[object]]::new()
            foreach ($object in $($item.NestedOwnerUserDetails)) {
                $userDetails = $AllUsersBasicHT[$object.id]
                  if (-not $userDetails.onPremisesSyncEnabled) { $userDetails.onPremisesSyncEnabled = "False" }

                $userObj = [pscustomobject]@{
                    "AssignmentType" = $($object.AssignmentType)
                    "Username" = $($userDetails.userPrincipalName)
                    "UsernameLink" = "<a href=Users_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($userDetails.id)>$($userDetails.userPrincipalName)</a>"
                    "Enabled" = $($userDetails.accountEnabled)
                    "Type" = $($userDetails.userType)
                    "Synced" = $($userDetails.onPremisesSyncEnabled)
                }

                [void]$NestedOwnerUser.Add($userObj)

                [void]$NestedOwnerUserHtml.Add([pscustomobject]@{
                    AssignmentType  = $userObj.AssignmentType
                    Username        = $userObj.UsernameLink
                    Enabled         = $userObj.Enabled
                    Type            = $userObj.Type
                    Synced          = $userObj.Synced
                })

            }

            # Build TXT report
            $formattedText = Format-ReportSection -Title "Nested Members: Users" `
            -Objects $NestedOwnerUser `
            -Properties @("AssignmentType", "Username", "Enabled", "Type", "Synced") `
            -ColumnWidths @{ AssignmentType = 14; Username = 50; Enabled = 7; Type = 7; Synced = 6}

            [void]$DetailTxtBuilder.AppendLine($formattedText)

            #Rebuild for HTML report
            $NestedOwnerUser = $NestedOwnerUserHtml
        }

        ############### Nested Owners (SP)
        if (@($item.NestedOwnerSPDetails).Count -ge 1) {

            foreach ($object in $item.NestedOwnerSPDetails) {
                $spObj = [pscustomobject]@{
                    "DisplayName"  = $object.DisplayName
                    "Type"         = $object.SPType
                    "Org"          = $object.PublisherName
                    "Foreign"      = $object.Foreign
                    "DefaultMS"    = $object.DefaultMS
                }
                [void]$NestedOwnerSP.Add($spObj)
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Nested Owners (Service Principals)")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($NestedOwnerSP | Format-Table | Out-String))
        }

        ############### Nested Groups
        if (@($item.NestedGroupsDetails).Count -ge 1) {
            $NestedGroupsRaw = [System.Collections.Generic.List[object]]::new()

            foreach ($object in $item.NestedGroupsDetails) {
                $groupDetails = $AllGroupsHT[$object.id]

                $rawObj = [pscustomobject]@{
                    AssignmentType     = $object.AssignmentType
                    DisplayName        = $groupDetails.displayName
                    DisplayNameLink    = "<a href=#$($object.id)>$($groupDetails.displayName)</a>"
                    SecurityEnabled    = $groupDetails.SecurityEnabled
                    IsAssignableToRole = $groupDetails.IsAssignableToRole
                }

                [void]$NestedGroupsRaw.Add($rawObj)
            }

            # Sort by role assignability & security for both TXT and HTML
            $SortedNestedGroups = $NestedGroupsRaw | Sort-Object {
                $priority = 0
                if (-not $_.IsAssignableToRole) { $priority += 1 }
                if (-not $_.SecurityEnabled)   { $priority += 1 }
                return $priority
            }

            # Build TXT
            $formattedText = Format-ReportSection -Title "Nested Members: Nested Groups" `
            -Objects $SortedNestedGroups `
            -Properties @("AssignmentType", "Displayname", "SecurityEnabled", "IsAssignableToRole") `
            -ColumnWidths @{ AssignmentType = 15; Displayname = 60; SecurityEnabled = 16; IsAssignableToRole = 19 }
            [void]$DetailTxtBuilder.AppendLine($formattedText)

            # Limit for HTML
            $ExceedsLimit = $SortedNestedGroups.Count -gt $HTMLNestedGroupsLimit
            $GroupsToShow = if ($ExceedsLimit) { $SortedNestedGroups[0..($HTMLNestedGroupsLimit - 1)] } else { $SortedNestedGroups }

            foreach ($obj in $GroupsToShow) {
                [void]$NestedGroups.Add([pscustomobject]@{
                    AssignmentType     = $obj.AssignmentType
                    DisplayName        = $obj.DisplayNameLink
                    SecurityEnabled    = $obj.SecurityEnabled
                    IsAssignableToRole = $obj.IsAssignableToRole
                })
            }

            if ($ExceedsLimit) {
                [void]$NestedGroups.Add([pscustomobject]@{
                    AssignmentType     = "-"
                    DisplayName        = "Showing first $HTMLNestedGroupsLimit of $($SortedNestedGroups.Count) groups (see TXT for full list)"
                    SecurityEnabled    = "-"
                    IsAssignableToRole = "-"
                })
            }
        }




        ############### Nested Users
        if (@($item.UserDetails).Count -ge 1) {
            $ObjectCounter = 0
            $NestedUsersTXT = [System.Collections.Generic.List[object]]::new()

            foreach ($object in $item.UserDetails) {
                $userDetails = $AllUsersBasicHT[$object.id]

                   if (-not $userDetails.onPremisesSyncEnabled) { $userDetails.onPremisesSyncEnabled = "False" }

                $linkedUsername = "<a href=Users_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($userDetails.id)>$($userDetails.userPrincipalName)</a>"

                # Plain for TXT
                $txtObj = [pscustomobject]@{
                    AssignmentType  = $object.AssignmentType
                    Username        = $userDetails.userPrincipalName
                    Enabled         = $userDetails.accountEnabled
                    Type            = $userDetails.userType
                    Synced          = $userDetails.onPremisesSyncEnabled
                }

                # Linked for HTML
                $htmlObj = [pscustomobject]@{
                    AssignmentType  = $object.AssignmentType
                    Username        = $linkedUsername
                    Enabled         = $userDetails.accountEnabled
                    Type            = $userDetails.userType
                    Synced          = $userDetails.onPremisesSyncEnabled
                }

                if ($ObjectCounter -lt $HTMLMemberLimit) {
                    [void]$NestedUsers.Add($htmlObj)
                } elseif ($ObjectCounter -eq $HTMLMemberLimit) {
                    [void]$NestedUsers.Add([pscustomobject]@{
                        AssignmentType = "-"
                        Username       = "List limited to $HTMLMemberLimit users. See TXT Report for full list"
                        Enabled        = "-"
                        Type           = "-"
                        Synced         = "-"
                    })
                }

                [void]$NestedUsersTXT.Add($txtObj)
                $ObjectCounter++
            }

            $formattedText = Format-ReportSection -Title "Nested Members: Users" `
            -Objects $NestedUsersTXT `
            -Properties @("AssignmentType", "Username", "Enabled", "Type", "Synced") `
            -ColumnWidths @{ AssignmentType = 14; Username = 50; Enabled = 7; Type = 7; Synced = 6}

            [void]$DetailTxtBuilder.AppendLine($formattedText)

        }

        ############### Nested SP
        if (@($item.MemberSpDetails).Count -ge 1) {
            $NestedSPRaw = [System.Collections.Generic.List[object]]::new()

            foreach ($object in $item.MemberSpDetails) {
                if ($object.SPType -eq "Application") {
                    $DisplayNameLink = "<a href=EnterpriseApps_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.displayName)</a>"
                    $org = $object.publisherName
                } else {
                    $DisplayNameLink = "<a href=ManagedIdentities_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.displayName)</a>"
                    $org = "-"
                }

                $rawObj = [pscustomobject]@{
                    DisplayName     = $object.displayName
                    DisplayNameLink = $DisplayNameLink
                    Type            = $object.SPType
                    Org             = $org
                    Foreign         = $object.Foreign
                    DefaultMS       = $object.DefaultMS
                }

                [void]$NestedSPRaw.Add($rawObj)
            }

            # Build TXT
            $formattedText = Format-ReportSection -Title "Nested Members: Service Principals" `
            -Objects $NestedSPRaw `
            -Properties @("DisplayName", "Type", "Org", "Foreign", "DefaultMS") `
            -ColumnWidths @{ DisplayName = 45; Type = 20; Org = 45; Foreign = 8; DefaultMS = 10 }
            [void]$DetailTxtBuilder.AppendLine($formattedText)


            foreach ($obj in $NestedSPRaw) {
                [void]$NestedSP.Add([pscustomobject]@{
                    DisplayName   = $obj.DisplayNameLink
                    Type          = $obj.Type
                    Organization  = $obj.Org
                    Foreign       = $obj.Foreign
                    DefaultMS     = $obj.DefaultMS
                })
            }
        }

        ############### Nested Devices
        if (@($item.DevicesDetails).count -ge 1) {
            $NestedDevicesRaw = [System.Collections.Generic.List[object]]::new()
            foreach ($object in $item.DevicesDetails) {
                $DeviceDetails = $Devices[$object.id]

                $rawObj = [pscustomobject]@{
                    Displayname   = $DeviceDetails.displayName
                    Type          = $DeviceDetails.trustType
                    OS            = "$($DeviceDetails.operatingSystem) / $($DeviceDetails.operatingSystemVersion)"
                }

                [void]$NestedDevicesRaw.Add($rawObj)
            }

            # Build TXT
            $formattedText = Format-ReportSection -Title "Nested Members: Devices" `
            -Objects $NestedDevicesRaw `
            -Properties @("Displayname", "Enabled", "Type", "Manufacturer", "OS") `
            -ColumnWidths @{ Displayname = 30; Enabled = 8; Type = 15; Manufacturer = 26; OS = 40 }
            [void]$DetailTxtBuilder.AppendLine($formattedText)

            # Limit HTML output
            $ExceedsLimit = $NestedDevicesRaw.Count -gt $HTMLMemberLimit
            if ($ExceedsLimit -and $HTMLMemberLimit -gt 0) {
                $DevicesToShow = $NestedDevicesRaw[0..($HTMLMemberLimit - 1)]
            } else {
                $DevicesToShow = $NestedDevicesRaw
            }

            foreach ($obj in $DevicesToShow) {
                [void]$NestedDevices.Add([pscustomobject]@{
                    Displayname   = $obj.Displayname
                    Type          = $obj.Type
                    OS            = $obj.OS
                })
            }

            if ($ExceedsLimit) {
                [void]$NestedDevices.Add([pscustomobject]@{
                    Displayname   = "List limited to $HTMLMemberLimit users. See TXT Report for full list"
                    Type          = "-"
                    OS            = "-"
                })
            }
        }

        ############### Nested in Groups
        if (@($item.NestedInGroupsDetails).count -ge 1) {
            $NestedInGroupsRaw = [System.Collections.Generic.List[object]]::new()

            foreach ($object in $item.NestedInGroupsDetails) {
                $groupDetails = $AllGroupsHT[$object.id]

                $rawObj = [pscustomobject]@{
                    AssignmentType     = $object.AssignmentType
                    Displayname        = $groupDetails.DisplayName
                    DisplayNameLink    = "<a href=#$($object.id)>$($groupDetails.displayName)</a>"
                    SecurityEnabled    = $groupDetails.SecurityEnabled
                    IsAssignableToRole = $groupDetails.IsAssignableToRole
                    EntraRoles         = $object.EntraRoles
                    AzureRoles         = $object.AzureRoles
                    CAPs               = $object.CAPs
                }

                [void]$NestedInGroupsRaw.Add($rawObj)
            }

            # Build TXT
            $formattedText = Format-ReportSection -Title "Member Of: Nested in Groups (Transitive)" `
            -Objects $NestedInGroupsRaw `
            -Properties @("AssignmentType", "Displayname", "SecurityEnabled", "IsAssignableToRole", "EntraRoles", "AzureRoles", "CAPs") `
            -ColumnWidths @{ AssignmentType = 15; Displayname = 45; SecurityEnabled = 16; IsAssignableToRole = 19; EntraRoles = 11; AzureRoles = 11; CAPs = 4 }
            [void]$DetailTxtBuilder.AppendLine($formattedText)

            # Sort only for HTML
            $SortedNestedGroups = $NestedInGroupsRaw | Sort-Object {
                if ($_.EntraRoles -or $_.AzureRoles -or $_.CAPs) { 0 } else { 1 }
            }

            # Apply HTML limit
            $ExceedsLimit = $SortedNestedGroups.Count -gt $HTMLNestedGroupsLimit
            if ($ExceedsLimit -and $HTMLNestedGroupsLimit -gt 0) {
                $GroupsToShow = $SortedNestedGroups[0..($HTMLNestedGroupsLimit - 1)]
            } else {
                $GroupsToShow = $SortedNestedGroups
            }

            foreach ($obj in $GroupsToShow) {
                [void]$NestedInGroups.Add([pscustomobject]@{
                    AssignmentType     = $obj.AssignmentType
                    DisplayName        = $obj.DisplayNameLink
                    SecurityEnabled    = $obj.SecurityEnabled
                    IsAssignableToRole = $obj.IsAssignableToRole
                    EntraRoles         = $obj.EntraRoles
                    AzureRoles         = $obj.AzureRoles
                    CAPs               = $obj.CAPs
                })
            }

            if ($ExceedsLimit) {
                [void]$NestedInGroups.Add([pscustomobject]@{
                    AssignmentType     = "-"
                    DisplayName        = "Showing first $HTMLNestedGroupsLimit of $($SortedNestedGroups.Count) groups (see TXT for full list)"
                    SecurityEnabled    = "-"
                    IsAssignableToRole = "-"
                    EntraRoles         = "-"
                    AzureRoles         = "-"
                    CAPs               = "-"
                })
            }
        }


        ############### Owns another Group (Pim for Groups)
        if (@($item.PfGOwnedGroupsDetails).Count -ge 1) {
            $OwnedGroupsRaw = [System.Collections.Generic.List[object]]::new()
            foreach ($object in $item.PfGOwnedGroupsDetails) {
                [void]$OwnedGroupsRaw.Add([pscustomobject]@{
                    AssignmentType      = $object.AssignmentType
                    Displayname         = $object.displayName
                    DisplayNameLink     = "<a href=#$($object.id)>$($object.displayName)</a>"
                    SecurityEnabled     = $object.SecurityEnabled
                    IsAssignableToRole  = $object.IsAssignableToRole
                    EntraRoles          = $object.EntraRoles
                    AzureRoles          = $object.AzureRoles
                    CAPs                = $object.CAPs
                })
            }

            $formattedText = Format-ReportSection -Title "Owned Groups (PIM for Groups)" `
            -Objects $OwnedGroupsRaw `
            -Properties @("AssignmentType", "Displayname", "SecurityEnabled", "IsAssignableToRole", "EntraRoles", "AzureRoles", "CAPs") `
            -ColumnWidths @{ AssignmentType = 15; Displayname = 60; SecurityEnabled = 16; IsAssignableToRole = 19; EntraRoles = 11; AzureRoles = 11; CAPs = 4 }

            [void]$DetailTxtBuilder.AppendLine($formattedText)


            # Rebuild for HTML report
            foreach ($obj in $OwnedGroupsRaw) {
                [void]$OwnedGroups.Add([pscustomobject]@{
                    AssignmentType      = $obj.AssignmentType
                    DisplayName         = $obj.DisplayNameLink
                    SecurityEnabled     = $obj.SecurityEnabled
                    IsAssignableToRole  = $obj.IsAssignableToRole
                    EntraRoles          = $obj.EntraRoles
                    AzureRoles          = $obj.AzureRoles
                    CAPs                = $obj.CAPs
                })
            }
        }

        $ObjectDetails = [pscustomobject]@{
            "Object Name"     = $item.DisplayName
            "Object ID"       = $item.Id
            "General Information"    = $ReportingGroupInfo
            "Administrative Units" = $ReportingAU
            "Entra ID Roles" = $ReportingRoles
            "Azure Roles" = $ReportingAzureRoles
            "Conditional Access Policies" = $ReportingCAPs
            "Application Roles" = $AppRoles
            "Owners (User)" = $OwnerUser
            "Owners (Groups)" = $OwnerGroups
            "Owners (SP)" = $OwnerSP
            "Nested owners (User)" = $NestedOwnerUser
            "Nested owner (SP)" = $NestedOwnerSP
            "Nested Groups" = $NestedGroups
            "Nested Users" = $NestedUsers
            "Nested SP" = $NestedSP
            "Nested Devices " = $NestedDevices
            "Nested in Groups " = $NestedInGroups
            "Owned Groups (PIM for Groups)" = $OwnedGroups
        }

        [void]$AllObjectDetailsHTML.Add($ObjectDetails)

    }

    $DetailOutputTxt = $DetailTxtBuilder.ToString()


    write-host "[*] Writing Reports"
    write-host ""

    #Define header HTML
    $headerHTML = [pscustomobject]@{
        "Executed in Tenant" = "$($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)"
        "Executed at" = "$StartTimestamp "
        "Execution Warnings" = $GroupScriptWarningList -join ' / '
    }

# Build Detail section as JSON for the HTML Report
$AllObjectDetailsHTML = $AllObjectDetailsHTML | ConvertTo-Json -Depth 5 -Compress
$ObjectsDetailsHEAD = @'
    <h2>Groups Details</h2>
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
Execution Warnings = $($GroupScriptWarningList  -join ' / ')
************************************************************************************************************************
"

    #Define Appendix
$AppendixTitle = "

###############################################################################################################################################
Appendix: Dynamic Groups
###############################################################################################################################################
    "

    $PmGeneratingDetails.Stop()
    $PmWritingReports = [System.Diagnostics.Stopwatch]::StartNew()

    # Prepare HTML output
    $headerHTML = $headerHTML | ConvertTo-Html -Fragment -PreContent "<div id=`"loadingOverlay`"><div class=`"spinner`"></div><div class=`"loading-text`">Loading data...</div></div><nav id=`"topNav`"></nav><h1>$($Title) Enumeration</h1>" -As List -PostContent "<h2>$($Title) Overview</h2>"



    ########################################## SECTION: OUTPUT WRITING ##########################################

    #Write TXT and CSV files
    $headerTXT | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    $tableOutput  |  Format-table DisplayName,type,SecurityEnabled,RoleAssignable,OnPrem,Dynamic,Visibility,Protected,PIM,AuUnits,DirectOwners,NestedOwners,OwnersSynced,Users,Guests,SPCount,Devices,NestedGroups,NestedInGroups,AppRoles,CAPs,EntraRoles,AzureRoles,Impact,Likelihood,Risk,Warnings | Out-File -Width 512 "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    $tableOutput | select-object DisplayName,type,SecurityEnabled,RoleAssignable,OnPrem,Dynamic,Visibility,Protected,PIM,AuUnits,DirectOwners,NestedOwners,OwnersSynced,Users,Guests,SPCount,Devices,NestedGroups,NestedInGroups,AppRoles,CAPs,EntraRoles,AzureRoles,Impact,Likelihood,Risk,Warnings | Export-Csv -Path "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).csv" -NoTypeInformation
    $DetailOutputTxt | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append

    write-host "[+] Details of $($tableOutput.count) groups stored in output files (CSV,TXT,HTML): $outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName)"
    If ($DynamicGroupsCount -gt 0) {
        $AppendixTitle | Out-File -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
        $AppendixDynamic | Out-File -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
        $AppendixDynamicHTML = $AppendixDynamic | ConvertTo-Html -Fragment -PreContent "<h2>Appendix: Dynamic Groups</h2>"
    }

    $PostContentCombined = $GLOBALJavaScript + "`n" + $AppendixDynamicHTML
    #Write HTML
    $Report = ConvertTo-HTML -Body "$headerHTML $mainTableHTML" -Title "$Title enumeration" -Head $GLOBALcss -PostContent $PostContentCombined -PreContent $AllObjectDetailsHTML
    $Report | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).html"

    $PmWritingReports.Stop()
    $PmEndTasks = [System.Diagnostics.Stopwatch]::StartNew()

    #Add information to the enumeration summary
    $M365Count = 0
    $OnPremCount = 0
    $PublicM365 = 0
    $PimOnboarded = 0

    foreach ($group in $AllGroupsDetails) {
        if ($group.Type -eq "M365 Group") {
            $M365Count++
            if ($group.Visibility -eq "Public") {
                $PublicM365++
            }
        }
        if ($group.OnPrem) {
            $OnPremCount++
        }
        if ($group.PIM -eq $true) {
            $PimOnboarded++
        }
    }

    # Store in global var
    $GlobalAuditSummary.Groups.Count = $GroupsTotalCount
    $GlobalAuditSummary.Groups.M365 = $M365Count
    $GlobalAuditSummary.Groups.PublicM365 = $PublicM365
    $GlobalAuditSummary.Groups.OnPrem = $OnPremCount
    $GlobalAuditSummary.Groups.PimOnboarded = $PimOnboarded

    #Dump data for QA checks
    if ($QAMode) {
        $AllGroupsDetails | ConvertTo-Json -Depth 10 | Out-File -FilePath "$outputFolder\QA_AllGroupsDetails.json" -Encoding utf8
    }

    #Convert to Hashtable for faster searches
    $AllGroupsDetailsHT = @{}

    foreach ($group in $AllGroupsDetails) {
        $AllGroupsDetailsHT[$group.Id] = [PSCustomObject]@{
            DisplayName   = $group.DisplayName
            Type = $group.Type
            Visibility = $group.Visibility
            RoleAssignable = $group.RoleAssignable
            SecurityEnabled = $group.SecurityEnabled
            OnPrem = $group.OnPrem
            Dynamic = $group.dynamic
            EntraRoles  = $group.EntraRoles
            CAPs = $group.CAPs
            AzureRoles = $group.AzureRoles
            AppRoles = $group.AppRoles
            Users = $group.Users
            Guests = $group.Guests
            Protected = $group.Protected
            Impact = $group.Impact
            ImpactOrg = $group.ImpactOrg
            Likelihood = $group.Likelihood
            Warnings = $group.Warnings
            EntraRolePrivilegedCount = $group.EntraRolePrivilegedCount
            InheritedHighValue = $group.InheritedHighValue
            DirectOwners = $group.DirectOwners
            NestedOwners = $group.NestedOwners
        }
    }

    Remove-Variable Report
    Remove-Variable DetailOutputTxt
    Remove-Variable tableOutput
    Remove-Variable AllGroupsDetails
    Remove-Variable details

    $PmEndTasks.Stop()
    $PmScript.Stop()

    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "=== Performance Summary ==="
    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message ("Init Tasks:           {0:N2} s" -f $PmInitTasks.Elapsed.TotalSeconds)
    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message ("Data Collection:      {0:N2} s" -f $PmDataCollection.Elapsed.TotalSeconds)
    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message ("Data Processing:      {0:N2} s" -f $PmDataProcessing.Elapsed.TotalSeconds)
    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message ("Post-Processing:      {0:N2} s" -f $PmDataPostProcessing.Elapsed.TotalSeconds)
    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message ("Generating Details:   {0:N2} s" -f $PmGeneratingDetails.Elapsed.TotalSeconds)
    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message ("Writing Reports:      {0:N2} s" -f $PmWritingReports.Elapsed.TotalSeconds)
    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message ("EndTasks:             {0:N2} s" -f $PmEndTasks.Elapsed.TotalSeconds)
    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message ("-------------------------------")
    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message ("Total Script Time:    {0:N2} s" -f $PmScript.Elapsed.TotalSeconds)

    return $AllGroupsDetailsHT
}
