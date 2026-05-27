<#
.SYNOPSIS
   Enumerate App Registrations (including: API Permission (Application), Owner, Secrets, Certificates, 	Access through App Roles etc.).

.DESCRIPTION
   This script will enumerate all App Registrations (including: API Permission (Application), Owner, Secrets, Certificates, Active access through App Roles, App instance property lock).

#>
function Invoke-CheckAppRegistrations {

    ############################## Parameter section ########################
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$OutputFolder = ".",
        [Parameter(Mandatory=$true)][hashtable]$AllGroupsDetails,
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$true)][hashtable]$EnterpriseApps,
        [Parameter(Mandatory=$true)][hashtable]$TenantRoleAssignments,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp
    )

    ############################## Function section ########################
    #Function to deliver detailed info about an object. Since the object type is not always known (Get-MgBetaRoleManagementDirectoryRoleAssignment) the type has to be determined first.
    #The type can be specified to save some GraphAPI calls
    function GetObjectInfo($Object,$type="unknown"){
        if ($type -eq "unknown" -or $type -eq "user" ) {
            $QueryParameters = @{
                '$select' = "DisplayName,UserPrincipalName,UserType,OnPremisesSyncEnabled,AccountEnabled,jobTitle,Department"
            }
            $user = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/users/$Object" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)

            if ($user) {
                If ($Null -eq $User.OnPremisesSyncEnabled) {
                    $onprem = $False
                } else {
                    $onprem = $True
                }
                If ($Null -eq $User.JobTitle) {
                    $JobTitle = "-"
                } else {
                    $JobTitle = $User.JobTitle
                }

                If ($Null -eq $User.Department) {
                    $Department = "-"
                } else {
                    $Department = $User.Department
                }
                [PSCustomObject]@{
                    Type = "User"
                    DisplayName = $User.DisplayName
                    UPN= $User.UserPrincipalName
                    UserType = $User.UserType
                    Enabled = $User.AccountEnabled
                    Onprem = $onprem
                    JobTitle = $JobTitle
                    Department = $Department
                }
            }
        }

        if ($type -eq "unknown" -or $type -eq "group" ) {
            #Takes information about the groups from $AllGroupsDetails parameter
            $MatchingGroup = $AllGroupsDetails[$($Object)]

            if (($MatchingGroup | Measure-Object).count -ge 1) {
                [PSCustomObject]@{
                    Type = "Group"
                    Id = $MatchingGroup.Id
                    DisplayName = $MatchingGroup.DisplayName
                    InheritedHighValue  = $MatchingGroup.InheritedHighValue
                    OnPrem  = $MatchingGroup.OnPrem
                    Users  = $MatchingGroup.Users
                    Guests  = $MatchingGroup.Guests
                    Owners  = $MatchingGroup.DirectOwners + $MatchingGroup.NestedOwners
                    LikelihoodScore  = $MatchingGroup.LikelihoodScore
                }
            }
        }

        if ($type -eq "unknown" -or $type -eq "ServicePrincipal" ) {
            $MatchingEnterpriseApp = $EnterpriseApps[$($Object)]

            if (($MatchingEnterpriseApp | Measure-Object).count -ge 1) {
                [PSCustomObject]@{
                    Type = "ServicePrincipal"
                    Id = $MatchingEnterpriseApp.Id
                    DisplayName = $MatchingEnterpriseApp.DisplayName
                    Foreign = $MatchingEnterpriseApp.Foreign
                    PublisherName = $MatchingEnterpriseApp.PublisherName
                    OwnersCount = $MatchingEnterpriseApp.OwnersCount
                }
            }
        }

        if ($type -eq "Secret" ) {
            if ($null -ne $Object.EndDateTime) {
                if (($Object.EndDateTime - (Get-Date).Date).TotalDays -le 0) {
                    $Expired = $True
                } else {
                    $Expired = $False
                }
            }
            [PSCustomObject]@{
                Type = "Secret"
                DisplayName = $Object.DisplayName
                EndDateTime = $Object.EndDateTime
                Expired = $Expired
                Hint = $Object.Hint
            }

        }

        if ($type -eq "Cert" ) {

            if ($null -ne $Object.EndDateTime) {
                if (($Object.EndDateTime - (Get-Date).Date).TotalDays -le 0) {
                    $Expired = $True
                } else {
                    $Expired = $False
                }
            }
            [PSCustomObject]@{
                Type = "Cert"
                DisplayName = $Object.DisplayName
                EndDateTime = $Object.EndDateTime
                Expired = $Expired
            }
        }
    }


    ############################## Script section ########################

    # Check token and trigger refresh if required
    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    #Define basic variables
    $Title = "AppRegistration"
    $ScriptWarningList = @()
    $AppsWithSecrets = @()
    $AppAuthentication = @()
    $ProgressCounter = 0
    $AllAppRegistrations = [System.Collections.ArrayList]::new()
    $AllObjectDetailsHTML = [System.Collections.ArrayList]::new()
    $AppLikelihoodScore = @{
        "AppBase"                   = 1
        "AppSecret"                 = 5
        "AppCertificate"            = 2
        "AppOwner"          	    = 20
        "AppAdmins"          	    = 10
	    "InternalSPOwner"		    = 5
	    "ExternalSPOwner"		    = 50
	    "GuestAsOwner"		        = 50
    }

    ########################################## SECTION: DATACOLLECTION ##########################################
    # Get Enterprise Apps (to check the permissions)
    write-host "[*] Get App Registrations"
    $QueryParameters = @{
        '$select' = "Id,AppID,DisplayName,SignInAudience,RequiredResourceAccess,ServicePrincipalLockConfiguration,web,KeyCredentials,PasswordCredentials,AppRoles,Spa,Windows,PublicClient,DefaultRedirectUri,isFallbackPublicClient"
    }
    $AppRegistrations = @(Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/applications' -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $AppsTotalCount = $($AppRegistrations.count)
    write-host "[+] Got $AppsTotalCount App registrations"

    #Abort if no apps are present
    if (@($AppRegistrations).count -eq 0) {
        $AllAppRegistrationsHT = @{}
        Return $AllAppRegistrationsHT
    }


    #Get members of Cloud Application Administrator (158c047a-c907-4556-b7ef-446551a6b5f7) with the scope for the Tenant
    $CloudAppAdminTenant = $TenantRoleAssignments.Values | ForEach-Object {$_ | Where-Object { $_.RoleDefinitionId -eq "158c047a-c907-4556-b7ef-446551a6b5f7" -and $_.DirectoryScopeId -eq "/" }} | Select-Object PrincipalId,AssignmentType
    $CloudAppAdminTenantDetails = foreach ($Object in $CloudAppAdminTenant) {
        # Get the object details
        $ObjectDetails = GetObjectInfo $Object.PrincipalId
        # Add the 'Role' property and use passthru to give back the object
        $ObjectDetails | Add-Member -MemberType NoteProperty -Name PrincipalId -Value $Object.PrincipalId
        $ObjectDetails | Add-Member -MemberType NoteProperty -Name AssignmentType -Value $Object.AssignmentType
        $ObjectDetails | Add-Member -MemberType NoteProperty -Name Role -Value 'CloudApplicationAdministrator'
        $ObjectDetails | Add-Member -MemberType NoteProperty -Name Scope -Value 'Tenant' -PassThru
    }

    #Get members of Application Administrator (9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3) with the scope for current the Tenant
    $AppAdminTenant = $TenantRoleAssignments.Values | ForEach-Object {$_ | Where-Object { $_.RoleDefinitionId -eq "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" -and $_.DirectoryScopeId -eq "/" }} | Select-Object PrincipalId,AssignmentType
    $AppAdminTenantDetails = foreach ($Object in $AppAdminTenant) {
        # Get the object details
        $ObjectDetails = GetObjectInfo $Object.PrincipalId
        # Add the 'Role' property and use passthru to give back the object
        $ObjectDetails | Add-Member -MemberType NoteProperty -Name PrincipalId -Value $Object.PrincipalId
        $ObjectDetails | Add-Member -MemberType NoteProperty -Name AssignmentType -Value $Object.AssignmentType
        $ObjectDetails | Add-Member -MemberType NoteProperty -Name Role -Value 'ApplicationAdministrator'
        $ObjectDetails | Add-Member -MemberType NoteProperty -Name Scope -Value 'Tenant' -PassThru
    }

    #Count Admins
    $CloudAppAdminTenantCount = ($CloudAppAdminTenant | Measure-Object).Count
    $AppAdminTenantCount = ($AppAdminTenant | Measure-Object).Count


    Write-Host "[*] Get all owners"
    $Requests = @()
    $AppRegistrations | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    =   "/applications/$($_.id)/owners"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $AppOwnersRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $AppOwnersRaw[$item.id] = $item.response.value
        }
    }


    ########################################## SECTION: Data Processing ##########################################

    #Calc dynamic update interval
    $StatusUpdateInterval = [Math]::Max([Math]::Floor($AppsTotalCount / 10), 1)
    if ($AppsTotalCount -gt 0 -and $StatusUpdateInterval -gt 1) {
        Write-Host "[*] Status: Processing app 1 of $AppsTotalCount (updates every $StatusUpdateInterval apps)..."
    }

    #Loop through each app and get additional info and store it in a custom object
    foreach ($item in $AppRegistrations) {
        $ImpactScore = 0
        $LikelihoodScore = $AppLikelihoodScore["AppBase"]
        $warnings = @()
        $AppRolesDetails = @()
        $AppCredentials = @()
        $SPObjectID = @()
        $AppHomePage = $null
        $Listfindings = ""
        $DefaultRedirectUri = $item.DefaultRedirectUri
        $IsFallbackPublicClient = $item.isFallbackPublicClient
        $AllowPublicClientflows = $item.web.implicitGrantSettings.enableAccessTokenIssuance
        $SpaRedirectUris = $item.Spa.RedirectUris -join ", "
        $WebOauth2AllowImplicitFlow = $item.Web.Oauth2AllowImplicitFlow -join ", "
        $WebRedirectUris = $item.Web.RedirectUris -join ", "
        $WindowsRedirectUris = $item.Windows.RedirectUris -join ", "
        $PublicClientRedirectUris = $item.PublicClient.RedirectUris -join ", "

        $ProgressCounter ++

        # Display status based on the objects numbers (slightly improves performance)
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $AppsTotalCount) {
            Write-Host "[*] Status: Processing app $ProgressCounter of $AppsTotalCount..."
        }


        #Process app credentials
        $AppCredentialsSecrets = foreach ($creds in $item.PasswordCredentials) {

            if ($null -ne $creds.EndDateTime) {
                try {
                    $endDate = [datetime]$creds.EndDateTime
                    $Expired = ($endDate - (Get-Date)).TotalDays -le 0
                } catch {
                    $Expired = "?"
                }
            }
            #The object for apps with secrets require the appname for seperate output file
            [pscustomobject]@{
                Type = "Secret"
                DisplayName = $creds.DisplayName
                EndDateTime = $creds.EndDateTime
                StartDateTime = $creds.StartDateTime
                Expired = $Expired
                AppName = $item.DisplayName
            }
        }

        $AppRolesDetails = foreach ($roles in $item.AppRoles) {
            [pscustomobject]@{
                DisplayName = $roles.DisplayName
                Enabled = $roles.IsEnabled
                Claim = $roles.Value
                Description = $roles.Description
                MemberTypes = ($roles.AllowedMemberTypes -join ' / ')
            }
        }

        $AppCredentialsCertificates = foreach ($creds in $item.KeyCredentials) {
            if ($null -ne $creds.EndDateTime) {
                try {
                    $endDate = [datetime]$creds.EndDateTime
                    $Expired = ($endDate - (Get-Date)).TotalDays -le 0
                } catch {
                    $Expired = "?"
                }
            }
            [pscustomobject]@{
                Type = "Certificate"
                DisplayName = $creds.DisplayName
                EndDateTime = $creds.EndDateTime
                StartDateTime = $creds.StartDateTime
                Expired = $Expired
            }
        }
        $AppCredentials += $AppCredentialsSecrets
        $AppCredentials += $AppCredentialsCertificates

        # Combine arrays into a hashtable for easy identification
        $AppRedirectURL = @{
            SpaRedirectUris = $item.Spa.RedirectUris
            WebRedirectUris = $item.Web.RedirectUris
            WindowsRedirectUris = $item.Windows.RedirectUris
            PublicClientRedirectUris = $item.PublicClient.RedirectUris
        }

        # Define patterns with severity levels
        $RedirectPatterns = @(
            [PSCustomObject]@{ Pattern = "*.azurewebsites.net"; Severity = "High" },
            [PSCustomObject]@{ Pattern = "*.logic.azure.com"; Severity = "High" },
            [PSCustomObject]@{ Pattern = "*.github.com"; Severity = "High" },
            [PSCustomObject]@{ Pattern = ".logic.azure.com"; Severity = "Medium" },
            [PSCustomObject]@{ Pattern = ".azurewebsites.net"; Severity = "Medium" }
        )

        # Prepare a result object
        $FindingsRedirectUrls = @()

        # Iterate through arrays and check for matches
        foreach ($key in $AppRedirectURL.Keys) {
            foreach ($RedirectURL in $AppRedirectURL[$key]) {
                foreach ($pattern in $RedirectPatterns) {
                    # Treat the pattern as a literal string (escaping special characters like `*`)
                    $escapedPattern = [regex]::Escape($pattern.Pattern)

                    # Check if the item contains the pattern as a substring
                    if ($RedirectURL -match $escapedPattern) {
                        $FindingsRedirectUrls += [PSCustomObject]@{
                            Match      = $RedirectURL
                            Pattern    = $pattern.Pattern
                            Severity   = $pattern.Severity
                            ArrayName  = $key
                        }
                    }
                }
            }
        }

        foreach ($Finding in $FindingsRedirectUrls) {
            $Listfindings += "$($Finding.Severity): $($Finding.Match)"
        }

        #Experimental collect app authentication properties
        $AppAuthentication += [pscustomobject]@{
            AppName = $item.DisplayName
            ApiDelegated = $ApiDelegatedCount
            IsFallbackPublicClient = $IsFallbackPublicClient
            AllowPublicClientflows = $AllowPublicClientflows
            WebOauth2AllowImplicitFlow = $WebOauth2AllowImplicitFlow
            DefaultRedirectUri = $DefaultRedirectUri
            PublicClientRedirectUris = $PublicClientRedirectUris
            SpaRedirectUris = $SpaRedirectUris
            WebRedirectUris = $WebRedirectUris
            WindowsRedirectUris = $WindowsRedirectUris
            Warning = $Listfindings
        }

        #Get application lock config
        $AppLockConfiguration = $item | Select-Object -ExpandProperty ServicePrincipalLockConfiguration


        # Ensure it's not null and is an object with properties
        if ($null -eq $AppLockConfiguration -or $AppLockConfiguration.PSObject.Properties.Count -eq 0) {
            # Initialize with default values if it's null or has no properties
            $AppLockConfiguration = [PSCustomObject]@{
                IsEnabled = $false
                AllProperties = $false
                credentialsWithUsageVerify = $false
            }
        } else {
            # Set to false if any expected property is null or missing
            if (-not $AppLockConfiguration.PSObject.Properties.Match('IsEnabled') -or $null -eq $AppLockConfiguration.IsEnabled) {
                $AppLockConfiguration | Add-Member -MemberType NoteProperty -Name IsEnabled -Value $false -Force
            }
            if (-not $AppLockConfiguration.PSObject.Properties.Match('AllProperties') -or $null -eq $AppLockConfiguration.AllProperties) {
                $AppLockConfiguration | Add-Member -MemberType NoteProperty -Name AllProperties -Value $false -Force
            }
            if (-not $AppLockConfiguration.PSObject.Properties.Match('credentialsWithUsageVerify') -or $null -eq $AppLockConfiguration.credentialsWithUsageVerify) {
                $AppLockConfiguration | Add-Member -MemberType NoteProperty -Name credentialsWithUsageVerify -Value $false -Force
            }
        }

        #Get application home page
        if ($null -ne $item.web.HomePageUrl) {
            $AppHomePage = $item.web.HomePageUrl
        }

        #Get owners of the sp
        $AppOwnerUsers  	= [System.Collections.ArrayList]::new()
        $AppOwnerSPs  	= [System.Collections.ArrayList]::new()
        if ($AppOwnersRaw.ContainsKey($item.Id)) {
            foreach ($OwnedObject in $AppOwnersRaw[$item.Id]) {
                switch ($OwnedObject.'@odata.type') {

                    '#microsoft.graph.user' {
                        #If not synced set to false for nicer output
                        if ($null -eq $OwnedObject.onPremisesSyncEnabled) {
                            $OwnedObject.onPremisesSyncEnabled = $false
                        }
                        [void]$AppOwnerUsers.Add(
                            [PSCustomObject]@{
                                Id                      = $OwnedObject.Id
                                displayName             = $OwnedObject.displayName
                                userPrincipalName       = $OwnedObject.userPrincipalName
                                accountEnabled          = $OwnedObject.accountEnabled
                                userType                = $OwnedObject.userType
                                Department              = $OwnedObject.department
                                JobTitle                = $OwnedObject.jobTitle
                                onPremisesSyncEnabled   = $OwnedObject.onPremisesSyncEnabled
                                AssignmentType          = 'Active'
                            }
                        )
                    }

                    '#microsoft.graph.servicePrincipal' {
                        [void]$AppOwnerSPs.Add(
                            [PSCustomObject]@{
                                Id = $OwnedObject.Id
                            }
                        )
                    }
                }
            }
        }

        $AppOwnersCount = $AppOwnerUsers.Count + $AppOwnerSPs.count
        #Get more information about the SP
        $AppOwnerSPs = foreach ($Object in $AppOwnerSPs) {
            GetObjectInfo $Object.Id -type "ServicePrincipal"
        }


        #Get members of Cloud Application Administrator (158c047a-c907-4556-b7ef-446551a6b5f7) with the scope for current App Registrations
        $CloudAppAdminCurrentApp = $TenantRoleAssignments.Values | ForEach-Object {$_ | Where-Object { $_.RoleDefinitionId -eq "158c047a-c907-4556-b7ef-446551a6b5f7" -and $_.DirectoryScopeId -eq "/$($item.Id)" }} | Select-Object PrincipalId,AssignmentType

        $CloudAppAdminCurrentAppDetails = foreach ($Object in $CloudAppAdminCurrentApp) {
            # Get the object details
            $ObjectDetails = GetObjectInfo $Object.PrincipalId
            # Add the 'Role' property and use passthru to give back the object
            $ObjectDetails | Add-Member -MemberType NoteProperty -Name PrincipalId -Value $Object.PrincipalId
            $ObjectDetails | Add-Member -MemberType NoteProperty -Name AssignmentType -Value $Object.AssignmentType
            $ObjectDetails | Add-Member -MemberType NoteProperty -Name Role -Value 'CloudApplicationAdministrator'
            $ObjectDetails | Add-Member -MemberType NoteProperty -Name Scope -Value 'ThisApplication' -PassThru
        }

        #Get members of Application Administrator (9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3) with the scope for current App Registrations
        $AppAdminCurrentApp = $TenantRoleAssignments.Values | ForEach-Object {$_ | Where-Object { $_.RoleDefinitionId -eq "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" -and $_.DirectoryScopeId -eq "/$($item.Id)" }} | Select-Object PrincipalId,AssignmentType
        $AppAdminCurrentAppDetails = foreach ($Object in $AppAdminCurrentApp) {
            # Get the object details
            $ObjectDetails = GetObjectInfo $Object.PrincipalId
            # Add the 'Role' property and use passthru to give back the object
            $ObjectDetails | Add-Member -MemberType NoteProperty -Name PrincipalId -Value $Object.PrincipalId
            $ObjectDetails | Add-Member -MemberType NoteProperty -Name AssignmentType -Value $Object.AssignmentType
            $ObjectDetails | Add-Member -MemberType NoteProperty -Name Role -Value 'ApplicationAdministrator'
            $ObjectDetails | Add-Member -MemberType NoteProperty -Name Scope -Value 'ThisApplication' -PassThru
        }

        #Calculate likelihood for client credentials
        $SecretsCount = ($AppCredentialsSecrets | Measure-Object).Count
        $LikelihoodScore += $SecretsCount * $AppLikelihoodScore["AppSecret"]

        $CertificateCount = ($AppCredentialsCertificates | Measure-Object).Count
        $LikelihoodScore += $CertificateCount * $AppLikelihoodScore["AppCertificate"]


        #Count App Admins and increase risk score
        $CloudAppAdminCurrentAppCount = ($CloudAppAdminCurrentApp | Measure-Object).Count
        $AppAdminCurrentAppCount = ($AppAdminCurrentApp | Measure-Object).Count
        $AppAdminsCount = $CloudAppAdminCurrentAppCount + $AppAdminCurrentAppCount + $CloudAppAdminTenantCount + $AppAdminTenantCount
        if ($AppAdminsCount -ge 1) {
            $LikelihoodScore += $AppAdminsCount * $AppLikelihoodScore["AppAdmins"]
        }


        #Check if there are owners
        if ($AppOwnersCount -ge 1) {
            $LikelihoodScore += $AppOwnersCount * $AppLikelihoodScore["AppOwner"]
        }

        #Check application lock config
        if ($AppLockConfiguration.IsEnabled -ne $true -or ($AppLockConfiguration.AllProperties -ne $true -and $AppLockConfiguration.credentialsWithUsageVerify -ne $true)) {
            $AppLock = $false
        } else {
            $AppLock = $true
        }



        #SP as owner
        if (($AppOwnerSPs | Measure-Object).count -ge 1) {
            if ($AppOwnerSPs.Foreign -contains $true) {
                $Warnings += "Foreign SP as owner!"
                $LikelihoodScore += $AppLikelihoodScore["ExternalSPOwner"]
            } elseif ($AppOwnerSPs.Foreign -contains $false) {
                $Warnings += "Internal SP as owner"
                $LikelihoodScore += $AppLikelihoodScore["InternalSPOwner"]
            }
        }


        if (($AppOwnerUsers | Where-Object { $_.UserType -eq "Guest" } | Measure-Object).Count -ge 1) {
            $Warnings += "Guest as Owner!"
            $LikelihoodScore += $AppLikelihoodScore["GuestAsOwner"]
        }
        if (($CloudAppAdminCurrentAppDetails | Where-Object { $_.UserType -eq "Guest" } | Measure-Object).Count -ge 1) {
            $Warnings += "Guest as scoped CloudAppAdmin!"
            $LikelihoodScore += $AppLikelihoodScore["GuestAsOwner"]
        }
        if (($AppAdminCurrentAppDetails | Where-Object { $_.UserType -eq "Guest" } | Measure-Object).Count -ge 1) {
            $Warnings += "Guest as scoped AppAdmin!"
            $LikelihoodScore += $AppLikelihoodScore["GuestAsOwner"]
        }
        if (($CloudAppAdminCurrentAppDetails | Where-Object { $_.Foreign -eq "True" } | Measure-Object).Count -ge 1) {
            $Warnings += "Foreign SP as scoped CloudAppAdmin!"
            $LikelihoodScore += $AppLikelihoodScore["ExternalSPOwner"]
        }
        if (($AppAdminCurrentAppDetails | Where-Object { $_.Foreign -eq "True" } | Measure-Object).Count -ge 1) {
            $Warnings += "Foreign SP scoped AppAdmin!"
            $LikelihoodScore += $AppLikelihoodScore["ExternalSPOwner"]
        }

        #Take ImpactScore and ObjectId from SP
        $EnterpriseApps.GetEnumerator() | Where-Object { $_.Value.AppId -eq $item.AppId } | Select-Object -First 1 | ForEach-Object {
            $ImpactScore += $_.Value.Impact
            $SPObjectID = $_.Name
            $ApiDelegatedCount = $_.Value.ApiDelegated
        }

        #Format warning messages
        $Warnings = if ($null -ne $Warnings) {
            $Warnings -join ' / '
        } else {
            ''
        }

        #Appendix of Applications with Secrets
        if ($SecretsCount -ge 1){
            $AppsWithSecrets += $AppCredentialsSecrets
        }

        #Write custom object
        $AppRegDetails = [PSCustomObject]@{
            Id = $item.Id
            DisplayName = $item.DisplayName
            DisplayNameLink = "<a href=#$($item.Id)>$($item.DisplayName)</a>"
            AppId = $item.AppId
            SignInAudience = $item.signInAudience
            OwnerCount = ($AppOwnerUsers | Measure-Object).Count + ($AppOwnerSPs | Measure-Object).Count
            SecretsCount = $SecretsCount
            CertsCount = $CertificateCount
            AppCredentialsDetails = $AppCredentials
            AppOwnerUsers = $AppOwnerUsers
            AppOwnerSPs = $AppOwnerSPs
            SPObjectId = $SPObjectID
            AppRolesDetails = $AppRolesDetails
            AppRoles = ($AppRolesDetails | Measure-Object).Count
            CloudAppAdmins = ($CloudAppAdminCurrentApp | Measure-Object).Count + ($CloudAppAdminTenantDetails | Measure-Object).Count
            AppAdmins = ($AppAdminCurrentApp | Measure-Object).Count + ($AppAdminTenantDetails | Measure-Object).Count
            CloudAppAdminCurrentAppDetails = $CloudAppAdminCurrentAppDetails
            AppAdminCurrentAppDetails = $AppAdminCurrentAppDetails
            DistinctAPIs = $($item.RequiredResourceAccess).Count
            Risk = [math]::Round(($ImpactScore * $LikelihoodScore))
            Impact = [math]::Round($ImpactScore)
            Likelihood = [math]::Round($LikelihoodScore,1)
            AppLock = $AppLock
            AppLockConfiguration = $AppLockConfiguration
            AppHomePage = $AppHomePage
            Warnings = $Warnings
        }
        [void]$AllAppRegistrations.Add($AppRegDetails)

    }

    ########################################## SECTION: OUTPUT DEFINITION ##########################################
    write-host "[*] Generating reports"


    #Define Table for output
    $tableOutput = $AllAppRegistrations | Sort-Object -Property risk -Descending | select-object DisplayName,DisplayNameLink,SignInAudience,AppRoles,AppLock,OwnerCount,CloudAppAdmins,AppAdmins,SecretsCount,CertsCount,Impact,Likelihood,Risk,Warnings


    #Define the apps to be displayed in detail and sort them by risk score
    $details = $AllAppRegistrations | Sort-Object Risk -Descending


    #Define stringbuilder to avoid performance impact
    $DetailTxtBuilder = [System.Text.StringBuilder]::new()

    foreach ($item in $details) {
        $ReportingAppRegInfo = @()
        $ReportingCredentials = @()
        $ReportingAppLock = @()
        $ReportingAppRoles = @()
        $ReportingAppOwnersUser = @()
        $ReportingAppOwnersSP = @()
        $ScopedAdminUser = @()
        $ScopedAdminGroup = @()
        $ScopedAdminSP = @()


        [void]$DetailTxtBuilder.AppendLine("############################################################################################################################################")

        ############### HEADER
        $ReportingAppRegInfo = [pscustomobject]@{
            "App Name" = $($item.DisplayName)
            "App Client-ID" = $($item.AppId)
            "App Object-ID" = $($item.Id)
            "Enterprise App Link" = "<a href=EnterpriseApps_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($item.SPObjectId)>$($item.DisplayName)</a>"
            "SignInAudience" = $($item.SignInAudience)
            "RiskScore" = $($item.Risk)
        }

        #Build dynamic TXT report property list
        $TxtReportProps = @("App Name","App Client-ID","App Object-ID","SignInAudience","RiskScore")

        if ($null -ne $item.AppHomePage) {
            $ReportingAppRegInfo | Add-Member -NotePropertyName URL -NotePropertyValue $item.AppHomePage
            $TxtReportProps += "URL"
        }

        if ($item.Warnings -ne '') {
            $ReportingAppRegInfo | Add-Member -NotePropertyName Warnings -NotePropertyValue $item.Warnings
            $TxtReportProps += "Warnings"
        }

        [void]$DetailTxtBuilder.AppendLine(($ReportingAppRegInfo | select-object $TxtReportProps | Out-String))

        ############### App Registration Credentials
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
            [void]$DetailTxtBuilder.AppendLine("App Registration Credentials")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingCredentials | Out-String))
        }

        ############### AppLock
        if ($($item.AppLockConfiguration | Measure-Object).count -ge 1) {
            $ReportingAppLock = foreach ($object in $($item.AppLockConfiguration)) {
                [pscustomobject]@{
                    "Enabled" = $($object.IsEnabled)
                    "All properties" = $($object.AllProperties)
                    "Credentials used for verification" = $($object.credentialsWithUsageVerify)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("App Instance Property Lock (AppLock)")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAppLock | Out-String))
        }

       ############### Owners of the App Registration
        if ($($item.AppOwnerUsers | Measure-Object).count -ge 1 -or $($item.AppOwnerSPs | Measure-Object).count -ge 1) {

            if ($($item.AppOwnerUsers | Measure-Object).count -ge 1) {
                $ReportingAppOwnersUser = foreach ($object in $($item.AppOwnerUsers)) {
                    [pscustomobject]@{
                        "UPN" = $($object.userPrincipalName)
                        "UPNLink" = "<a href=Users_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.userPrincipalName)</a>"
                        "Enabled" = $($object.accountEnabled)
                        "Type" = $($object.userType)
                        "OnPremSync" = $($object.onPremisesSyncEnabled)
                        "Department" = $($object.Department)
                        "JobTitle" = $($object.jobTitle)
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

            if ($($item.AppOwnerSPs | Measure-Object).count -ge 1) {
                $ReportingAppOwnersSP = foreach ($object in $($item.AppOwnerSPs)) {
                    [pscustomobject]@{
                        "DisplayName" = $($object.DisplayName)
                        "DisplayNameLink" = "<a href=EnterpriseApps_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.DisplayName)</a>"
                        "Foreign" = $($object.Foreign)
                        "PublisherName" = $($object.publisherName)
                        "OwnersCount" = $($object.OwnersCount)
                    }
                }

                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine("Owners (Service Principals)")
                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine(($ReportingAppOwnersSP | format-table -Property DisplayName,Enabled,Foreign,PublisherName,OwnersCount | Out-String))
                $ReportingAppOwnersSP = foreach ($obj in $ReportingAppOwnersSP) {
                    [pscustomobject]@{
                        DisplayName     = $obj.DisplayNameLink
                        Enabled         = $obj.Enabled
                        Foreign         = $obj.Foreign
                        PublisherName   = $obj.PublisherName
                        OwnersCount     = $obj.OwnersCount
                    }
                }
            }
        }

        ############### Scoped Admins

        #Wrap to Array and merge
        $CloudAppAdminCurrentAppDetails = @($item.CloudAppAdminCurrentAppDetails)
        $AppAdminCurrentAppDetails = @($item.AppAdminCurrentAppDetails)
        $MergedAdmins = $CloudAppAdminCurrentAppDetails + $AppAdminCurrentAppDetails + $CloudAppAdminTenantDetails + $AppAdminTenantDetails

        if ($($MergedAdmins | Measure-Object).count -ge 1) {

            #Split by object type
            $EntityDetails = @{
                Users  = @($MergedAdmins | Where-Object { $_.Type -eq 'User' })
                Groups = @($MergedAdmins | Where-Object { $_.Type -eq 'Group' })
                SP = @($MergedAdmins | Where-Object { $_.Type -eq 'ServicePrincipal' })
            }

            if ($($EntityDetails.Users | Measure-Object).count -ge 1) {
                $ScopedAdminUser = foreach ($object in $($EntityDetails.Users)) {
                    [pscustomobject]@{
                        "Role" = $($object.Role)
                        "Scope" = $($object.Scope)
                        "AssignmentType"  = $($object.AssignmentType)
                        "UPN" = $($object.UPN)
                        "UPNLink" = "<a href=Users_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.PrincipalId)>$($object.UPN)</a>"
                        "Enabled" = $($object.Enabled)
                        "Type" = $($object.userType)
                        "OnPremSync" = $($object.Onprem)
                        "Department" = $($object.Department)
                        "JobTitle" = $($object.JobTitle)
                    }
                }

                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine("App Admins (Users)")
                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine(($ScopedAdminUser | format-table -Property Role,Scope,AssignmentType,UPN,Enabled,Type,OnPremSync,Department,JobTitle | Out-String))
                $ScopedAdminUser  = foreach ($obj in $ScopedAdminUser ) {
                    [pscustomobject]@{
                        Role            = $obj.Role
                        Scope           = $obj.Scope
                        AssignmentType  = $obj.AssignmentType
                        UserName        = $obj.UPNLink
                        Enabled         = $obj.Enabled
                        Type            = $obj.Type
                        OnPremSync      = $obj.OnPremSync
                        Department      = $obj.Department
                        JobTitle        = $obj.JobTitle
                    }
                }
            }

            if ($($EntityDetails.Groups | Measure-Object).count -ge 1) {
                $ScopedAdminGroup = foreach ($object in $($EntityDetails.Groups)) {
                    [pscustomobject]@{
                        "Role" = $($object.Role)
                        "Scope" = $($object.Scope)
                        "AssignmentType"  = $($object.AssignmentType)
                        "Name" = $($object.DisplayName)
                        "NameLink" = "<a href=Groups_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.DisplayName)</a>"
                        "OnPremSync" = $($object.OnPrem)
                        "Users" = $($object.Users)
                        "Guests" = $($object.Guests)
                        "Owners" = $($object.Owners)
                    }
                }
                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine("Admins (Groups)")
                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine(($ScopedAdminGroup | format-table -Property Role,Scope,AssignmentType,Name,OnPremSync,Users,Guests,Owners | Out-String))
                $ScopedAdminGroup  = foreach ($obj in $ScopedAdminGroup) {
                    [pscustomobject]@{
                        Role            = $obj.Role
                        Scope           = $obj.Scope
                        AssignmentType  = $obj.AssignmentType
                        DisplayName     = $obj.NameLink
                        OnPremSync      = $obj.OnPremSync
                        Users           = $obj.Users
                        Guests          = $obj.Guests
                        Owners          = $obj.Owners
                    }
                }
            }

            if ($($EntityDetails.SP | Measure-Object).count -ge 1) {
                $ScopedAdminSP = foreach ($object in $($EntityDetails.SP)) {
                    [pscustomobject]@{
                        "Role" = $($object.Role)
                        "Scope" = $($object.Scope)
                        "AssignmentType"  = $($object.AssignmentType)
                        "DisplayName" = $($object.DisplayName)
                        "DisplayNameLink" = "<a href=EnterpriseApps_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.DisplayName)</a>"
                        "PublisherName" = $($object.publisherName)
                        "Foreign" = $($object.Foreign)
                        "Owners" = $($object.OwnersCount)
                    }
                }
                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine("Admins (SPs)")
                [void]$DetailTxtBuilder.AppendLine("================================================================================================")
                [void]$DetailTxtBuilder.AppendLine(($ScopedAdminSP | format-table -Property Role,Scope,AssignmentType,DisplayName,PublisherName,Foreign,Owners | Out-String))
                $ReportingAppOwnersSP = foreach ($obj in $ReportingAppOwnersSP) {
                    [pscustomobject]@{
                        Role            = $obj.Role
                        Scope           = $obj.Scope
                        AssignmentType  = $obj.AssignmentType
                        DisplayName     = $obj.DisplayNameLink
                        Foreign         = $obj.Foreign
                        PublisherName   = $obj.PublisherName
                        Owners          = $obj.Owners
                    }
                }
            }
        }

        ############### AppLock
        if ($($item.AppRolesDetails | Measure-Object).count -ge 1) {
            $ReportingAppRoles = foreach ($object in $($item.AppRolesDetails)) {
                [pscustomobject]@{
                    "DisplayName" = $($object.DisplayName)
                    "Enabled" = $($object.Enabled)
                    "Claim" = $($object.Claim)
                    "MemberTypes" = $($object.MemberTypes)
                    "Description" = $($object.Description)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("App Roles")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAppRoles | Out-String))
        }


        $ObjectDetails=[pscustomobject]@{
            "Object Name"     = $item.DisplayName
            "Object ID"       = $item.Id
            "General Information"    = $ReportingAppRegInfo
            "App Credentials"    = $ReportingCredentials
            "App Instance Property Lock (AppLock)"    = $ReportingAppLock
            "Application Roles"    = $ReportingAppRoles
            "Owners (Users)"    = $ReportingAppOwnersUser
            "Owners (ServicePrincipals)"    = $ReportingAppOwnersSP
            "Admins (Users)"    = $ScopedAdminUser
            "Admins (Groups)"    = $ScopedAdminGroup
            "Admins (ServicePrincipals)"    = $ScopedAdminSP
        }

        [void]$AllObjectDetailsHTML.Add($ObjectDetails)

    }

    $DetailOutputTxt = $DetailTxtBuilder.ToString()

    write-host "[*] Writing log files"
    write-host

    $mainTable = $tableOutput | select-object -Property @{Name = "DisplayName"; Expression = { $_.DisplayNameLink}},SignInAudience,AppLock,AppRoles,OwnerCount,CloudAppAdmins,AppAdmins,SecretsCount,CertsCount,Impact,Likelihood,Risk,Warnings
    $mainTableJson  = $mainTable | ConvertTo-Json -Depth 5 -Compress
    $mainTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainTableJson + "`n" + '</script>'



# Build Detail section as JSON for the HTML Report
    $AllObjectDetailsHTML = $AllObjectDetailsHTML | ConvertTo-Json -Depth 5 -Compress
$ObjectsDetailsHEAD = @'
    <h2>App Registrations Details</h2>
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
Execution Warnings = $($ScriptWarningList  -join ' / ')
************************************************************************************************************************
"

$headerHTML = [pscustomobject]@{
    "Executed in Tenant" = "$($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)"
    "Executed at" = "$StartTimestamp "
    "Execution Warnings" = $ScriptWarningList -join ' / '
}


#Define Appendix

$AppendixClientSecrets = "

===============================================================================================================================================
Appendix: App Registrations with Client Secrets
===============================================================================================================================================
"

$AppendixAppAuthSettings = "

===============================================================================================================================================
Appendix: Experimental App Authentication Settings
===============================================================================================================================================
"

    # Prepare HTML output
    $headerHTML = $headerHTML | ConvertTo-Html -Fragment -PreContent "<div id=`"loadingOverlay`"><div class=`"spinner`"></div><div class=`"loading-text`">Loading data...</div></div><nav id=`"topNav`"></nav><h1>$($Title) Enumeration</h1>" -As List -PostContent "<h2>$($Title) Overview</h2>"

    #Write TXT and CSV files
    $headerTXT | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    $tableOutput | format-table DisplayName,SignInAudience,AppLock,AppRoles,OwnerCount,CloudAppAdmins,AppAdmins,SecretsCount,CertsCount,Impact,Likelihood,Risk,Warnings | Out-File -Width 512 "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    $tableOutput | select-object DisplayName,SignInAudience,AppLock,AppRoles,OwnerCount,CloudAppAdmins,AppAdmins,SecretsCount,CertsCount,Impact,Likelihood,Risk,Warnings | Export-Csv -Path "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).csv" -NoTypeInformation
    $DetailOutputTxt | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    $AppsWithSecrets = $AppsWithSecrets | sort-object DisplayName | select-object AppName,Displayname,StartDateTime,EndDateTime,Expired
    if (($AppsWithSecrets | Measure-Object).count -ge 1) {
        $AppendixClientSecrets  | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
        $AppsWithSecrets | Format-Table -AutoSize | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
        $AppsWithSecrets | Export-Csv -Path "$outputFolder\$($Title)_Secrets_$($StartTimestamp)_$($CurrentTenant.DisplayName).csv" -NoTypeInformation
        $AppendixSecretsHTML += $AppsWithSecrets | ConvertTo-Html -Fragment -PreContent "<h2>Appendix: Apps With Secrets</h2>"
    }

    if (($AppAuthentication | Measure-Object).count -ge 1) {
        $AppendixAppAuthSettings  | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
        $AppAuthentication | Format-Table -AutoSize | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
        $AppendixSecretsHTML += $AppAuthentication | ConvertTo-Html -Fragment -PreContent "<h2>Appendix: Application Authentication Configuration</h2>"
    }


    $PostContentCombined = $GLOBALJavaScript + "`n" + $AppendixSecretsHTML

    #Write HTML
    $Report = ConvertTo-HTML -Body "$headerHTML $mainTableHTML" -Title "$Title Enumeration" -Head $GLOBALcss -PostContent $PostContentCombined -PreContent $AllObjectDetailsHTML
    $Report | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).html"

    write-host "[+] Details of $($AllAppRegistrations.count) App Registrations stored in output files (CSV,TXT,HTML): $outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName)"

    #Add information to the enumeration summary
    $AppLock = 0
    $AzureADMyOrg = 0
    $AzureADMultipleOrgs = 0
    $AzureADandPersonalMicrosoftAccount = 0
    $AppsSecrets = 0
    $AppsCertificates = 0
    $AppsNoCredentials = 0

    foreach ($app in $AllAppRegistrations) {
        if ($app.AppLock) {
            $AppLock++
        }
        if ($app.SecretsCount -ge 1) {
            $AppsSecrets++
        }
        if ($app.CertsCount -ge 1) {
            $AppsCertificates++
        }
        if ($app.SecretsCount -eq 0 -and $app.CertsCount -eq 0){
            $AppsNoCredentials++
        }

        switch ($app.signInAudience) {
            "AzureADMyOrg" {
                $AzureADMyOrg++
                break
            }
            "AzureADMultipleOrgs" {
                $AzureADMultipleOrgs++
                break
            }
            "AzureADandPersonalMicrosoftAccount" {
                $AzureADandPersonalMicrosoftAccount++
                break
            }
        }
    }

    # Store in global var
    $GlobalAuditSummary.AppRegistrations.Count = $AppsTotalCount
    $GlobalAuditSummary.AppRegistrations.AppLock = $AppLock
    $GlobalAuditSummary.AppRegistrations.Credentials.AppsSecrets = $AppsSecrets
    $GlobalAuditSummary.AppRegistrations.Credentials.AppsCerts = $AppsCertificates
    $GlobalAuditSummary.AppRegistrations.Credentials.AppsNoCreds = $AppsNoCredentials
    $GlobalAuditSummary.AppRegistrations.Audience.SingleTenant = $AzureADMyOrg
    $GlobalAuditSummary.AppRegistrations.Audience.MultiTenant = $AzureADMultipleOrgs
    $GlobalAuditSummary.AppRegistrations.Audience.MultiTenantPersonal = $AzureADandPersonalMicrosoftAccount

    #Convert to Hashtable for faster searches
    $AllAppRegistrationsHT = @{}
    foreach ($item in $AllAppRegistrations) {
        $AllAppRegistrationsHT[$item.Id] = $item
    }
    Return $AllAppRegistrationsHT
}
