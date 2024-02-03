param(
    [Parameter(Mandatory = $true)]
    [string]$WorkspaceId,
    [Parameter(Mandatory = $true)]
    [string]$LogAnalyticsWorkspaceSubscriptionID
)

function Get-GraphAPIResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$URI
    )
    $result = Invoke-AzRestMethod -Method Get -Uri $URI

    if ($result.StatusCode -eq 200) {
        return $result
    }
    elseif ($result.Content) {
        $Content = $result.Content | ConvertFrom-Json
        Write-Error $Content.error.message
    }
}

function Get-DirectoryRoles {
    $uri = "https://graph.microsoft.com/v1.0/directoryRoles"
    $directoryRoles = (Get-GraphAPIResult -URI $uri).Content | ConvertFrom-Json | Select-Object -ExpandProperty value 
    return $directoryRoles
}

function Get-DirectoryRoleMembers {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DirectoryRoleID
    )
    $uri = "https://graph.microsoft.com/v1.0/directoryRoles/$DirectoryRoleID/members"
    $directoryRoleMembers = (Get-GraphAPIResult -URI $uri).Content | ConvertFrom-Json | Select-Object -ExpandProperty value 
    return $directoryRoleMembers
}

function Get-AllUsersWithDirectDirectoryRoles {
    $directoryRoles = Get-DirectoryRoles
    $usersWithPrivilegedRoles = @{}
    $directoryRoles | ForEach-Object {
        $directoryRole = $_
        $users = Get-DirectoryRoleMembers -DirectoryRoleID $_.id
        # Check if there are any users that have the role and that the object is a user and not a group
        if ($null -ne $users) {
            $users | ForEach-Object {
                if ($_.'@odata.type' -eq '#microsoft.graph.user') {
                    if ($usersWithPrivilegedRoles.ContainsKey($_.userPrincipalName)) {
                        $usersWithPrivilegedRoles[$_.userPrincipalName] += $directoryRole
                    }
                    else {
                        $usersWithPrivilegedRoles.Add($_.userPrincipalName, @($directoryRole))
                    }
                }
            }
        }
    }
    return $usersWithPrivilegedRoles
}

function Get-AllEntraIdGroupMembersWithDirectoryRoles {
    $directoryRoles = Get-DirectoryRoles
    $usersWithPrivilegedRoles = @()

    $directoryRoles | ForEach-Object {
        $directoryRole = $_
        $directoryRoleMembers = Get-DirectoryRoleMembers -DirectoryRoleID $_.id
        if ($null -ne $directoryRoleMembers -and $directoryRoleMembers.'@odata.type' -eq '#microsoft.graph.group') {
            $directoryRoleMembers | ForEach-Object {
                $uri = "https://graph.microsoft.com/v1.0/groups/$($_.id)/members"
                $groupMembers = (Get-GraphAPIResult -URI $uri).Content | ConvertFrom-Json | Select-Object -ExpandProperty value 
                if ($null -ne $groupMembers) {
                    $groupMembers | ForEach-Object {
                        if ($_.'@odata.type' -eq '#microsoft.graph.user') {
                            $usersWithPrivilegedRoles += [PSCustomObject]@{
                                users         = $groupMembers
                                directoryRole = $directoryRole
                            }
                        }
                    }
                }
            }
        }
    }
    return $usersWithPrivilegedRoles
}

function Get-QueryResultFromLogAnalyticsWorkspace {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkspaceId,
        [Parameter(Mandatory = $true)]
        [string]$LogAnalyticsWorkspaceSubscriptionID,
        [Parameter(Mandatory = $true)]
        [string]$Query
    )
    $null = Select-AzSubscription -SubscriptionId $LogAnalyticsWorkspaceSubscriptionID -WarningAction SilentlyContinue
    try {
        $queryResults = Invoke-AzOperationalInsightsQuery -Query $Query -WorkspaceId $WorkspaceId
        $results = $queryResults.Results
    }
    catch {
        Write-Error "Error occured while getting the query results from Log Analytics Workspace. Error message: $($_)"
    }
    return $results
}

function Get-ActionListBasedOnActivityForUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$User
    )
    $query = @"
AzureActivity
| where Caller == '$($User)'
| where TimeGenerated > ago(90d)
| summarize ActionList = make_set(OperationNameValue) by Caller
"@
    return $query
}

function Get-ActionListBasedonAuditLogsForUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$User
    )
    $query = @"
AuditLogs 
| where InitiatedBy.user.userPrincipalName == '$($User)'
| summarize Operation = make_set(OperationName) by tostring(InitiatedBy.user.userPrincipalName)    
"@
    return $query
}

function Get-InformationAboutUsersDirectoryRoleQuery {
    param(
        [Parameter(Mandatory = $true)]
        [string]$User,
        [Parameter(Mandatory = $true)]
        [string]$DirectoryRoleID
    )
    $query = @"
datatable(UserPrincipalName:string, Roles:dynamic) [
    '$($User)', dynamic(['$($DirectoryRoleID)'])
]
| join kind=inner (AuditLogs
    | where TimeGenerated > ago(90d)
    | extend ActorName = iif(
        isnotempty(tostring(InitiatedBy["user"])),
        tostring(InitiatedBy["user"]["userPrincipalName"]),
        tostring(InitiatedBy["app"]["displayName"])
    )
    | extend ActorID = iif(
        isnotempty(tostring(InitiatedBy["user"])),
        tostring(InitiatedBy["user"]["id"]),
        tostring(InitiatedBy["app"]["id"])
    )
    | where isnotempty(ActorName)
) on `$left.UserPrincipalName == `$right.ActorName
| summarize Operations = make_set(OperationName) by ActorName, ActorID, tostring(Roles)
| extend OperationsCount = array_length(Operations)
| project ActorName, Operations, OperationsCount, Roles, ActorID
| sort by OperationsCount desc
"@
    return $query
}

function Get-UsersBasedOnActivity {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$ActiveUsers,
        [Parameter(Mandatory = $true)]
        [hashtable]$UserInformation
    )
    $usersNotInUse = @()
    $usersInUse = @()
    $infoHashTable.GetEnumerator() | ForEach-Object {
        $user = $_.Key
        $directoryRoles = @()
        $userNotInUse = $false
        $_.value | ForEach-Object {
            $userActivity = $_.UserActivity
            if (-not $userActivity) {
                $userNotInUse = $true
            }
            $directoryRoles += $_.DirectoryRole
        }
        if ($userNotInUse) {
            $usersNotInUse += [PSCustomObject]@{
                User          = $user
                DirectoryRole = $directoryRoles
            }
        }
        else {
            $usersInUse += [PSCustomObject]@{
                User          = $user
                DirectoryRole = $directoryRoles
            }
        }
    }
    if ($ActiveUsers) {
        return $usersInUse
    }
    else {
        return $usersNotInUse
    }
}

function Get-RolePermissions {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RoleTemplateId
    )
    $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$($RoleTemplateId)"
    $graphApiQuery = Get-GraphAPIResult -URI $uri
    $result = ($graphApiQuery.Content | ConvertFrom-Json | Select-Object -ExpandProperty rolePermissions).allowedResourceActions
    return $result
}

function Get-AllDirectoryRolesPermissions {
    $directoryRoles = Get-DirectoryRoles
    $listOverDirectoryRoles = @()
    $directoryRoles | ForEach-Object {
        $listOverDirectoryRoles += [PSCustomObject]@{
            RoleTemplateId = $_.roleTemplateId
            ID             = $_.id
            DisplayName    = $_.displayName
            Permissions    = Get-RolePermissions -RoleTemplateId $_.roleTemplateId
        }
    }
    return $listOverDirectoryRoles
}

function Invoke-EntraIdPrivilegedRoleReport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkspaceId,
        [Parameter(Mandatory = $true)]
        [string]$LogAnalyticsWorkspaceSubscriptionID,
        [Parameter(Mandatory = $false)]
        [bool]$IncludeGroups,
        [Parameter(Mandatory = $false)]
        [bool]$IncludePIM
    )

    $info = @()
    $usersWithDirectDirectoryRoles = Get-AllUsersWithDirectDirectoryRoles
    
    if ($IncludeGroups) {
        $usersWithEntraIdGroupMembersWithDirectoryRoles = Get-AllEntraIdGroupMembersWithDirectoryRoles
        $usersWithPrivilegedRoles = $usersWithDirectDirectoryRoles + $usersWithEntraIdGroupMembersWithDirectoryRoles
    }
    else {
        $usersWithPrivilegedRoles = $usersWithDirectDirectoryRoles
    }

    $usersWithPrivilegedRoles | ForEach-Object {
        $directoryRole = $_.directoryRole
        $_.users | ForEach-Object {
            $query = Get-InformationAboutUsersDirectoryRoleQuery -User $_.userPrincipalName -DirectoryRoleID $directoryRole.id
            $queryResults = Get-QueryResultFromLogAnalyticsWorkspace -WorkspaceId $WorkspaceId -LogAnalyticsWorkspaceSubscriptionID $LogAnalyticsWorkspaceSubscriptionID -Query $query

            # If the user has not done any actions that last 90 days
            if ($null -eq $queryResults) {
                $userActivity = $null
            }
            else {
                $userActivity = $queryResults 
            }
            $info += [PSCustomObject]@{
                User          = $_.userPrincipalName
                DirectoryRole = $directoryRole.displayName
                UserActivity  = $userActivity
            }

        }
    }

    $infoHashTable = $info | Group-Object -property User, DirectoryRole | ForEach-Object { $_.Group[0] } | Group-Object -Property User -AsHashTable 

    Write-Output "People that have no activity logs that last 90 days and have directory roles. These users should be evaluated for removal from the directory roles."
  
    Get-UsersBasedOnActivity -ActiveUsers $false -UserInformation $infoHashTable | ForEach-Object {
        Write-Output " - User: $($_.User)"
        Write-Output " - DirectoryRole: $($_.DirectoryRole)"
        Write-Output ""
    }

    Write-Output "People that have done actions in the last 90 days and what type of role they have:"
    
    Get-UsersBasedOnActivity -ActiveUsers $True -UserInformation $infoHashTable | ForEach-Object {
        Write-Output " - User: $($_.User)"
        Write-Output " - DirectoryRole: $($_.DirectoryRole)"
        Write-Output ""
    }
}


function Invoke-ActivityAnalyser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkspaceId,
        [Parameter(Mandatory = $true)]
        [string]$LogAnalyticsWorkspaceSubscriptionID
    )
    # Get all the users 
    $usersWithDirectDirectoryRoles = Get-AllUsersWithDirectDirectoryRoles
    
    $info = @{}

    $usersWithDirectDirectoryRoles.GetEnumerator() | ForEach-Object {
        $_ | ForEach-Object {
            $activityLogQuery = Get-ActionListBasedOnActivityForUser -User $_.Key
            $queryResult = Get-QueryResultFromLogAnalyticsWorkspace -WorkspaceId $WorkspaceId -LogAnalyticsWorkspaceSubscriptionID $LogAnalyticsWorkspaceSubscriptionID -Query $activityLogQuery
            
            if ($null -eq $queryResult) {
                Write-Verbose "No actions done by the user: $($_.Key) in the last 90 days"
            }
            else {
                $actionList = $queryResult.ActionList | ConvertFrom-Json
                if ($_.Key -in $info.Keys) {
                    $info[$_.Key] += $actionList
                }
                else {
                    $info.Add($_.Key, $actionList)
                }
            } 
        }
    }
    Write-Output "Retreived all the actions done by the users with directory roles in the last 90 days"

    Write-Output "Retrieving all the directory roles and their permissions..."
    $directoryRolePermissions = Get-AllDirectoryRolesPermissions
    Write-Output " - Retrieved all the directory roles and their permissions"

    # Remove all the actions that are not part of the directory roles from the useractivity
    # Check if the user has done any actions that are part of the directory roles
    # This means that we keep the user for futher analysis
    # If the user has not done any actions that are part of the directory roles we can remove the user from the analysis

    $directoryRolePermissions | ForEach-Object {
        $usedDirectoryRoleActions = $false
        $directoryRole = $_.DisplayName
        $directoryPermissions = $_.Permissions
        $info | ForEach-Object {
            $user = $_.Keys
            $actions = $_.Values
            $actions | ForEach-Object {
                if ($directoryPermissions -contains $_) {
                    $usedDirectoryRoleActions = $true
                    Write-Output "User: $user has done the action: $_ that is part of the directory role: $directoryRole"
                }
            }
            if (-not $usedDirectoryRoleActions) {
                Write-Output "User: $user has not done any actions that are part of the directory role: $directoryRole"
            }
        }
    }

    # Create list over all roles that have the actions that the user has done
    # Create list over the roles 
}

Invoke-ActivityAnalyser -WorkspaceId $WorkspaceId -LogAnalyticsWorkspaceSubscriptionID $LogAnalyticsWorkspaceSubscriptionID
