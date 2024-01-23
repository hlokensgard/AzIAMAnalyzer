function Get-DirectoryRoles {
    $directoryRoles = Invoke-AzRestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/directoryRoles"

    if ($directoryRoles.StatusCode -eq 200) {
        $directoryRoles = $directoryRoles.Content | ConvertFrom-Json | Select-Object -ExpandProperty value 
        return $directoryRoles
    }
    elseif ($directoryRoles.Content) {
        $Content = $directoryRoles.Content | ConvertFrom-Json
        Write-Error $Content.error.message
    }
}

function Get-DirectoryRoleMembers {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DirectoryRoleID
    )
    $directoryRoleMembers = Invoke-AzRestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$DirectoryRoleID/members"

    if ($directoryRoleMembers.StatusCode -eq 200) {
        $directoryRoleMembers = $directoryRoleMembers.Content | ConvertFrom-Json | Select-Object -ExpandProperty value 
        return $directoryRoleMembers
    }
    elseif ($directoryRoleMembers.Content) {
        $Content = $directoryRoleMembers.Content | ConvertFrom-Json
        Write-Error $Content.error.message
    }
}

function Get-AllUsersWithDirectDirectoryRoles {
    $directoryRoles = Get-DirectoryRoles
    $usersWithPrivilegedRoles = @()
    $directoryRoles | ForEach-Object {
        $directoryRole = $_
        $users = Get-DirectoryRoleMembers -DirectoryRoleID $_.id
        # Check if there are any users that have the role and that the object is a user and not a group
        if ($null -ne $users) {
            $users | ForEach-Object {
                if ($_.'@odata.type' -eq '#microsoft.graph.user') {
                    $usersWithPrivilegedRoles += [PSCustomObject]@{
                        users         = $users
                        directoryRole = $directoryRole
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
                $groupMembers = Invoke-AzRestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/groups/$($_.id)/members"
                if ($groupMembers.StatusCode -eq 200) {
                    $groupMembers = $groupMembers.Content | ConvertFrom-Json | Select-Object -ExpandProperty value
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
                    elseif ($groupMembers.Content) {
                        $Content = $groupMembers.Content | ConvertFrom-Json
                        Write-Error $Content.error.message
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

function Get-Query {
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
        else{
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
            $query = Get-Query -User $_.userPrincipalName -DirectoryRoleID $directoryRole.id
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

    $infoHashTable = $info | Group-Object -property User, DirectoryRole | ForEach-Object {$_.Group[0] } | Group-Object -Property User -AsHashTable 

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