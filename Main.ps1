# Prompt user for the API Key and run-as user
#$apiKey = Read-Host "Enter your API Key"
$apiKey = "fd1c8d1a2d44ca6adb3ace8a5a2d810a442c3cad8c583f6db1516942e71bacbf7a8df83a4d4413f1650b4a28db11d8a6aa711e5cdb8d937e66f86ec07320d78f"
#$runAsUser = Read-Host "Enter the run-as user (e.g., lseg\ichohan-a)"
$runAsUser = "lseg\ichohan-a"

# Prompt for credentials
$Credential = $null
try {
    $Credential = Get-Credential -Message "Enter your password (leave blank if not required - hit ESC to bypass):" -UserName $runAsUser
} catch {
    # If the user cancels the prompt, create a PSCredential object with a non-empty password
    $SecurePassword = ConvertTo-SecureString -String "dummy" -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential($runAsUser, $SecurePassword)
}

# Set the base URL for BeyondTrust
$BThost = "paa.prod.stockex.local"
$baseUrl = "https://${BThost}/BeyondTrust/api/public/v3/"

# Forming the Authorization header
$headers = if ($Credential.Password.Length -gt 0) {
    @{ Authorization = "PS-Auth key=${apiKey};runas=${runAsUser};pwd=[${Credential.GetNetworkCredential().Password}]" }
} else {
    @{ Authorization = "PS-Auth key=${apiKey};runas=${runAsUser}" }
}

# Prompt user for log directory
#$logDirectory = Read-Host "Enter the directory where logs should be stored (e.g., C:\Logs):"  
$logDirectory = "C:\Users\ichohan\logs"
if (-not (Test-Path $logDirectory)) {
    New-Item -ItemType Directory -Path $logDirectory
}

# Log file setup
$timestamp = Get-Date -Format "yyyyMMddHHmmss"
$logFile = "$logDirectory\script_log_$timestamp.txt"
Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Script executed by $runAsUser"

# Sign In Block
try {
    Write-Host "Signing-in.."
    $signinResult = Invoke-RestMethod -Uri "${baseUrl}Auth/SignAppIn" -Method Post -Headers $headers -SessionVariable session
    Write-Host "..Signed-In as $($signinResult.UserName)"
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Signed-In as $($signinResult.UserName)"
} catch {
    Write-Host "Sign-in failed: $($_.Exception.Message)"
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Sign-in failed $($_.Exception.Message)"
    if ($_.Exception.Response.StatusCode.value__ -eq 401 -and ($_.Exception.Response.Headers.Contains("WWW-Authenticate-2FA") -eq $true)) {
        $mfacode = Read-Host "Enter your MFA Challenge Code"
        $headers.Authorization += ";challenge=${mfacode}"
        if ($Credential.Password.Length -gt 0) { $headers.Authorization += ";pwd=[${Credential.GetNetworkCredential().Password}]" }
        try {
            $mfaSignin = Invoke-RestMethod -Uri "${baseUrl}Auth/SignAppIn" -Method Post -ContentType "application/json" -Headers $headers -WebSession $session
            Write-Host "..Signed-In to BeyondTrust as $($mfaSignin.UserName)"
            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Signed-In to BeyondTrust as $($mfaSignin.UserName)"
        } catch {
            Write-Host "MFA Sign-in failed: $($_.Exception.Message)"
            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): MFA Sign-in failed $($_.Exception.Message)"
            throw
        }
    } else { throw }
}

# Function to check if a group exists in the domain
function Check-GroupExists {
    param (
        [string]$groupName,
        [string]$domainName
    )

    try {
        $groupUri = "${baseUrl}UserGroups?filter=groupName eq '$groupName' and domainName eq '$domainName'"
        $groupResult = Invoke-RestMethod -Uri $groupUri -Method Get -Headers $headers -WebSession $session
        return $groupResult.UserGroups.Count -gt 0
    } catch {
        Write-Host "Failed to check group existence: $($_.Exception.Message)"
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Failed to check group existence: $($_.Exception.Message)"
        return $false
    }
}

# Function to get user groups
function Get-UserGroups {
    param (
        [string]$userName,
        [string]$domainName,
        [string]$csvFilePath
    )

    try {
        # Read the CSV file
        $users = Import-Csv -Path $csvFilePath

        # Find the user in the CSV file with exact match on username and domain
        $user = $users | Where-Object { $_.UserName -eq $userName -and $_.DomainName -eq $domainName }

        if (-not $user) {
            Write-Host "User not found $userName in domain $domainName"
            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): User not found $userName in domain $domainName"
            return
        }

        $userId = $user.UserID
        Write-Host "User: $($user.UserName), Domain: $($user.DomainName), UserID: $userId"
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): User: $($user.UserName), Domain: $($user.DomainName), UserID: $userId"

        # Store the user groups in a variable for later use
        $userGroups = @()

        # Read user groups from CSV
        foreach ($group in $user.Groups) {
            $userGroups += [PSCustomObject]@{
                Name = $group.Name
                ID = $group.ID
            }
        }

        $groupCount = $userGroups.Count
        Write-Host "Total groups for user $userName $groupCount"
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Total groups for user $userName $groupCount"

        Write-Host "Groups for user $userName"
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Groups for user $userName"
        foreach ($group in $userGroups) {
            Write-Host "$($group.Name) (ID: $($group.ID))"
            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $($group.Name) (ID: $($group.ID))"
        }

        # Prompt to add a new group
        $addGroup = Read-Host "Do you want to add a new group? (yes/no)"
        if ($addGroup -eq "yes") {
            $newGroupName = Read-Host "Enter the new group name"
            $newGroupDescription = Read-Host "Enter the new group description"
            $newGroupDomain = Read-Host "Enter the domain name for the new group"
            $newGroupForest = Read-Host "Enter the forest name for the new group"
            $bindUser = Read-Host "Enter the bind user for the new group"
            $bindPassword = Read-Host "Enter the bind password for the new group"

            # Check if the group exists in the domain
            if (-not (Check-GroupExists -groupName $newGroupName -domainName $newGroupDomain)) {
                Write-Host "Group $newGroupName does not exist in domain $newGroupDomain. Stopping script."
                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Group $newGroupName does not exist in domain $newGroupDomain. Stopping script."
                return
            }

            $newGroupBody = @{
                groupType = "ActiveDirectory"
                groupName = $newGroupName
                forestName = $newGroupForest
                domainName = $newGroupDomain
                description = $newGroupDescription
                bindUser = $bindUser
                bindPassword = $bindPassword
                useSSL = $false
                isActive = $true
                ExcludedFromGlobalSync = $false
                OverrideGlobalSyncSettings = $false
                Permissions = @(
                    @{ PermissionID = 1; AccessLevelID = 2 }  # Example permission, replace with actual IDs
                )
            }

            $newGroupUri = "${baseUrl}UserGroups"
            Write-Host "Creating new group: $newGroupName"
            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Creating new group: $newGroupName"
            
            $newGroupResult = Invoke-RestMethod -Uri $newGroupUri -Method Post -Headers $headers -Body ($newGroupBody | ConvertTo-Json) -ContentType "application/json" -WebSession $session
            $newGroupId = $newGroupResult.ID
            Write-Host "New group created with ID: $newGroupId"
            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): New group created with ID: $newGroupId"
        } else {
            $existingGroupName = Read-Host "Enter the existing group name"
            $existingGroupDomain = Read-Host "Enter the domain name for the existing group"

            # Check if the existing group exists in the domain
            if (-not (Check-GroupExists -groupName $existingGroupName -domainName $existingGroupDomain)) {
                Write-Host "Group $existingGroupName does not exist in domain $existingGroupDomain. Stopping script."
                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Group $existingGroupName does not exist in domain $existingGroupDomain. Stopping script."
                return
            }

            # Retrieve the existing group ID
            $existingGroupUri = "${baseUrl}UserGroups?filter=groupName eq '$existingGroupName' and domainName eq '$existingGroupDomain'"
            $existingGroupResult = Invoke-RestMethod -Uri $existingGroupUri -Method Get -Headers $headers -WebSession $session
            $existingGroupId = $existingGroupResult.UserGroups[0].ID
            Write-Host "Existing group found with ID: $existingGroupId"
            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Existing group found with ID: $existingGroupId"
        }

        # Add user's groups to the new or existing group
        $targetGroupId = if ($newGroupId) { $newGroupId } else { $existingGroupId }
        foreach ($group in $userGroups) {
            if ($group.Name -eq "lseg.stockex.local\FUNC-BeyondTrust-StandardAccounts") {
                Write-Host "Skipping group $($group.Name)"
                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Skipping group $($group.Name)"
                continue
            }

            $addGroupUri = "${baseUrl}UserGroups/$targetGroupId/SmartRules/$($group.ID)/Roles"
            $addGroupBody = @{
                Roles = @(
                    @{ RoleID = 1 },  # Recorded session reviewer
                    @{ RoleID = 2 }   # Active session reviewer
                )
                AccessPolicyID = 1  # Example access policy ID, replace with actual ID
            }

            Write-Host "Adding group $($group.Name) to group ID $targetGroupId"
            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Adding group $($group.Name) to group ID $targetGroupId"
            
            $confirmation = Read-Host "Confirm adding group $($group.Name) to group ID $targetGroupId (yes/no)"
            if ($confirmation -eq "yes") {
                Invoke-RestMethod -Uri $addGroupUri -Method Post -Headers $headers -Body ($addGroupBody | ConvertTo-Json) -ContentType "application/json" -WebSession $session
            } else {
                Write-Host "Skipping addition of group $($group.Name)"
                Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Skipping addition of group $($group.Name)"
            }
        }

        Write-Host "All groups added to group ID $targetGroupId"
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): All groups added to group ID $targetGroupId"
    } catch {
        Write-Host "Failed to retrieve groups for user $userName $($_.Exception.Message)"
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Failed to retrieve groups for user $userName $($_.Exception.Message)"
    }
}

# Prompt for the username to search
$userName = Read-Host "Enter the username to search for"

# Prompt for the domain name
$domainName = Read-Host "Enter the domain name"

# Prompt for the CSV file path
$csvFilePath = Read-Host "Enter the path to the CSV file"

# Get the groups for the user
Get-UserGroups -userName $userName -domainName $domainName -csvFilePath $csvFilePath
