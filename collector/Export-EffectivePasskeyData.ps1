<#
.SYNOPSIS
    Read-only export of the four files EffectivePasskey analyzes.

.DESCRIPTION
    Signs in with delegated, read-only Microsoft Graph scopes and writes
    policy.json, groups.json, users.json and roles.json to -OutputPath.
    Nothing is changed in the tenant. The analyzer itself never sees a token:
    you export, you analyze, you delete.

    Per-user FIDO2 detail is fetched only for privileged users and users whose
    only MFA is SMS/voice, which keeps per-user Graph calls bounded.

    Also writes conditional_access.json (CA policies and authentication
    strengths) and, with -IncludeSignIns, signins.json for privileged users.

    Requires PowerShell 7+ and the Microsoft.Graph.Authentication module:
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

.EXAMPLE
    ./Export-EffectivePasskeyData.ps1 -OutputPath ./contoso-export
    python3 -m effective_passkey analyze ./contoso-export -o ./contoso-report
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $OutputPath,
    [string] $TenantId,
    # Also export recent sign-ins of privileged users (R16). Needs AuditLog.Read.All and Entra ID P1.
    [switch] $IncludeSignIns,
    [int] $SignInDays = 7
)

$ErrorActionPreference = 'Stop'

$Scopes = @(
    'Policy.Read.All',                   # authentication methods policy, passkey profiles, campaign
    'UserAuthenticationMethod.Read.All', # per-user FIDO2 methods
    'GroupMember.Read.All',              # members of policy-targeted groups
    'RoleManagement.Read.Directory',     # active and eligible role assignments
    'AuditLog.Read.All'                  # userRegistrationDetails report
)

$PrivilegedRoleTemplates = @(
    '62e90394-69f5-4237-9190-012177145e10', 'e8611ab8-c189-46e8-94e1-60213ab1f814',
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', 'c4e39bd9-1100-46d3-8c65-fb160da0071f',
    '194ae4cb-b126-40b2-bd5b-6091b380977d', 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9',
    'fe930be7-5e62-47db-91af-98c3a49a38b1', '29232cdf-9323-42fd-ade2-1d097af3e4de',
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3',
    '158c047a-c907-4556-b7ef-446551a6b5f7', '3a2c62db-5318-420d-8d74-23affee5d9d5',
    '729827e3-9c14-49f7-bb1b-9608f156bbb8', '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2',
    '966707d0-3269-4727-9be2-8c3a10f19b9d'
)
$PhoneMethods = @('mobilePhone', 'alternateMobilePhone', 'officePhone', 'sms', 'voice')
$NonMfaMethods = @('email', 'securityQuestion', 'password', 'temporaryAccessPass')

function Get-GraphAll([string] $Uri) {
    $items = [System.Collections.Generic.List[object]]::new()
    while ($Uri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
        if ($page.value) { $items.AddRange([object[]] $page.value) }
        $Uri = $page.'@odata.nextLink'
    }
    return $items
}

function Write-Json($Object, [string] $Name) {
    $path = Join-Path $OutputPath $Name
    $Object | ConvertTo-Json -Depth 20 | Set-Content -Path $path -Encoding utf8
    Write-Host "wrote $path"
}

New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
$connect = @{ Scopes = $Scopes; NoWelcome = $true }
if ($TenantId) { $connect.TenantId = $TenantId }
Connect-MgGraph @connect

# 1. Policy (beta exposes passkey profiles)
$policy = Invoke-MgGraphRequest -Method GET -OutputType PSObject `
    -Uri 'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy?$expand=authenticationMethodConfigurations'
$org = Invoke-MgGraphRequest -Method GET -OutputType PSObject -Uri 'https://graph.microsoft.com/v1.0/organization?$select=displayName'
$policy | Add-Member -NotePropertyName tenantDisplayName -NotePropertyValue $org.value[0].displayName -Force
Write-Json $policy 'policy.json'

# 1b. Conditional Access policies and authentication strengths (R11, R12, R14)
$caPolicies = Get-GraphAll 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
$strengths = Get-GraphAll 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationStrength/policies'
foreach ($st in $strengths) {
    if ($st.policyType -eq 'custom') {
        $cc = Get-GraphAll "https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationStrength/policies/$($st.id)/combinationConfigurations"
        $st | Add-Member -NotePropertyName combinationConfigurations -NotePropertyValue $cc -Force
    }
}
Write-Json ([pscustomobject]@{ policies = $caPolicies; authenticationStrengths = $strengths }) 'conditional_access.json'

# 2. Role assignments (active + PIM eligible) for privileged roles
$assignments = [System.Collections.Generic.List[object]]::new()
foreach ($tid in $PrivilegedRoleTemplates) {
    foreach ($a in Get-GraphAll "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$tid'") {
        $assignments.Add([pscustomobject]@{ principalId = $a.principalId; roleTemplateId = $tid; assignmentType = 'active' })
    }
    foreach ($a in Get-GraphAll "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=roleDefinitionId eq '$tid'") {
        $assignments.Add([pscustomobject]@{ principalId = $a.principalId; roleTemplateId = $tid; assignmentType = 'eligible' })
    }
}

# 3. Groups: every group the passkey policy or campaign targets, plus role-assignable groups, with nesting
$fido = $policy.authenticationMethodConfigurations | Where-Object { $_.id -eq 'Fido2' }
$tap = $policy.authenticationMethodConfigurations | Where-Object { $_.id -eq 'TemporaryAccessPass' }
$campaign = $policy.registrationEnforcement.authenticationMethodsRegistrationCampaign
$queue = [System.Collections.Generic.Queue[string]]::new()
@($fido.includeTargets) + @($fido.excludeTargets) + @($tap.includeTargets) + @($tap.excludeTargets) +
    @($campaign.includeTargets) + @($campaign.excludeTargets) |
    Where-Object { $_ -and $_.id -ne 'all_users' -and $_.targetType -eq 'group' } |
    ForEach-Object { $queue.Enqueue($_.id) }
foreach ($ca in $caPolicies) {
    @($ca.conditions.users.includeGroups) + @($ca.conditions.users.excludeGroups) |
        Where-Object { $_ } | ForEach-Object { $queue.Enqueue($_) }
}
$assignments | ForEach-Object { $queue.Enqueue($_.principalId) }

$groups = @{}
while ($queue.Count -gt 0) {
    $id = $queue.Dequeue()
    if ($groups.ContainsKey($id)) { continue }
    try {
        $g = Invoke-MgGraphRequest -Method GET -OutputType PSObject -Uri "https://graph.microsoft.com/v1.0/groups/$id`?`$select=id,displayName,isAssignableToRole,membershipRule"
    } catch { continue }  # principal is a user, not a group
    $members = Get-GraphAll "https://graph.microsoft.com/v1.0/groups/$id/members?`$select=id"
    $owners = Get-GraphAll "https://graph.microsoft.com/v1.0/groups/$id/owners?`$select=id"
    $groups[$id] = [pscustomobject]@{
        id = $g.id; displayName = $g.displayName
        isAssignableToRole = [bool] $g.isAssignableToRole; membershipRule = $g.membershipRule
        owners = @($owners | ForEach-Object { $_.id }); members = @($members | ForEach-Object { $_.id })
    }
    $members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' } | ForEach-Object { $queue.Enqueue($_.id) }
}
Write-Json ([pscustomobject]@{ value = @($groups.Values) }) 'groups.json'

# 4. Users: registration details report
$users = Get-GraphAll 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails'
Write-Json ([pscustomobject]@{ value = $users }) 'users.json'

# 5. FIDO2 detail for privileged users and the SMS/voice-only cohort
function Expand-Principal([string] $Id, $Seen) {
    if (-not $groups.ContainsKey($Id)) { return @($Id) }
    if ($Seen.Contains($Id)) { return @() }
    [void] $Seen.Add($Id)
    $groups[$Id].members | ForEach-Object { Expand-Principal $_ $Seen }
}
$deep = [System.Collections.Generic.HashSet[string]]::new()
$assignments | ForEach-Object { Expand-Principal $_.principalId ([System.Collections.Generic.HashSet[string]]::new()) } |
    ForEach-Object { [void] $deep.Add($_) }
foreach ($u in $users) {
    $mfa = @($u.methodsRegistered | Where-Object { $_ -notin $NonMfaMethods })
    if ($mfa.Count -gt 0 -and -not ($mfa | Where-Object { $_ -notin $PhoneMethods })) { [void] $deep.Add($u.id) }
}
$fido2Methods = @{}
foreach ($id in $deep) {
    try {
        $fido2Methods[$id] = @(Get-GraphAll "https://graph.microsoft.com/v1.0/users/$id/authentication/fido2Methods")
    } catch { Write-Warning "could not read FIDO2 methods for $id : $_" }
}
Write-Json ([pscustomobject]@{ roleAssignments = $assignments; fido2Methods = $fido2Methods }) 'roles.json'

# 6. Optional: recent sign-ins of privileged users (R16)
if ($IncludeSignIns) {
    $since = (Get-Date).ToUniversalTime().AddDays(-$SignInDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $privileged = [System.Collections.Generic.HashSet[string]]::new()
    $assignments | ForEach-Object { Expand-Principal $_.principalId ([System.Collections.Generic.HashSet[string]]::new()) } |
        ForEach-Object { [void] $privileged.Add($_) }
    $signIns = [System.Collections.Generic.List[object]]::new()
    foreach ($id in $privileged) {
        $uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=userId eq '$id' and createdDateTime ge $since" +
               "&`$select=userId,userPrincipalName,createdDateTime,appDisplayName,status,authenticationDetails"
        try { (Get-GraphAll $uri) | ForEach-Object { $signIns.Add($_) } }
        catch { Write-Warning "could not read sign-ins for $id : $_" }
    }
    Write-Json ([pscustomobject]@{ value = $signIns }) 'signins.json'
}

Disconnect-MgGraph | Out-Null
Write-Host "Done. Export holds user names and method metadata: keep it local and delete it after analysis."
