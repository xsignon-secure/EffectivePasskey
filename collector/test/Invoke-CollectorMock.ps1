<#
.SYNOPSIS
    Runs the real collector against a mocked Microsoft Graph built from a demo tenant.

.DESCRIPTION
    Replaces Connect-MgGraph, Invoke-MgGraphRequest and Disconnect-MgGraph with
    functions that answer from the demo tenant's JSON files, including paging,
    $filter by role/user and non-group principals. Lets CI prove the collector
    writes exports the analyzer accepts, without a tenant.

.EXAMPLE
    pwsh ./collector/test/Invoke-CollectorMock.ps1 -Tenant examples/demo-tenants/contoso -OutputPath ./out
#>
param(
    [Parameter(Mandatory)] [string] $Tenant,
    [Parameter(Mandatory)] [string] $OutputPath
)
$ErrorActionPreference = 'Stop'

function Read-Fixture([string] $Name) {
    $path = Join-Path $Tenant $Name
    if (Test-Path $path) { return Get-Content $path -Raw | ConvertFrom-Json }
    return $null
}

$global:EP_Policy = Read-Fixture 'policy.json'
$global:EP_Groups = @((Read-Fixture 'groups.json').value)
$global:EP_Users = @((Read-Fixture 'users.json').value)
$global:EP_Roles = Read-Fixture 'roles.json'
$global:EP_Ca = Read-Fixture 'conditional_access.json'
$global:EP_SignIns = Read-Fixture 'signins.json'
$global:EP_Calls = [System.Collections.Generic.List[string]]::new()

function Page($Items, $Next) {
    $o = [ordered]@{ value = @($Items) }
    if ($Next) { $o['@odata.nextLink'] = $Next }
    return [pscustomobject]$o
}

function global:Connect-MgGraph { param($Scopes, $TenantId, [switch] $NoWelcome) }
function global:Disconnect-MgGraph { }
function global:Invoke-MgGraphRequest {
    param($Method, $Uri, $OutputType)
    $global:EP_Calls.Add($Uri)
    if ($Method -ne 'GET') { throw "collector must only read; got $Method $Uri" }
    switch -Regex ($Uri) {
        'authenticationMethodsPolicy' { return $global:EP_Policy }
        '/organization' { return Page @([pscustomobject]@{ displayName = $global:EP_Policy.tenantDisplayName }) }
        'authenticationStrength/policies/([^/]+)/combinationConfigurations' {
            $id = $Matches[1]
            $st = @($global:EP_Ca.authenticationStrengths) | Where-Object { $_.id -eq $id }
            return Page @($st.combinationConfigurations)
        }
        'authenticationStrength/policies' {
            $list = @($global:EP_Ca.authenticationStrengths) | Where-Object { $_ } | ForEach-Object {
                $c = $_ | Select-Object * -ExcludeProperty combinationConfigurations
                $c | Add-Member -NotePropertyName policyType -NotePropertyValue 'custom' -Force
                $c
            }
            return Page @($list)
        }
        'conditionalAccess/policies' { return Page @($global:EP_Ca.policies | Where-Object { $_ }) }
        "roleAssignments\?\`$filter=roleDefinitionId eq '([^']+)'" {
            $t = $Matches[1]
            return Page @($global:EP_Roles.roleAssignments | Where-Object { $_.roleTemplateId -eq $t -and $_.assignmentType -ne 'eligible' })
        }
        "roleEligibilitySchedules\?\`$filter=roleDefinitionId eq '([^']+)'" {
            $t = $Matches[1]
            return Page @($global:EP_Roles.roleAssignments | Where-Object { $_.roleTemplateId -eq $t -and $_.assignmentType -eq 'eligible' })
        }
        '/groups/([^/?]+)/members' {
            $g = $global:EP_Groups | Where-Object { $_.id -eq $Matches[1] }
            $gids = $global:EP_Groups.id
            return Page @($g.members | ForEach-Object {
                [pscustomobject]@{ id = $_; '@odata.type' = $(if ($_ -in $gids) { '#microsoft.graph.group' } else { '#microsoft.graph.user' }) } })
        }
        '/groups/([^/?]+)/owners' {
            $g = $global:EP_Groups | Where-Object { $_.id -eq $Matches[1] }
            return Page @($g.owners | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ id = $_ } })
        }
        '/groups/([^/?]+)\?' {
            $g = $global:EP_Groups | Where-Object { $_.id -eq $Matches[1] }
            if (-not $g) { throw "Request_ResourceNotFound: $($Matches[1]) is not a group" }
            return $g
        }
        'userRegistrationDetails\?page=2' { return Page @($global:EP_Users | Select-Object -Skip 3) }
        'userRegistrationDetails' { return Page @($global:EP_Users | Select-Object -First 3) ($Uri + '?page=2') }
        '/users/([^/]+)/authentication/fido2Methods' {
            $id = $Matches[1]
            $m = $global:EP_Roles.fido2Methods.$id
            return Page @($m | Where-Object { $_ })
        }
        "auditLogs/signIns\?\`$filter=userId eq '([^']+)'" {
            $id = $Matches[1]
            return Page @($global:EP_SignIns.value | Where-Object { $_.userId -eq $id })
        }
        default { throw "unmocked Graph call: $Uri" }
    }
}

$collector = Join-Path $PSScriptRoot '..' 'Export-EffectivePasskeyData.ps1'
& $collector -OutputPath $OutputPath -IncludeSignIns:([bool] $global:EP_SignIns)
Write-Host "mock Graph calls: $($global:EP_Calls.Count) (all GET)"
