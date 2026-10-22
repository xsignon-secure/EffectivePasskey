# Export format

A directory with four JSON files. Raw Graph responses (`{"value": [...]}`) are accepted.

## policy.json
`GET /beta/policies/authenticationMethodsPolicy?$expand=authenticationMethodConfigurations`.
The engine reads:
- the FIDO2 config (`@odata.type` contains `fido2`, or `id: "Fido2"`): `state`, `includeTargets`,
  `excludeTargets`, and `passkeyProfiles[]` with `id`, `displayName`, `passkeyTypes`
  (`"deviceBound"`, `"synced"` or `"deviceBound,synced"`), `attestationEnforcement`
  (`"disabled"` or `"registrationOnly"`), `keyRestrictions {isEnforced, enforcementType, aaGuids}`.
  Each include target lists its `passkeyProfileIds`; a target without one gets the default profile.
- If there are no `passkeyProfiles`, the legacy `isAttestationEnforced` and `keyRestrictions`
  become one synthesized Default profile (synced allowed when attestation is off, mirroring
  Microsoft's migration).
- `registrationEnforcement.authenticationMethodsRegistrationCampaign`.
- SMS / voice configs (`state`).
- Optional `tenantDisplayName`.

Graph's passkey profile schema is new; if a real export names a field differently, the loader in
`effective_passkey/model.py` is the one place to adjust.

## groups.json
`{"value": [{"id", "displayName", "members": ["<user or group id>", ...]}]}`. Direct members;
nested groups are resolved by the engine. Include every group the policy or campaign targets and
every group that holds a privileged role. `all_users` needs no entry.

## users.json
`GET /reports/authenticationMethods/userRegistrationDetails`: `id`, `userPrincipalName`,
`userDisplayName`, `userType`, `methodsRegistered`. External users are detected from `#EXT#` in the
UPN (or `identityCategory: "external"`); other guests count as internal guests.

## Optional inputs

These unlock R11 to R16. Without them those rules stay silent and the report lists which inputs it had.

- **policy.json** may also carry `policyMigrationState` and a `temporaryAccessPass` method configuration
  (`state`, `includeTargets`, `excludeTargets`, `isUsableOnce`, `defaultLifetimeInMinutes`, `maximumLifetimeInMinutes`).
- **groups.json** entries may carry `isAssignableToRole`, `owners` (ids) and `membershipRule`.
- **conditional_access.json**: `{"policies": [...], "authenticationStrengths": [...]}` from
  `GET /identity/conditionalAccess/policies` and `.../authenticationStrength/policies`, with each custom strength's
  `combinationConfigurations` (a `fido2CombinationConfiguration` carries `allowedAAGUIDs`). Built-in strengths do not
  need to be listed.
- **signins.json**: `GET /beta/auditLogs/signIns` rows with `userId`, `createdDateTime`, `appDisplayName`, `status`
  and `authenticationDetails[].authenticationMethod`.

## roles.json
```json
{
  "roleAssignments": [{"principalId": "...", "roleTemplateId": "...", "assignmentType": "active|eligible"}],
  "fido2Methods": {"<userId>": [{"id", "displayName", "aaGuid", "attestationLevel", "createdDateTime"}]}
}
```
`principalId` may be a group; it is expanded. `fido2Methods` covers privileged users, the
SMS/voice cohort and, when an AAGUID allow list is enforced, every passkey holder. Any array may be
written as a bare object when it has one item (PowerShell's `ConvertTo-Json` does this); it is read as
a one-item list. A key may carry `passkeyType` explicitly; otherwise it is classified from a list
of known AAGUIDs (extend with `--aaguid-map map.json`, `{"<aaguid>": ["Name", "synced"]}`).
