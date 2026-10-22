# Remediation plan: Fabrikam (synthetic demo)

_Proposed changes for human review. EffectivePasskey never applies changes to a tenant._

## Simulated outcome

Re-running the audit on the proposed configuration:

- Findings before: 1 critical, 3 high, 3 medium, 2 low, 1 info
- Findings after policy changes: 1 high, 2 low, 1 info
- Privileged users who can register a synced passkey: 1 → 0
- 6 finding(s) resolved by policy changes; the rest need the user tasks below or a human decision.

## Proposed changes

### C1 · Remove 'synced' from attested profile 'Admins - security keys (attested)'

Synced passkeys cannot be attested, so listing them in an attested profile is misleading. (fixes R6)

Before:
```json
{
  "displayName": "Admins - security keys (attested)",
  "passkeyTypes": [
    "deviceBound",
    "synced"
  ],
  "attestation": "required",
  "keyRestriction": "allow: ['ee882879-721c-4913-9775-3dfcce97072a']",
  "weakestCredential": "Device-bound, attested, allow-listed authenticators only"
}
```
After:
```json
{
  "displayName": "Admins - security keys (attested)",
  "passkeyTypes": [
    "deviceBound"
  ],
  "attestation": "required",
  "keyRestriction": "allow: ['ee882879-721c-4913-9775-3dfcce97072a']",
  "weakestCredential": "Device-bound, attested, allow-listed authenticators only"
}
```

### C2 · Retarget profile(s) 'Contractors' from 'Contractors' to a group without admins

Entra allows a passkey if any scoped profile allows it, so a loose profile on a target that contains admins overrides their strict profile. (fixes R1, R4, R6)

Before:
```json
{
  "target": "Contractors",
  "targetId": "g-contractors",
  "privilegedUsersCovered": [
    "gina@fabrikam.example"
  ]
}
```
After:
```json
{
  "target": "Contractors (excluding privileged users)",
  "targetId": "ep-proposed-contractors-excluding-privileged-users",
  "members": 1
}
```
> The proposed group is a static snapshot. In production, keep it current with a dynamic membership rule or by excluding your role-assignable admin groups from it.

### C3 · Scope privileged users to 'Workforce - Authenticator only'

Every admin should be scoped to the strict profile, and only to it. (fixes R1)

After:
```json
{
  "target": "Privileged users (passkey admin profile)",
  "profile": "Workforce - Authenticator only",
  "users": [
    "gina@fabrikam.example",
    "jack@fabrikam.example"
  ]
}
```
> Prefer targeting your existing role-assignable admin group instead of this snapshot group.

### C4 · Add 1 AAGUID(s) to the allow list of 'Admins - security keys (attested)'

Users hold keys this profile would reject, so they would lose sign-in with them. (fixes R5)

Before:
```json
{
  "aaGuids": [
    "ee882879-721c-4913-9775-3dfcce97072a"
  ]
}
```
After:
```json
{
  "aaGuids": [
    "a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa",
    "ee882879-721c-4913-9775-3dfcce97072a"
  ]
}
```
> Only add AAGUIDs of authenticator models you approve; otherwise have the users re-register.

### C5 · Add 1 AAGUID(s) to the allow list of 'Workforce - Authenticator only'

Users hold keys this profile would reject, so they would lose sign-in with them. (fixes R5)

Before:
```json
{
  "aaGuids": [
    "90a3ccdf-635c-4729-a248-9b709135078f",
    "de1e552d-db1d-4423-a619-566b625cdc84"
  ]
}
```
After:
```json
{
  "aaGuids": [
    "90a3ccdf-635c-4729-a248-9b709135078f",
    "cb69481e-8ff7-4039-93ec-0a2729a154a8",
    "de1e552d-db1d-4423-a619-566b625cdc84"
  ]
}
```
> Only add AAGUIDs of authenticator models you approve; otherwise have the users re-register.

### C6 · Point the registration campaign at passkeys for all users, with limited snoozes

1 SMS/voice-only user(s) need a nudge before their deadline. (fixes R8)

Before:
```json
{
  "state": "disabled",
  "snoozeDurationInDays": null,
  "enforceRegistrationAfterAllowedSnoozes": null,
  "targets": [],
  "targetedAuthenticationMethod": null
}
```
After:
```json
{
  "state": "enabled",
  "snoozeDurationInDays": 1,
  "enforceRegistrationAfterAllowedSnoozes": true,
  "targets": [
    "All users"
  ],
  "targetedAuthenticationMethod": "passkey"
}
```
> Check the targetedAuthenticationMethod value your tenant's Graph version accepts.

## User tasks

| User | Task | Rule | Due |
|---|---|---|---|
| liam@fabrikam.example | Register a passkey to replace SMS/voice | R3 | 2027-02-01 |

## Still open after the proposal

- [high] R3 SMS/voice-only user: liam@fabrikam.example
- [info] R10 Authenticator AAGUIDs in allow list: Workforce - Authenticator only
- [low] R10 Many passkey profiles: tenant
- [low] R10 Profile not targeted by any group: Pilot (unused)
