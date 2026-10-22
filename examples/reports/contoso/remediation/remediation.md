# Remediation plan: Contoso (synthetic demo)

_Proposed changes for human review. EffectivePasskey never applies changes to a tenant._

## Simulated outcome

Re-running the audit on the proposed configuration:

- Findings before: 13 critical, 12 high, 4 medium, 1 info
- Findings after policy changes: 4 critical, 5 high, 2 medium, 1 info
- Privileged users who can register a synced passkey: 4 → 0
- 19 finding(s) resolved by policy changes; the rest need the user tasks below or a human decision.

**Findings the proposal introduces (review before applying):**

- [high] R5 Registered passkey not accepted by any scoped profile: carol@contoso.example

An R5 here usually means a weak key the user holds stops working once the loose profile no longer covers them. Complete that user's task (register a device-bound key) before applying the change.

## Proposed changes

### C1 · Retarget profile(s) 'Default' from 'All users' to a group without admins

Entra allows a passkey if any scoped profile allows it, so a loose profile on a target that contains admins overrides their strict profile. (fixes R1, R4, R6)

Before:
```json
{
  "target": "All users",
  "targetId": "all_users",
  "privilegedUsersCovered": [
    "alice@contoso.example",
    "bob@contoso.example",
    "carol@contoso.example",
    "erin@contoso.example"
  ]
}
```
After:
```json
{
  "target": "All users (excluding privileged users)",
  "targetId": "ep-proposed-all-users-excluding-privileged-users",
  "members": 2
}
```
> The proposed group is a static snapshot. In production, keep it current with a dynamic membership rule or by excluding your role-assignable admin groups from it.

### C2 · Scope privileged users to 'Admins - device-bound'

Every admin should be scoped to the strict profile, and only to it. (fixes R1)

After:
```json
{
  "target": "Privileged users (passkey admin profile)",
  "profile": "Admins - device-bound",
  "users": [
    "erin@contoso.example"
  ]
}
```
> Prefer targeting your existing role-assignable admin group instead of this snapshot group.

### C3 · Point the registration campaign at passkeys for all users, with limited snoozes

3 SMS/voice-only user(s) need a nudge before their deadline. (fixes R8)

Before:
```json
{
  "state": "enabled",
  "snoozeDurationInDays": 1,
  "enforceRegistrationAfterAllowedSnoozes": false,
  "targets": [
    "All users"
  ],
  "targetedAuthenticationMethod": "passkey"
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

### C4 · Require 'Admins - device-bound keys only' for admins on all apps

Conditional Access must be satisfied by every applicable policy, so one strict policy closes the sign-in gap left by plain MFA or the built-in phishing-resistant strength (which accepts synced passkeys). (fixes R11, R12)

Before:
```json
{
  "adminsWithWeakGate": [
    "alice@contoso.example",
    "bob@contoso.example",
    "carol@contoso.example",
    "erin@contoso.example"
  ]
}
```
After:
```json
{
  "authenticationStrength": {
    "name": "Admins - device-bound keys only",
    "allowedCombinations": [
      "fido2",
      "windowsHelloForBusiness",
      "x509CertificateMultiFactor"
    ],
    "fido2AllowedAAGUIDs": [
      "a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa",
      "cb69481e-8ff7-4039-93ec-0a2729a154a8",
      "ee882879-721c-4913-9775-3dfcce97072a"
    ]
  },
  "policy": "Admins: device-bound keys only (EffectivePasskey)",
  "target": "Privileged users (sign-in and TAP)",
  "breakGlassExcluded": "not targeted"
}
```
> Roll out in report-only first and check sign-in logs for admins without an approved key.
> Emergency-access accounts are left out on purpose; protect them separately.

### C5 · Exclude admins from Temporary Access Pass and make TAP single-use, 60 minutes

Anyone who can issue an admin a TAP can register a passkey on that account. (fixes R13)

Before:
```json
{
  "isUsableOnce": false,
  "maximumLifetimeInMinutes": 480,
  "excluded": []
}
```
After:
```json
{
  "isUsableOnce": true,
  "maximumLifetimeInMinutes": 60,
  "excluded": [
    "Privileged users (TAP excluded)"
  ]
}
```
> Issue admin TAPs only through a documented, two-person process, by temporarily removing the admin from this group.

### C6 · Replace 'CA exclusions (legacy apps)' with a role-assignable group

Only Privileged Role Administrators can change a role-assignable group, so owners and Groups Administrators can no longer move admins in or out of policy scope. (fixes R14)

Before:
```json
{
  "group": "CA exclusions (legacy apps)",
  "isAssignableToRole": false,
  "owners": 1,
  "membershipRule": null
}
```
After:
```json
{
  "group": "CA exclusions (legacy apps) (role-assignable)",
  "isAssignableToRole": true,
  "owners": 0,
  "members": 1
}
```
> isAssignableToRole can only be set when a group is created, so this is a new group.

### C7 · Complete the authentication methods migration

Legacy MFA and SSPR settings keep governing SMS and voice until the migration is marked complete. (fixes R15)

Before:
```json
{
  "policyMigrationState": "migrationInProgress"
}
```
After:
```json
{
  "policyMigrationState": "migrationComplete"
}
```
> Check that the methods policy enables everything users rely on before you complete it.

## User tasks

| User | Task | Rule | Due |
|---|---|---|---|
| carol@contoso.example | Register a device-bound key, then delete the weak passkey | R2 | now |
| erin@contoso.example | Register a device-bound key, then delete the weak passkey | R2 | now |
| bob@contoso.example | Issue and register a device-bound passkey | R7 | now |
| bob@contoso.example | Register a passkey to replace SMS/voice | R3 | 2027-02-01 |
| dave@contoso.example | Register a passkey to replace SMS/voice | R3 | 2027-02-01 |
| frank_partner.example#EXT#@contoso.example | Register a passkey to replace SMS/voice | R3 | 2027-07-01 |

## Still open after the proposal

- [critical] R16 Admin signed in with a synced passkey: carol@contoso.example
- [critical] R2 Privileged user holds a synced passkey: carol@contoso.example
- [critical] R2 Privileged user holds a synced passkey: erin@contoso.example
- [critical] R7 Privileged user has no phishing-resistant method: bob@contoso.example
- [high] R16 Admin still signs in with SMS or voice: bob@contoso.example
- [high] R3 SMS/voice-only user: bob@contoso.example
- [high] R3 SMS/voice-only user: dave@contoso.example
- [high] R3 SMS/voice-only user: frank_partner.example#EXT#@contoso.example
- [info] R16 Users still signing in with SMS or voice: tenant
- [medium] R12 Admin sign-in not gated by any enforced MFA policy: breakglass01@contoso.example
- [medium] R9 Privileged user excluded from passkey policy: breakglass01@contoso.example
