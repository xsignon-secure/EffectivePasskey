# Remediation plan: Contoso (synthetic demo)

_Proposed changes for human review. EffectivePasskey never applies changes to a tenant._

## Simulated outcome

Re-running the audit on the proposed configuration:

- Findings before: 5 critical, 4 high, 3 medium
- Findings after policy changes: 2 critical, 4 high, 1 medium
- Privileged users who can register a synced passkey: 3 → 0
- 6 finding(s) resolved by policy changes; the rest need the user tasks below or a human decision.

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
    "carol@contoso.example"
  ]
}
```
After:
```json
{
  "target": "All users (excluding privileged users)",
  "targetId": "ep-proposed-all-users-excluding-privileged-users",
  "members": 3
}
```
> The proposed group is a static snapshot. In production, keep it current with a dynamic membership rule or by excluding your role-assignable admin groups from it.

### C2 · Point the registration campaign at passkeys for all users, with limited snoozes

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

## User tasks

| User | Task | Rule | Due |
|---|---|---|---|
| carol@contoso.example | Register a device-bound key, then delete the weak passkey | R2 | now |
| bob@contoso.example | Issue and register a device-bound passkey | R7 | now |
| bob@contoso.example | Register a passkey to replace SMS/voice | R3 | 2027-02-01 |
| dave@contoso.example | Register a passkey to replace SMS/voice | R3 | 2027-02-01 |
| frank_partner.example#EXT#@contoso.example | Register a passkey to replace SMS/voice | R3 | 2027-07-01 |

## Still open after the proposal

- [critical] R2 Privileged user holds a synced passkey: carol@contoso.example
- [critical] R7 Privileged user has no phishing-resistant method: bob@contoso.example
- [high] R3 SMS/voice-only user: bob@contoso.example
- [high] R3 SMS/voice-only user: dave@contoso.example
- [high] R3 SMS/voice-only user: frank_partner.example#EXT#@contoso.example
- [medium] R9 Privileged user excluded from passkey policy: breakglass01@contoso.example
