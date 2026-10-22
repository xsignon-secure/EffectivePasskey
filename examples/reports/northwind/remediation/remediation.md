# Remediation plan: Northwind (synthetic demo)

_Proposed changes for human review. EffectivePasskey never applies changes to a tenant._

## Simulated outcome

Re-running the audit on the proposed configuration:

- Findings before: 8 critical, 2 high, 2 medium, 1 low
- Findings after policy changes: 2 critical, 5 high
- Privileged users who can register a synced passkey: 1 → 0
- 6 finding(s) resolved by policy changes; the rest need the user tasks below or a human decision.

## Proposed changes

### C1 · Convert legacy FIDO2 settings to an explicit Default passkey profile

Makes the synced-passkey decision explicit instead of inherited from the old attestation toggle. (fixes R6)

After:
```json
{
  "displayName": "Default",
  "passkeyTypes": [
    "deviceBound",
    "synced"
  ],
  "attestation": "off",
  "keyRestriction": "none",
  "weakestCredential": "Synced passkey, any provider, unattested"
}
```

### C2 · Retarget profile(s) 'Default' from 'Passkey Pilot' to a group without admins

Entra allows a passkey if any scoped profile allows it, so a loose profile on a target that contains admins overrides their strict profile. (fixes R1, R4, R6)

Before:
```json
{
  "target": "Passkey Pilot",
  "targetId": "g-pilot",
  "privilegedUsersCovered": [
    "oscar@northwind.example"
  ]
}
```
After:
```json
{
  "target": "Passkey Pilot (excluding privileged users)",
  "targetId": "ep-proposed-passkey-pilot-excluding-privileged-users",
  "members": 1
}
```
> The proposed group is a static snapshot. In production, keep it current with a dynamic membership rule or by excluding your role-assignable admin groups from it.

### C3 · Create profile 'Admins - device-bound, attested'

Admins need a profile that only accepts device-bound, attested passkeys. (fixes R1)

After:
```json
{
  "displayName": "Admins - device-bound, attested",
  "passkeyTypes": [
    "deviceBound"
  ],
  "attestation": "required",
  "keyRestriction": "none",
  "weakestCredential": "Device-bound, attested, any authenticator"
}
```
> Add an AAGUID allow list for your approved security keys.

### C4 · Scope privileged users to 'Admins - device-bound, attested'

Every admin should be scoped to the strict profile, and only to it. (fixes R1)

After:
```json
{
  "target": "Privileged users (passkey admin profile)",
  "profile": "Admins - device-bound, attested",
  "users": [
    "nora@northwind.example",
    "oscar@northwind.example"
  ]
}
```
> Prefer targeting your existing role-assignable admin group instead of this snapshot group.

### C5 · Scope 4 SMS/voice-only user(s) to profile 'Default'

They will get a blocking passkey prompt when SMS/voice retires, but policy does not let them register one. (fixes R3)

After:
```json
{
  "target": "SMS/voice users without a passkey path",
  "profile": "Default",
  "users": [
    "quinn@northwind.example",
    "ravi@northwind.example",
    "sara.contractor@northwind.example",
    "tom_supplier.example#EXT#@northwind.example"
  ]
}
```
> Or widen the existing workforce target so it includes them.

### C6 · Point the registration campaign at passkeys for all users, with limited snoozes

5 SMS/voice-only user(s) need a nudge before their deadline. (fixes R8)

Before:
```json
{
  "state": "enabled",
  "snoozeDurationInDays": 3,
  "enforceRegistrationAfterAllowedSnoozes": true,
  "targets": [
    "Passkey Pilot"
  ],
  "targetedAuthenticationMethod": "microsoftAuthenticator"
}
```
After:
```json
{
  "state": "enabled",
  "snoozeDurationInDays": 3,
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
| nora@northwind.example | Register a passkey to replace SMS/voice | R3 | 2027-07-01 |
| quinn@northwind.example | Register a passkey to replace SMS/voice | R3 | 2027-02-01 |
| ravi@northwind.example | Register a passkey to replace SMS/voice | R3 | 2027-02-01 |
| sara.contractor@northwind.example | Register a passkey to replace SMS/voice | R3 | 2027-02-01 |
| tom_supplier.example#EXT#@northwind.example | Register a passkey to replace SMS/voice | R3 | 2027-07-01 |
| nora@northwind.example | Issue and register a device-bound passkey | R7 | now |
| oscar@northwind.example | Issue and register a device-bound passkey | R7 | now |

## Still open after the proposal

- [critical] R7 Privileged user has no phishing-resistant method: nora@northwind.example
- [critical] R7 Privileged user has no phishing-resistant method: oscar@northwind.example
- [high] R3 SMS/voice-only user: nora@northwind.example (was critical)
- [high] R3 SMS/voice-only user: quinn@northwind.example (was critical)
- [high] R3 SMS/voice-only user: ravi@northwind.example (was critical)
- [high] R3 SMS/voice-only user: sara.contractor@northwind.example (was critical)
- [high] R3 SMS/voice-only user: tom_supplier.example#EXT#@northwind.example (was critical)
