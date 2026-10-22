# EffectivePasskey report: Contoso (synthetic demo)

As of 2026-10-22 · grade **F** · EffectivePasskey 0.1.0

- **102 days** to 1 Feb 2027 (SMS/voice retirement); 252 days to 1 Jul 2027 (Global Admins, external users)
- 7 users analyzed, 4 privileged, **3 privileged users can register a synced passkey**
- SMS/voice-only: 2 in the 1 Feb cohort, 1 in the 1 Jul cohort
- Findings: 5 critical, 4 high, 3 medium, 0 low, 0 info

Overlapping passkey profiles resolve by *at least one profile allows it*, not most-restrictive-wins. Each user's effective policy below is the union of every profile they are scoped to.

## Findings

### [CRITICAL] R1 Privileged user can register a synced passkey: alice@contoso.example

alice@contoso.example (Global Administrator) can register: Synced passkey, any provider, unattested. Their stricter admin profile is overridden.

Evidence:
1. alice@contoso.example holds privileged role(s): Global Administrator
2. All users (tenant-wide target) → scoped to profile 'Default'
3. member of group 'Privileged Admins' → scoped to profile 'Admins - device-bound'
4. Profile 'Default': deviceBound + synced; no attestation; no AAGUID restriction
5. Profile 'Admins - device-bound': deviceBound; attestation required; allow-list of 3 AAGUID(s)
6. Microsoft rule: a passkey is allowed if it satisfies at least one scoped profile; there is no most-restrictive-wins.
7. Effective weakest credential: Synced passkey, any provider, unattested (permitted by 'Default')
8. The stricter profile(s) 'Admins - device-bound' never get a say for this credential.

**Action:** Exclude privileged users from the target(s) 'All users' of the loose profile (e.g. scope it to a group that excludes admins), and scope admins only to a device-bound, attested profile.

### [CRITICAL] R1 Privileged user can register a synced passkey: bob@contoso.example

bob@contoso.example (Security Administrator) can register: Synced passkey, any provider, unattested. Their stricter admin profile is overridden.

Evidence:
1. bob@contoso.example holds privileged role(s): Security Administrator
2. All users (tenant-wide target) → scoped to profile 'Default'
3. member of group 'Privileged Admins' → scoped to profile 'Admins - device-bound'
4. Profile 'Default': deviceBound + synced; no attestation; no AAGUID restriction
5. Profile 'Admins - device-bound': deviceBound; attestation required; allow-list of 3 AAGUID(s)
6. Microsoft rule: a passkey is allowed if it satisfies at least one scoped profile; there is no most-restrictive-wins.
7. Effective weakest credential: Synced passkey, any provider, unattested (permitted by 'Default')
8. The stricter profile(s) 'Admins - device-bound' never get a say for this credential.

**Action:** Exclude privileged users from the target(s) 'All users' of the loose profile (e.g. scope it to a group that excludes admins), and scope admins only to a device-bound, attested profile.

### [CRITICAL] R1 Privileged user can register a synced passkey: carol@contoso.example

carol@contoso.example (Privileged Role Administrator (PIM eligible) via group 'Tier 0 Role Holders (role-assignable)') can register: Synced passkey, any provider, unattested. Their stricter admin profile is overridden.

Evidence:
1. carol@contoso.example holds privileged role(s): Privileged Role Administrator (PIM eligible) via group 'Tier 0 Role Holders (role-assignable)'
2. All users (tenant-wide target) → scoped to profile 'Default'
3. member of 'Tier 0 Role Holders (role-assignable)' → 'Privileged Admins' (nested) → scoped to profile 'Admins - device-bound'
4. Profile 'Default': deviceBound + synced; no attestation; no AAGUID restriction
5. Profile 'Admins - device-bound': deviceBound; attestation required; allow-list of 3 AAGUID(s)
6. Microsoft rule: a passkey is allowed if it satisfies at least one scoped profile; there is no most-restrictive-wins.
7. Effective weakest credential: Synced passkey, any provider, unattested (permitted by 'Default')
8. The stricter profile(s) 'Admins - device-bound' never get a say for this credential.

**Action:** Exclude privileged users from the target(s) 'All users' of the loose profile (e.g. scope it to a group that excludes admins), and scope admins only to a device-bound, attested profile.

### [CRITICAL] R2 Privileged user holds a synced passkey: carol@contoso.example

carol@contoso.example holds 'iPhone passkey' (synced, AAGUID fbfc3007-154e-4ecc-8c0b-6e020557d7bd).

Evidence:
1. carol@contoso.example holds privileged role(s): Privileged Role Administrator (PIM eligible) via group 'Tier 0 Role Holders (role-assignable)'
2. Registered FIDO2 method 'iPhone passkey', model 'iCloud Keychain', AAGUID fbfc3007-154e-4ecc-8c0b-6e020557d7bd
3. Classified as synced; attestation: not attested
4. Created 2026-09-03T14:20:00Z

**Action:** Register a device-bound, attested key for this admin, then remove this passkey.

### [CRITICAL] R7 Privileged user has no phishing-resistant method: bob@contoso.example

bob@contoso.example (Security Administrator) has no passkey, Windows Hello for Business or certificate registered.

Evidence:
1. bob@contoso.example holds privileged role(s): Security Administrator
2. Registered methods: mobilePhone, sms

**Action:** Issue this admin a device-bound passkey (security key or Authenticator) and require it with an authentication strength.

### [HIGH] R3 SMS/voice-only user: bob@contoso.example

bob@contoso.example relies only on mobilePhone, sms. Blocking registration prompt from 1 Feb 2027.

Evidence:
1. Registered MFA methods: mobilePhone, sms (no non-phone MFA method)
2. User category: member
3. Deadline cohort: 1 Feb 2027; 102 day(s) from 2026-10-22
4. Passkey policy status: Synced passkey, any provider, unattested

**Action:** Have the user register a passkey (device-bound preferred) before the deadline.

### [HIGH] R3 SMS/voice-only user: dave@contoso.example

dave@contoso.example relies only on mobilePhone. Blocking registration prompt from 1 Feb 2027.

Evidence:
1. Registered MFA methods: mobilePhone (no non-phone MFA method)
2. User category: member
3. Deadline cohort: 1 Feb 2027; 102 day(s) from 2026-10-22
4. Passkey policy status: Synced passkey, any provider, unattested

**Action:** Have the user register a passkey (device-bound preferred) before the deadline.

### [HIGH] R3 SMS/voice-only user: frank_partner.example#EXT#@contoso.example

frank_partner.example#EXT#@contoso.example relies only on mobilePhone. Blocking registration prompt from 1 Jul 2027 (external user).

Evidence:
1. Registered MFA methods: mobilePhone (no non-phone MFA method)
2. User category: external
3. Deadline cohort: 1 Jul 2027 (external user); 252 day(s) from 2026-10-22
4. Passkey policy status: Synced passkey, any provider, unattested

**Action:** Have the user register a passkey (device-bound preferred) before the deadline.

### [HIGH] R4 Privileged SMS/voice user in an 'all passkey types' profile: bob@contoso.example

bob@contoso.example has phone MFA and sits in 'Default', which allows every passkey type with no attestation.

Evidence:
1. bob@contoso.example holds privileged role(s): Security Administrator
2. Phone methods registered: mobilePhone, sms
3. Microsoft auto-enabled passkeys for SMS/voice users on 1 Sep 2026 in a profile allowing all passkey types.
4. Profile 'Default': deviceBound + synced; no attestation; no AAGUID restriction

**Action:** Move this admin into an admin-only device-bound profile and out of the all-types profile's target.

### [MEDIUM] R6 Attested profile is bypassed by an overlapping profile: Admins - device-bound

3 of 3 users scoped to attested profile 'Admins - device-bound' can still register unattested passkeys through another profile.

Evidence:
1. Users affected: alice@contoso.example, bob@contoso.example, carol@contoso.example
2. Union semantics: the attested profile only constrains users who have no looser profile.

**Action:** Remove the users of 'Admins - device-bound' from the targets of looser profiles, or accept that 'Admins - device-bound' is not an attestation control for them.

### [MEDIUM] R8 Campaign allows unlimited snoozes: tenant

Users can snooze for 1 day(s) indefinitely, so the campaign may never convert them before the deadline.

Evidence:
1. snoozeDurationInDays = 1
2. enforceRegistrationAfterAllowedSnoozes = false

**Action:** Set enforceRegistrationAfterAllowedSnoozes to true.

### [MEDIUM] R9 Privileged user excluded from passkey policy: breakglass01@contoso.example

breakglass01@contoso.example is excluded, so no passkey can be registered or used. Name suggests a break-glass account: confirm this is intentional.

Evidence:
1. breakglass01@contoso.example holds privileged role(s): Global Administrator
2. Exclusion: member of group 'Break-glass accounts'
3. Exclusion wins over every inclusion (Microsoft Learn).

**Action:** Confirm the break-glass design (e.g. certificate-based auth or a dedicated FIDO2 key) is documented and tested.

## Effective policy per user

| User | Privileged | Status / weakest credential | Permitted by | SMS cohort | Rules |
|---|---|---|---|---|---|
| alice@contoso.example | Global Administrator | Synced passkey, any provider, unattested | Default | - | R1 |
| bob@contoso.example | Security Administrator | Synced passkey, any provider, unattested | Default | 1 Feb 2027 | R1, R3, R4, R7 |
| carol@contoso.example | Privileged Role Administrator (PIM eligible) via group 'Tier 0 Role Holders (role-assignable)' | Synced passkey, any provider, unattested | Default | - | R1, R2 |
| dave@contoso.example | no | Synced passkey, any provider, unattested | Default | 1 Feb 2027 | R3 |
| erin@contoso.example | no | Synced passkey, any provider, unattested | Default | - | - |
| frank_partner.example#EXT#@contoso.example | no | Synced passkey, any provider, unattested | Default | 1 Jul 2027 (external user) | R3 |
| breakglass01@contoso.example | Global Administrator | Excluded from passkey policy | - | - | R9 |

## Passkey profiles

| Profile | Types | Attestation | AAGUID restriction | Weakest credential | Users scoped |
|---|---|---|---|---|---|
| Admins - device-bound | deviceBound | required | allow (3) | Device-bound, attested, allow-listed authenticators only | 3 |
| Default | deviceBound, synced | off | none | Synced passkey, any provider, unattested | 6 |

## Rules

- **R1 Overlap weakening**: A privileged user can register a weaker passkey than the admin profile intends, because at least one scoped profile allows it.
- **R2 Weak key already held**: A privileged user already holds a synced or unattested passkey.
- **R3 Deadline cohort**: User's only MFA is SMS or voice. They hit a blocking passkey registration prompt on 1 Feb 2027 (Global Admins and external users: 1 Jul 2027).
- **R4 Auto-enabled admin**: A privileged SMS/voice user sits in an 'all passkey types' profile, the shape Microsoft auto-enabled on 1 Sep 2026.
- **R5 AAGUID trap**: A user holds a passkey that none of their scoped profiles accepts. Microsoft blocks keys whose AAGUID is not permitted, so they lose sign-in with it.
- **R6 Attestation illusion**: A profile is relied on as 'attested' but synced passkeys cannot be attested, or its users can bypass it through another profile.
- **R7 No phishing-resistant method**: A privileged user has no phishing-resistant method registered.
- **R8 Campaign gap**: The registration campaign will not reliably move the SMS/voice cohort to passkeys before the deadline.
- **R9 Excluded but privileged**: A privileged user is excluded from the passkey policy. Exclusion beats every inclusion, so they cannot use passkeys at all.
- **R10 Policy hygiene**: Profile count, list size, unused or dangling references, and auto-added Authenticator AAGUIDs.

---

_Per-user FIDO2 detail is exported for privileged users and the SMS/voice cohort only, which keeps Graph calls bounded. Rules that read registered keys (R2, R5) cover that scope._

_Generated offline by EffectivePasskey 0.1.0. No tenant credentials were used by the analyzer._
