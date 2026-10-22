# EffectivePasskey report: Northwind (synthetic demo)

As of 2026-10-22 · grade **F** · EffectivePasskey 0.3.0

- **102 days** to 1 Feb 2027 (SMS/voice retirement); 252 days to 1 Jul 2027 (Global Admins, external users)
- 8 users analyzed, 2 privileged, **1 privileged users can register a synced passkey**
- SMS/voice-only: 3 in the 1 Feb cohort, 2 in the 1 Jul cohort
- Findings: 8 critical, 2 high, 2 medium, 1 low, 0 info

Overlapping passkey profiles resolve by *at least one profile allows it*, not most-restrictive-wins. Each user's effective policy below is the union of every profile they are scoped to.

## Admin attack paths

| Admin | Verdict | Passkey scope | Can register | Holds | Sign-in gate |
|---|---|---|---|---|---|
| oscar@northwind.example | exposed | Default (legacy FIDO2 settings) (member of group 'Passkey Pilot') | Synced passkey, any provider, unattested | no passkey | Not evaluated (no Conditional Access export) |
| nora@northwind.example | partial | - | Not targeted by passkey policy | no passkey | Not evaluated (no Conditional Access export) |

## Findings

### [CRITICAL] R1 Privileged user can register a synced passkey: oscar@northwind.example

oscar@northwind.example (User Administrator) can register: Synced passkey, any provider, unattested. No strict profile covers them at all.

Evidence:
1. oscar@northwind.example holds privileged role(s): User Administrator
2. member of group 'Passkey Pilot' → scoped to profile 'Default (legacy FIDO2 settings)'
3. Profile 'Default (legacy FIDO2 settings)': deviceBound + synced; no attestation; no AAGUID restriction
4. Microsoft rule: a passkey is allowed if it satisfies at least one scoped profile; there is no most-restrictive-wins.
5. Effective weakest credential: Synced passkey, any provider, unattested (permitted by 'Default (legacy FIDO2 settings)')

**Action:** Exclude privileged users from the target(s) 'Passkey Pilot' of the loose profile (e.g. scope it to a group that excludes admins), and scope admins only to a device-bound, attested profile.

### [CRITICAL] R3 SMS/voice-only user with no passkey path: nora@northwind.example

nora@northwind.example relies only on mobilePhone, officePhone. Blocking registration prompt from 1 Jul 2027 (Global Admin).

Evidence:
1. Registered MFA methods: mobilePhone, officePhone (no non-phone MFA method)
2. User category: member, Global Administrator
3. Deadline cohort: 1 Jul 2027 (Global Admin); 252 day(s) from 2026-10-22
4. Passkey policy status: Not targeted by passkey policy
5. They will be prompted to register a passkey, but current policy does not let them register one.

**Action:** Fix policy targeting first (they are not targeted by passkey policy), then have them register a passkey.

### [CRITICAL] R3 SMS/voice-only user with no passkey path: quinn@northwind.example

quinn@northwind.example relies only on mobilePhone. Blocking registration prompt from 1 Feb 2027.

Evidence:
1. Registered MFA methods: mobilePhone (no non-phone MFA method)
2. User category: member
3. Deadline cohort: 1 Feb 2027; 102 day(s) from 2026-10-22
4. Passkey policy status: Not targeted by passkey policy
5. They will be prompted to register a passkey, but current policy does not let them register one.

**Action:** Fix policy targeting first (they are not targeted by passkey policy), then have them register a passkey.

### [CRITICAL] R3 SMS/voice-only user with no passkey path: ravi@northwind.example

ravi@northwind.example relies only on mobilePhone. Blocking registration prompt from 1 Feb 2027.

Evidence:
1. Registered MFA methods: mobilePhone (no non-phone MFA method)
2. User category: member
3. Deadline cohort: 1 Feb 2027; 102 day(s) from 2026-10-22
4. Passkey policy status: Not targeted by passkey policy
5. They will be prompted to register a passkey, but current policy does not let them register one.

**Action:** Fix policy targeting first (they are not targeted by passkey policy), then have them register a passkey.

### [CRITICAL] R3 SMS/voice-only user with no passkey path: sara.contractor@northwind.example

sara.contractor@northwind.example relies only on mobilePhone. Blocking registration prompt from 1 Feb 2027 (internal guest).

Evidence:
1. Registered MFA methods: mobilePhone (no non-phone MFA method)
2. User category: internalGuest
3. Deadline cohort: 1 Feb 2027 (internal guest); 102 day(s) from 2026-10-22
4. Passkey policy status: Not targeted by passkey policy
5. They will be prompted to register a passkey, but current policy does not let them register one.

**Action:** Fix policy targeting first (they are not targeted by passkey policy), then have them register a passkey.

### [CRITICAL] R3 SMS/voice-only user with no passkey path: tom_supplier.example#EXT#@northwind.example

tom_supplier.example#EXT#@northwind.example relies only on mobilePhone. Blocking registration prompt from 1 Jul 2027 (external user).

Evidence:
1. Registered MFA methods: mobilePhone (no non-phone MFA method)
2. User category: external
3. Deadline cohort: 1 Jul 2027 (external user); 252 day(s) from 2026-10-22
4. Passkey policy status: Not targeted by passkey policy
5. They will be prompted to register a passkey, but current policy does not let them register one.

**Action:** Fix policy targeting first (they are not targeted by passkey policy), then have them register a passkey.

### [CRITICAL] R7 Privileged user has no phishing-resistant method: nora@northwind.example

nora@northwind.example (Global Administrator) has no passkey, Windows Hello for Business or certificate registered.

Evidence:
1. nora@northwind.example holds privileged role(s): Global Administrator
2. Registered methods: mobilePhone, officePhone

**Action:** Issue this admin a device-bound passkey (security key or Authenticator) and require it with an authentication strength.

### [CRITICAL] R7 Privileged user has no phishing-resistant method: oscar@northwind.example

oscar@northwind.example (User Administrator) has no passkey, Windows Hello for Business or certificate registered.

Evidence:
1. oscar@northwind.example holds privileged role(s): User Administrator
2. Registered methods: microsoftAuthenticatorPush, mobilePhone

**Action:** Issue this admin a device-bound passkey (security key or Authenticator) and require it with an authentication strength.

### [HIGH] R4 Privileged SMS/voice user in an 'all passkey types' profile: oscar@northwind.example

oscar@northwind.example has phone MFA and sits in 'Default (legacy FIDO2 settings)', which allows every passkey type with no attestation.

Evidence:
1. oscar@northwind.example holds privileged role(s): User Administrator
2. Phone methods registered: mobilePhone
3. Microsoft auto-enabled passkeys for SMS/voice users on 1 Sep 2026 in a profile allowing all passkey types.
4. Profile 'Default (legacy FIDO2 settings)': deviceBound + synced; no attestation; no AAGUID restriction

**Action:** Move this admin into an admin-only device-bound profile and out of the all-types profile's target.

### [HIGH] R14 Policy group can be changed by non-privileged admins: Passkey Pilot

'Passkey Pilot' targets a passkey profile that allows synced passkeys but is not role-assignable. Adding an admin to it lets them register a synced passkey (R1).

Evidence:
1. Group 'Passkey Pilot' targets a passkey profile that allows synced passkeys
2. isAssignableToRole = false, so Groups Administrators, User Administrators and the group's owners can change its membership
3. Adding an admin to it lets them register a synced passkey (R1).

**Action:** Use a role-assignable group (isAssignableToRole = true, no owners) for this target, so only Privileged Role Administrators can change it.

### [MEDIUM] R6 Legacy FIDO2 settings imply synced passkeys: Default (legacy FIDO2 settings)

This tenant has no passkey profiles in the export. Microsoft's migration derives passkey type from the old attestation toggle, so with attestation off, synced passkeys are allowed.

Evidence:
1. policy.json FIDO2 config has no passkeyProfiles
2. isAttestationEnforced is false

**Action:** Create explicit passkey profiles and decide on synced passkeys deliberately.

### [MEDIUM] R8 Campaign misses part of the SMS/voice cohort: tenant

5 of 5 SMS/voice-only users are not targeted (or are excluded) by the campaign.

Evidence:
1. Not covered: nora@northwind.example, quinn@northwind.example, ravi@northwind.example, sara.contractor@northwind.example, tom_supplier.example#EXT#@northwind.example

**Action:** Target the campaign at all users, or at a group containing the whole cohort.

### [LOW] R8 Campaign nudges a non-passkey method: tenant

The campaign targets 'microsoftAuthenticator', not passkeys.

Evidence:
1. targetedAuthenticationMethod = microsoftAuthenticator

**Action:** Point the campaign at passkeys if your goal is phishing-resistant MFA for this cohort.

## Effective policy per user

| User | Privileged | Status / weakest credential | Permitted by | SMS cohort | Rules |
|---|---|---|---|---|---|
| oscar@northwind.example | User Administrator | Synced passkey, any provider, unattested | Default (legacy FIDO2 settings) | - | R1, R4, R7 |
| paula@northwind.example | no | Synced passkey, any provider, unattested | Default (legacy FIDO2 settings) | - | - |
| nora@northwind.example | Global Administrator | Not targeted by passkey policy | - | 1 Jul 2027 (Global Admin) | R3, R7 |
| quinn@northwind.example | no | Not targeted by passkey policy | - | 1 Feb 2027 | R3 |
| ravi@northwind.example | no | Not targeted by passkey policy | - | 1 Feb 2027 | R3 |
| sara.contractor@northwind.example | no | Not targeted by passkey policy | - | 1 Feb 2027 (internal guest) | R3 |
| tom_supplier.example#EXT#@northwind.example | no | Not targeted by passkey policy | - | 1 Jul 2027 (external user) | R3 |
| uma@northwind.example | no | Not targeted by passkey policy | - | - | - |

## Passkey profiles

| Profile | Types | Attestation | AAGUID restriction | Weakest credential | Users scoped |
|---|---|---|---|---|---|
| Default (legacy FIDO2 settings) | deviceBound, synced | off | none | Synced passkey, any provider, unattested | 2 |

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
- **R11 Synced passkey at sign-in**: Every Conditional Access policy covering an admin accepts a synced passkey. Microsoft's built-in phishing-resistant strength does; only a FIDO2 AAGUID allow list stops it.
- **R12 Weak admin sign-in gate**: An admin is covered by no enforced MFA policy, or every policy covering them accepts SMS or voice.
- **R13 TAP bootstrap path**: Temporary Access Pass is enabled for an admin, so anyone who can issue them a TAP can register a passkey on their account.
- **R14 Tamperable policy group**: A group that decides passkey, TAP or Conditional Access scope is not role-assignable, so non-privileged admins or owners can change who is in it.
- **R15 Migration incomplete**: Legacy MFA and SSPR settings still govern SMS and voice because the authentication methods migration is not complete.
- **R16 Sign-in evidence**: Sign-in logs show admins using SMS, voice or synced passkeys.

---

_Per-user FIDO2 detail is exported for privileged users and the SMS/voice cohort only, which keeps Graph calls bounded. Rules that read registered keys (R2, R5) cover that scope._

_Generated offline by EffectivePasskey 0.3.0. No tenant credentials were used by the analyzer._
