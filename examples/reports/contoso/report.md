# EffectivePasskey report: Contoso (synthetic demo)

As of 2026-10-22 · grade **F** · EffectivePasskey 0.3.0

- **102 days** to 1 Feb 2027 (SMS/voice retirement); 252 days to 1 Jul 2027 (Global Admins, external users)
- 7 users analyzed, 5 privileged, **4 privileged users can register a synced passkey**
- SMS/voice-only: 2 in the 1 Feb cohort, 1 in the 1 Jul cohort
- Findings: 13 critical, 12 high, 4 medium, 0 low, 1 info

Overlapping passkey profiles resolve by *at least one profile allows it*, not most-restrictive-wins. Each user's effective policy below is the union of every profile they are scoped to.

## Admin attack paths

| Admin | Verdict | Passkey scope | Can register | Holds | Sign-in gate | TAP bootstrap | Signed in with |
|---|---|---|---|---|---|---|---|
| alice@contoso.example | exposed | Default, Admins - device-bound (All users (tenant-wide target); member of group 'Privileged Admins') | Synced passkey, any provider, unattested | device-bound key held | Synced passkey accepted | 1 other user(s) can issue a TAP | FIDO2 security key |
| bob@contoso.example | exposed | Default, Admins - device-bound (All users (tenant-wide target); member of group 'Privileged Admins') | Synced passkey, any provider, unattested | no passkey | Synced passkey accepted | 2 other user(s) can issue a TAP | Text message |
| breakglass01@contoso.example | exposed | - | Excluded from passkey policy | no passkey | No enforced CA policy requires MFA | 1 other user(s) can issue a TAP | no sign-ins in export |
| carol@contoso.example | exposed | Default, Admins - device-bound (All users (tenant-wide target); member of 'Tier 0 Role Holders (role-assignable)' → 'Privileged Admins' (nested)) | Synced passkey, any provider, unattested | synced/unattested key held | Synced passkey accepted | 2 other user(s) can issue a TAP | Passkey (synced) |
| erin@contoso.example | exposed | Default (All users (tenant-wide target)) | Synced passkey, any provider, unattested | synced/unattested key held | SMS/voice accepted | 2 other user(s) can issue a TAP | no sign-ins in export |

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

### [CRITICAL] R1 Privileged user can register a synced passkey: erin@contoso.example

erin@contoso.example (Helpdesk Administrator via group 'Helpdesk') can register: Synced passkey, any provider, unattested. No strict profile covers them at all.

Evidence:
1. erin@contoso.example holds privileged role(s): Helpdesk Administrator via group 'Helpdesk'
2. All users (tenant-wide target) → scoped to profile 'Default'
3. Profile 'Default': deviceBound + synced; no attestation; no AAGUID restriction
4. Microsoft rule: a passkey is allowed if it satisfies at least one scoped profile; there is no most-restrictive-wins.
5. Effective weakest credential: Synced passkey, any provider, unattested (permitted by 'Default')

**Action:** Exclude privileged users from the target(s) 'All users' of the loose profile (e.g. scope it to a group that excludes admins), and scope admins only to a device-bound, attested profile.

### [CRITICAL] R2 Privileged user holds a synced passkey: carol@contoso.example

carol@contoso.example holds 'iPhone passkey' (synced, AAGUID fbfc3007-154e-4ecc-8c0b-6e020557d7bd).

Evidence:
1. carol@contoso.example holds privileged role(s): Privileged Role Administrator (PIM eligible) via group 'Tier 0 Role Holders (role-assignable)'
2. Registered FIDO2 method 'iPhone passkey', model 'iCloud Keychain', AAGUID fbfc3007-154e-4ecc-8c0b-6e020557d7bd
3. Classified as synced; attestation: not attested
4. Created 2026-09-03T14:20:00Z

**Action:** Register a device-bound, attested key for this admin, then remove this passkey.

### [CRITICAL] R2 Privileged user holds a synced passkey: erin@contoso.example

erin@contoso.example holds 'Google Password Manager passkey' (synced, AAGUID ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4).

Evidence:
1. erin@contoso.example holds privileged role(s): Helpdesk Administrator via group 'Helpdesk'
2. Registered FIDO2 method 'Google Password Manager passkey', model 'Google Password Manager', AAGUID ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4
3. Classified as synced; attestation: not attested
4. Created 2026-08-14T10:05:00Z

**Action:** Register a device-bound, attested key for this admin, then remove this passkey.

### [CRITICAL] R7 Privileged user has no phishing-resistant method: bob@contoso.example

bob@contoso.example (Security Administrator) has no passkey, Windows Hello for Business or certificate registered.

Evidence:
1. bob@contoso.example holds privileged role(s): Security Administrator
2. Registered methods: mobilePhone, sms

**Action:** Issue this admin a device-bound passkey (security key or Authenticator) and require it with an authentication strength.

### [CRITICAL] R11 Admin can register and sign in with a synced passkey: alice@contoso.example

alice@contoso.example's sign-in gate accepts synced passkeys and nothing upstream stops one being registered.

Evidence:
1. alice@contoso.example holds privileged role(s)
2. CA 'Admins: require phishing-resistant MFA' requires strength 'Phishing-resistant MFA' (fido2, windowsHelloForBusiness, x509CertificateMultiFactor; any passkey or security key)
3. CA 'All users: require MFA' grant: mfa
4. Conditional Access requires every applicable policy to be satisfied; none of these rejects a synced passkey.
5. Microsoft's built-in 'Phishing-resistant MFA' strength accepts synced passkeys; only a custom strength with a FIDO2 AAGUID allow list of device-bound keys excludes them.
6. Registration also allows a synced passkey

**Action:** Create a custom authentication strength allowing only FIDO2 with your approved device-bound AAGUIDs and require it for admin roles in Conditional Access.

### [CRITICAL] R11 Admin can register and sign in with a synced passkey: bob@contoso.example

bob@contoso.example's sign-in gate accepts synced passkeys and nothing upstream stops one being registered.

Evidence:
1. bob@contoso.example holds privileged role(s)
2. CA 'Admins: require phishing-resistant MFA' requires strength 'Phishing-resistant MFA' (fido2, windowsHelloForBusiness, x509CertificateMultiFactor; any passkey or security key)
3. CA 'All users: require MFA' grant: mfa
4. Conditional Access requires every applicable policy to be satisfied; none of these rejects a synced passkey.
5. Microsoft's built-in 'Phishing-resistant MFA' strength accepts synced passkeys; only a custom strength with a FIDO2 AAGUID allow list of device-bound keys excludes them.
6. Registration also allows a synced passkey

**Action:** Create a custom authentication strength allowing only FIDO2 with your approved device-bound AAGUIDs and require it for admin roles in Conditional Access.

### [CRITICAL] R11 Admin can register and sign in with a synced passkey: carol@contoso.example

carol@contoso.example's sign-in gate accepts synced passkeys and nothing upstream stops one being registered.

Evidence:
1. carol@contoso.example holds privileged role(s)
2. CA 'Admins: require phishing-resistant MFA' requires strength 'Phishing-resistant MFA' (fido2, windowsHelloForBusiness, x509CertificateMultiFactor; any passkey or security key)
3. CA 'All users: require MFA' grant: mfa
4. Conditional Access requires every applicable policy to be satisfied; none of these rejects a synced passkey.
5. Microsoft's built-in 'Phishing-resistant MFA' strength accepts synced passkeys; only a custom strength with a FIDO2 AAGUID allow list of device-bound keys excludes them.
6. Registration also allows a synced passkey

**Action:** Create a custom authentication strength allowing only FIDO2 with your approved device-bound AAGUIDs and require it for admin roles in Conditional Access.

### [CRITICAL] R11 Admin can register and sign in with a synced passkey: erin@contoso.example

erin@contoso.example's sign-in gate accepts synced passkeys and nothing upstream stops one being registered.

Evidence:
1. erin@contoso.example holds privileged role(s)
2. CA 'All users: require MFA' grant: mfa
3. Conditional Access requires every applicable policy to be satisfied; none of these rejects a synced passkey.
4. Microsoft's built-in 'Phishing-resistant MFA' strength accepts synced passkeys; only a custom strength with a FIDO2 AAGUID allow list of device-bound keys excludes them.
5. Registration also allows a synced passkey

**Action:** Create a custom authentication strength allowing only FIDO2 with your approved device-bound AAGUIDs and require it for admin roles in Conditional Access.

### [CRITICAL] R14 Policy group can be changed by non-privileged admins: CA exclusions (legacy apps)

'CA exclusions (legacy apps)' is excluded from CA 'Admins: require phishing-resistant MFA', which covers admins (and 1 more use) but is not role-assignable. Adding an admin to it removes their sign-in requirement.

Evidence:
1. Group 'CA exclusions (legacy apps)' is excluded from CA 'Admins: require phishing-resistant MFA', which covers admins
2. Group 'CA exclusions (legacy apps)' is excluded from CA 'All users: require MFA', which covers admins
3. isAssignableToRole = false, so Groups Administrators, User Administrators and the group's owners can change its membership
4. Owners: dave@contoso.example
5. Adding an admin to it removes their sign-in requirement.

**Action:** Use a role-assignable group (isAssignableToRole = true, no owners) for this target, so only Privileged Role Administrators can change it.

### [CRITICAL] R16 Admin signed in with a synced passkey: carol@contoso.example

1 successful sign-in(s) by carol@contoso.example used a synced passkey.

Evidence:
1. 2026-10-21T09:40:00Z · Microsoft Entra admin center · Passkey (synced)

**Action:** Replace the synced passkey with a device-bound key and block synced passkeys at sign-in (R11).

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

### [HIGH] R12 Admin sign-in accepts SMS or voice: erin@contoso.example

Every CA policy covering erin@contoso.example can be satisfied with SMS or voice MFA.

Evidence:
1. CA 'All users: require MFA' grant: mfa

**Action:** Replace plain MFA with a phishing-resistant authentication strength for admin roles.

### [HIGH] R13 Temporary Access Pass can bootstrap a new passkey on an admin: alice@contoso.example

1 other user(s) can issue alice@contoso.example a TAP and register a passkey with it.

Evidence:
1. TAP is enabled and alice@contoso.example is in its target
2. isUsableOnce = False; maximum lifetime = 480 min
3. 1 other user(s) can issue a TAP to them: breakglass01@contoso.example
4. A TAP lets the holder register a new passkey on the account. Whoever issues it can enrol their own key.

**Action:** Exclude admin groups from the TAP policy (issue admin TAPs through a break-glass process), or set isUsableOnce = true and a maximum lifetime of 60 minutes or less.

### [HIGH] R13 Temporary Access Pass can bootstrap a new passkey on an admin: bob@contoso.example

2 other user(s) can issue bob@contoso.example a TAP and register a passkey with it.

Evidence:
1. TAP is enabled and bob@contoso.example is in its target
2. isUsableOnce = False; maximum lifetime = 480 min
3. 2 other user(s) can issue a TAP to them: alice@contoso.example, breakglass01@contoso.example
4. A TAP lets the holder register a new passkey on the account. Whoever issues it can enrol their own key.

**Action:** Exclude admin groups from the TAP policy (issue admin TAPs through a break-glass process), or set isUsableOnce = true and a maximum lifetime of 60 minutes or less.

### [HIGH] R13 Temporary Access Pass can bootstrap a new passkey on an admin: breakglass01@contoso.example

1 other user(s) can issue breakglass01@contoso.example a TAP and register a passkey with it.

Evidence:
1. TAP is enabled and breakglass01@contoso.example is in its target
2. isUsableOnce = False; maximum lifetime = 480 min
3. 1 other user(s) can issue a TAP to them: alice@contoso.example
4. A TAP lets the holder register a new passkey on the account. Whoever issues it can enrol their own key.

**Action:** Exclude admin groups from the TAP policy (issue admin TAPs through a break-glass process), or set isUsableOnce = true and a maximum lifetime of 60 minutes or less.

### [HIGH] R13 Temporary Access Pass can bootstrap a new passkey on an admin: carol@contoso.example

2 other user(s) can issue carol@contoso.example a TAP and register a passkey with it.

Evidence:
1. TAP is enabled and carol@contoso.example is in its target
2. isUsableOnce = False; maximum lifetime = 480 min
3. 2 other user(s) can issue a TAP to them: alice@contoso.example, breakglass01@contoso.example
4. A TAP lets the holder register a new passkey on the account. Whoever issues it can enrol their own key.

**Action:** Exclude admin groups from the TAP policy (issue admin TAPs through a break-glass process), or set isUsableOnce = true and a maximum lifetime of 60 minutes or less.

### [HIGH] R13 Temporary Access Pass can bootstrap a new passkey on an admin: erin@contoso.example

2 other user(s) can issue erin@contoso.example a TAP and register a passkey with it.

Evidence:
1. TAP is enabled and erin@contoso.example is in its target
2. isUsableOnce = False; maximum lifetime = 480 min
3. 2 other user(s) can issue a TAP to them: alice@contoso.example, breakglass01@contoso.example
4. A TAP lets the holder register a new passkey on the account. Whoever issues it can enrol their own key.

**Action:** Exclude admin groups from the TAP policy (issue admin TAPs through a break-glass process), or set isUsableOnce = true and a maximum lifetime of 60 minutes or less.

### [HIGH] R15 Authentication methods migration not complete: tenant

policyMigrationState is 'migrationInProgress'. Legacy per-user MFA and SSPR settings still decide SMS and voice for 3 user(s) with phone methods, so disabling them in the methods policy alone may not hold.

Evidence:
1. policyMigrationState = migrationInProgress
2. Microsoft retired the legacy MFA and SSPR method settings; the methods policy is the only one that should govern.

**Action:** Finish the migration (Authentication methods > Manage migration > Migration complete).

### [HIGH] R16 Admin still signs in with SMS or voice: bob@contoso.example

1 successful sign-in(s) by bob@contoso.example used SMS or voice.

Evidence:
1. 2026-10-20T08:12:00Z · Azure Portal · Text message

**Action:** Move this admin to a device-bound passkey now; their SMS sign-ins stop working on the retirement date.

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

### [MEDIUM] R12 Admin sign-in not gated by any enforced MFA policy: breakglass01@contoso.example

No enforced Conditional Access policy requires MFA or an authentication strength for breakglass01@contoso.example.

Evidence:
1. breakglass01@contoso.example holds privileged role(s)
2. 3 CA policies exported; none enforced for this user on all apps or admin portals with MFA or a strength
3. Name suggests an emergency-access account. Excluding it from CA can be intentional; it then needs a strong credential, sign-in alerts and a tested procedure.

**Action:** Confirm the emergency-access design and alert on every sign-in by this account.

### [INFO] R16 Users still signing in with SMS or voice: tenant

1 non-admin user(s) signed in with SMS or voice in the exported window.

Evidence:
1. From signins.json

**Action:** Prioritize these users in the registration campaign.

## Effective policy per user

| User | Privileged | Status / weakest credential | Permitted by | SMS cohort | Rules |
|---|---|---|---|---|---|
| alice@contoso.example | Global Administrator | Synced passkey, any provider, unattested | Default | - | R1, R11, R13 |
| bob@contoso.example | Security Administrator | Synced passkey, any provider, unattested | Default | 1 Feb 2027 | R1, R3, R4, R7, R11, R13, R16 |
| carol@contoso.example | Privileged Role Administrator (PIM eligible) via group 'Tier 0 Role Holders (role-assignable)' | Synced passkey, any provider, unattested | Default | - | R1, R2, R11, R13, R16 |
| erin@contoso.example | Helpdesk Administrator via group 'Helpdesk' | Synced passkey, any provider, unattested | Default | - | R1, R2, R11, R12, R13 |
| dave@contoso.example | no | Synced passkey, any provider, unattested | Default | 1 Feb 2027 | R3 |
| frank_partner.example#EXT#@contoso.example | no | Synced passkey, any provider, unattested | Default | 1 Jul 2027 (external user) | R3 |
| breakglass01@contoso.example | Global Administrator | Excluded from passkey policy | - | - | R9, R12, R13 |

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
- **R11 Synced passkey at sign-in**: Every Conditional Access policy covering an admin accepts a synced passkey. Microsoft's built-in phishing-resistant strength does; only a FIDO2 AAGUID allow list stops it.
- **R12 Weak admin sign-in gate**: An admin is covered by no enforced MFA policy, or every policy covering them accepts SMS or voice.
- **R13 TAP bootstrap path**: Temporary Access Pass is enabled for an admin, so anyone who can issue them a TAP can register a passkey on their account.
- **R14 Tamperable policy group**: A group that decides passkey, TAP or Conditional Access scope is not role-assignable, so non-privileged admins or owners can change who is in it.
- **R15 Migration incomplete**: Legacy MFA and SSPR settings still govern SMS and voice because the authentication methods migration is not complete.
- **R16 Sign-in evidence**: Sign-in logs show admins using SMS, voice or synced passkeys.

---

_Per-user FIDO2 detail is exported for privileged users and the SMS/voice cohort only, which keeps Graph calls bounded. Rules that read registered keys (R2, R5) cover that scope._

_Generated offline by EffectivePasskey 0.3.0. No tenant credentials were used by the analyzer._
