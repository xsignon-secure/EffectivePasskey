# EffectivePasskey report: Fabrikam (synthetic demo)

As of 2026-10-22 · grade **C** · EffectivePasskey 0.3.0

- **102 days** to 1 Feb 2027 (SMS/voice retirement); 252 days to 1 Jul 2027 (Global Admins, external users)
- 6 users analyzed, 2 privileged, **1 privileged users can register a synced passkey**
- SMS/voice-only: 1 in the 1 Feb cohort, 0 in the 1 Jul cohort
- Findings: 0 critical, 5 high, 5 medium, 2 low, 1 info

Overlapping passkey profiles resolve by *at least one profile allows it*, not most-restrictive-wins. Each user's effective policy below is the union of every profile they are scoped to.

## Admin attack paths

| Admin | Verdict | Passkey scope | Can register | Holds | Sign-in gate | TAP bootstrap |
|---|---|---|---|---|---|---|
| gina@fabrikam.example | exposed | Contractors, Admins - security keys (attested) (member of 'Vendors EU' → 'Contractors' (nested); member of group 'IT Admins') | Synced passkey, any provider, unattested | device-bound key held | Device-bound, approved keys only | 1 other user(s) can issue a TAP |
| jack@fabrikam.example | exposed | Admins - security keys (attested) (member of group 'IT Admins') | Device-bound, attested, allow-listed authenticators only | device-bound key held | Device-bound, approved keys only | 0 other user(s) can issue a TAP |

## Findings

### [HIGH] R1 Privileged user can register a synced passkey: gina@fabrikam.example

gina@fabrikam.example (Exchange Administrator) can register: Synced passkey, any provider, unattested. Their stricter admin profile is overridden.

Evidence:
1. gina@fabrikam.example holds privileged role(s): Exchange Administrator
2. member of 'Vendors EU' → 'Contractors' (nested) → scoped to profile 'Contractors'
3. member of group 'IT Admins' → scoped to profile 'Admins - security keys (attested)'
4. Profile 'Contractors': deviceBound + synced; no attestation; no AAGUID restriction
5. Profile 'Admins - security keys (attested)': deviceBound + synced; attestation required; allow-list of 1 AAGUID(s)
6. Microsoft rule: a passkey is allowed if it satisfies at least one scoped profile; there is no most-restrictive-wins.
7. Effective weakest credential: Synced passkey, any provider, unattested (permitted by 'Contractors')
8. The stricter profile(s) 'Admins - security keys (attested)' never get a say for this credential.
9. Sign-in gate: 'IT Admins: approved security keys only' rejects synced passkeys, so a registered synced passkey cannot be used to sign in to covered apps. Registration is still weaker than intended.

**Action:** Exclude privileged users from the target(s) 'Contractors' of the loose profile (e.g. scope it to a group that excludes admins), and scope admins only to a device-bound, attested profile.

### [HIGH] R3 SMS/voice-only user: liam@fabrikam.example

liam@fabrikam.example relies only on sms. Blocking registration prompt from 1 Feb 2027.

Evidence:
1. Registered MFA methods: sms (no non-phone MFA method)
2. User category: member
3. Deadline cohort: 1 Feb 2027; 102 day(s) from 2026-10-22
4. Passkey policy status: Device-bound, attested, allow-listed authenticators only

**Action:** Have the user register a passkey (device-bound preferred) before the deadline.

### [HIGH] R5 Registered passkey not accepted by any scoped profile: hank@fabrikam.example

hank@fabrikam.example's key 'YubiKey 5' (AAGUID cb69481e-8ff7-4039-93ec-0a2729a154a8) satisfies none of their profiles.

Evidence:
1. Registered key: YubiKey 5, deviceBound, AAGUID cb69481e-8ff7-4039-93ec-0a2729a154a8
2. Profile 'Workforce - Authenticator only': deviceBound; attestation required; allow-list of 2 AAGUID(s) → rejects this key

**Action:** Add AAGUID cb69481e-8ff7-4039-93ec-0a2729a154a8 to an allow list that covers this user, or have them register a permitted key before the change lands.

### [HIGH] R5 Registered passkey not accepted by any scoped profile: jack@fabrikam.example

jack@fabrikam.example's key 'YubiKey 5 NFC (FW 5.7)' (AAGUID a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa) satisfies none of their profiles.

Evidence:
1. Registered key: YubiKey 5 NFC (FW 5.7), deviceBound, AAGUID a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa
2. Profile 'Admins - security keys (attested)': deviceBound + synced; attestation required; allow-list of 1 AAGUID(s) → rejects this key

**Action:** Add AAGUID a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa to an allow list that covers this user, or have them register a permitted key before the change lands.

### [HIGH] R14 Policy group can be changed by non-privileged admins: Contractors

'Contractors' targets a passkey profile that allows synced passkeys but is not role-assignable. Adding an admin to it lets them register a synced passkey (R1).

Evidence:
1. Group 'Contractors' targets a passkey profile that allows synced passkeys
2. isAssignableToRole = false, so Groups Administrators, User Administrators and the group's owners can change its membership
3. Dynamic membership rule: user.companyName -eq "Vendor" (whoever can edit those user attributes controls membership)
4. Adding an admin to it lets them register a synced passkey (R1).

**Action:** Use a role-assignable group (isAssignableToRole = true, no owners) for this target, so only Privileged Role Administrators can change it.

### [MEDIUM] R6 Attested profile lists synced passkeys: Admins - security keys (attested)

'Admins - security keys (attested)' requires attestation and also lists synced passkeys. Synced passkeys cannot be attested, so that setting is dead weight and suggests a misunderstanding.

Evidence:
1. Profile 'Admins - security keys (attested)': deviceBound + synced; attestation required; allow-list of 1 AAGUID(s)
2. Attestation is not possible for synced passkeys (Microsoft Learn).

**Action:** Remove 'synced' from this profile, or drop the attestation claim and document it as a synced profile.

### [MEDIUM] R6 Attested profile is bypassed by an overlapping profile: Admins - security keys (attested)

1 of 2 users scoped to attested profile 'Admins - security keys (attested)' can still register unattested passkeys through another profile.

Evidence:
1. Users affected: gina@fabrikam.example
2. Union semantics: the attested profile only constrains users who have no looser profile.

**Action:** Remove the users of 'Admins - security keys (attested)' from the targets of looser profiles, or accept that 'Admins - security keys (attested)' is not an attestation control for them.

### [MEDIUM] R8 Registration campaign is off: tenant

1 SMS/voice-only user(s) and no registration campaign to nudge them before the deadline.

Evidence:
1. Campaign state: disabled

**Action:** Enable the registration campaign for the SMS/voice cohort, targeting passkeys, with limited snoozes.

### [MEDIUM] R13 Temporary Access Pass can bootstrap a new passkey on an admin: gina@fabrikam.example

1 other user(s) can issue gina@fabrikam.example a TAP and register a passkey with it.

Evidence:
1. TAP is enabled and gina@fabrikam.example is in its target
2. isUsableOnce = True; maximum lifetime = 60 min
3. 1 other user(s) can issue a TAP to them: jack@fabrikam.example
4. A TAP lets the holder register a new passkey on the account. Whoever issues it can enrol their own key.

**Action:** Exclude admin groups from the TAP policy (issue admin TAPs through a break-glass process), or set isUsableOnce = true and a maximum lifetime of 60 minutes or less.

### [MEDIUM] R13 Temporary Access Pass can bootstrap a new passkey on an admin: jack@fabrikam.example

0 other user(s) can issue jack@fabrikam.example a TAP and register a passkey with it.

Evidence:
1. TAP is enabled and jack@fabrikam.example is in its target
2. isUsableOnce = True; maximum lifetime = 60 min
3. 0 other user(s) can issue a TAP to them: none listed
4. A TAP lets the holder register a new passkey on the account. Whoever issues it can enrol their own key.

**Action:** Exclude admin groups from the TAP policy (issue admin TAPs through a break-glass process), or set isUsableOnce = true and a maximum lifetime of 60 minutes or less.

### [LOW] R10 Profile not targeted by any group: Pilot (unused)

'Pilot (unused)' is defined but no include target uses it. It protects nobody.

Evidence:

**Action:** Target it at the intended group or delete it.

### [LOW] R10 Many passkey profiles: tenant

4 profiles (soft threshold 3). More profiles mean more overlap to reason about.

Evidence:
1. Workforce - Authenticator only, Admins - security keys (attested), Contractors, Pilot (unused)

**Action:** Consolidate to an admin profile and a workforce profile where possible.

### [INFO] R10 Authenticator AAGUIDs in allow list: Workforce - Authenticator only

'Workforce - Authenticator only' allows Microsoft Authenticator AAGUIDs, which Entra adds automatically when Authenticator passkeys are enabled.

Evidence:
1. AAGUIDs: 90a3ccdf-635c-4729-a248-9b709135078f, de1e552d-db1d-4423-a619-566b625cdc84

**Action:** Confirm Authenticator passkeys are intended for the users of this profile.

## Effective policy per user

| User | Privileged | Status / weakest credential | Permitted by | SMS cohort | Rules |
|---|---|---|---|---|---|
| gina@fabrikam.example | Exchange Administrator | Synced passkey, any provider, unattested | Contractors | - | R1, R13 |
| kim@vendor.example | no | Synced passkey, any provider, unattested | Contractors | - | - |
| jack@fabrikam.example | Global Administrator | Device-bound, attested, allow-listed authenticators only | Admins - security keys (attested) | - | R5, R13 |
| hank@fabrikam.example | no | Device-bound, attested, allow-listed authenticators only | Workforce - Authenticator only | - | R5 |
| ivy@fabrikam.example | no | Device-bound, attested, allow-listed authenticators only | Workforce - Authenticator only | - | - |
| liam@fabrikam.example | no | Device-bound, attested, allow-listed authenticators only | Workforce - Authenticator only | 1 Feb 2027 | R3 |

## Passkey profiles

| Profile | Types | Attestation | AAGUID restriction | Weakest credential | Users scoped |
|---|---|---|---|---|---|
| Workforce - Authenticator only | deviceBound | required | allow (2) | Device-bound, attested, allow-listed authenticators only | 3 |
| Admins - security keys (attested) | deviceBound, synced | required | allow (1) | Device-bound, attested, allow-listed authenticators only | 2 |
| Contractors | deviceBound, synced | off | none | Synced passkey, any provider, unattested | 2 |
| Pilot (unused) | deviceBound | off | none | Device-bound, unattested (authenticator model not verified) | 0 |

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
