# Rules

| Rule | Name | Fires when | Default severity |
|---|---|---|---|
| R1 | Overlap weakening | A privileged user's union of profiles lets them register a synced passkey (critical) or an unattested device-bound one (high). | critical / high |
| R2 | Weak key already held | A privileged user already holds a synced or unattested passkey. | critical |
| R3 | Deadline cohort | Every MFA method the user has is SMS/voice. Cohort 1 Feb 2027, or 1 Jul 2027 for Global Admins and external users. Critical when policy gives them no way to register a passkey. | high / critical |
| R4 | Auto-enabled admin | A privileged user with phone MFA sits in a profile allowing all passkey types with no attestation or AAGUID limits (the 1 Sep 2026 auto-enable shape). | high |
| R5 | AAGUID trap | A registered key satisfies none of the user's scoped profiles, so it stops working. | high |
| R6 | Attestation illusion | A profile requires attestation but lists synced passkeys; a legacy policy implies synced; or users of an attested profile bypass it through another profile. | medium |
| R7 | No phishing-resistant method | A privileged user has no passkey, WHfB or certificate. | critical |
| R8 | Campaign gap | The registration campaign is off, misses part of the SMS cohort, allows unlimited snoozes, or nudges a non-passkey method. | medium / low |
| R9 | Excluded but privileged | A privileged user is excluded from the FIDO2 policy. Medium if it looks like a break-glass account. | high / medium |
| R10 | Policy hygiene | FIDO2 disabled, many profiles, large AAGUID lists, unused profiles, dangling targets, auto-added Authenticator AAGUIDs. | high / low / info |
| R11 | Synced passkey at sign-in | Every enforced CA policy covering an admin (all apps or admin portals) accepts a synced passkey. Critical if they can also register or already hold one; medium if only registration blocks it. When CA blocks synced passkeys, R1 drops from critical to high and says why. | critical / medium |
| R12 | Weak admin sign-in gate | No enforced CA policy requires MFA or a strength for the admin, or every one accepts SMS/voice. Critical for Global Admins, medium for accounts named like break-glass. | critical / high / medium |
| R13 | TAP bootstrap path | TAP is enabled for the admin. Lists who can issue it (Global Admin and Privileged Authentication Admin; Authentication Admin for Helpdesk/Password admins). High if multi-use or longer than 60 minutes. | high / medium |
| R14 | Tamperable policy group | A group used as a loose-profile target, FIDO2 exclusion, TAP target or CA exclusion for admins has isAssignableToRole = false. Shows owners and dynamic rules. | critical / high / medium |
| R15 | Migration incomplete | policyMigrationState is not migrationComplete. | high / medium |
| R16 | Sign-in evidence | Successful admin sign-ins with a synced passkey (critical) or SMS/voice (high); a count of non-admins still on SMS (info). | critical / high / info |

## Effective credential ladder (higher is weaker)

0. No passkey can be registered
1. Device-bound, attested, allow-listed authenticators only
2. Device-bound, attested, any authenticator
3. Device-bound, unattested (AAGUID is self-reported, so key restrictions are advisory)
4. Synced passkey, allow-listed providers only
5. Synced passkey, any provider, unattested

A user's effective rank is the **maximum** over their scoped profiles.

## Grant semantics used for R11 and R12

- Only enforced policies count; report-only policies are listed in the evidence.
- A policy counts for an admin when it targets all apps or Microsoft Admin Portals and requires MFA, an
  authentication strength, or block.
- Every applicable policy must be satisfied, so a credential is accepted only if every policy accepts it.
- Within a policy, an OR grant is satisfied by any one control. A device control (compliant or joined device) offered
  as an OR alternative lets any credential through. AND grants need all controls.
- A strength accepts synced passkeys when it allows `fido2` with no AAGUID allow list, or with an allow list that
  includes a known synced-provider AAGUID.

## Grade

F: 3+ critical · D: 1-2 critical · C: any high · B: any medium · A: otherwise.
