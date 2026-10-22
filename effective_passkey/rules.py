"""The ten audit rules (R1 to R10).

Every finding carries an evidence chain: the ordered facts that lead from the
exports to the conclusion, so a consultant can defend it in front of a client.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from .constants import (
    AUTHENTICATOR_AAGUIDS,
    MAX_AAGUIDS_SOFT,
    MAX_PROFILES_SOFT,
    NON_MFA_METHODS,
    PHISHING_RESISTANT_METHODS,
    PHONE_METHODS,
    SEVERITY_ORDER,
    SMS_RETIREMENT_LATE,
    SMS_RETIREMENT_MAIN,
)
from .deep import DeepRules
from .resolver import RANK_LABELS, EffectivePolicy, Resolver
from .model import Tenant, User

RULES = {
    "R1": ("Overlap weakening", "A privileged user can register a weaker passkey than the admin profile intends, because at least one scoped profile allows it."),
    "R2": ("Weak key already held", "A privileged user already holds a synced or unattested passkey."),
    "R3": ("Deadline cohort", "User's only MFA is SMS or voice. They hit a blocking passkey registration prompt on 1 Feb 2027 (Global Admins and external users: 1 Jul 2027)."),
    "R4": ("Auto-enabled admin", "A privileged SMS/voice user sits in an 'all passkey types' profile, the shape Microsoft auto-enabled on 1 Sep 2026."),
    "R5": ("AAGUID trap", "A user holds a passkey that none of their scoped profiles accepts. Microsoft blocks keys whose AAGUID is not permitted, so they lose sign-in with it."),
    "R6": ("Attestation illusion", "A profile is relied on as 'attested' but synced passkeys cannot be attested, or its users can bypass it through another profile."),
    "R7": ("No phishing-resistant method", "A privileged user has no phishing-resistant method registered."),
    "R8": ("Campaign gap", "The registration campaign will not reliably move the SMS/voice cohort to passkeys before the deadline."),
    "R9": ("Excluded but privileged", "A privileged user is excluded from the passkey policy. Exclusion beats every inclusion, so they cannot use passkeys at all."),
    "R10": ("Policy hygiene", "Profile count, list size, unused or dangling references, and auto-added Authenticator AAGUIDs."),
    "R11": ("Synced passkey at sign-in", "Every Conditional Access policy covering an admin accepts a synced passkey. Microsoft's built-in phishing-resistant strength does; only a FIDO2 AAGUID allow list stops it."),
    "R12": ("Weak admin sign-in gate", "An admin is covered by no enforced MFA policy, or every policy covering them accepts SMS or voice."),
    "R13": ("TAP bootstrap path", "Temporary Access Pass is enabled for an admin, so anyone who can issue them a TAP can register a passkey on their account."),
    "R14": ("Tamperable policy group", "A group that decides passkey, TAP or Conditional Access scope is not role-assignable, so non-privileged admins or owners can change who is in it."),
    "R15": ("Migration incomplete", "Legacy MFA and SSPR settings still govern SMS and voice because the authentication methods migration is not complete."),
    "R16": ("Sign-in evidence", "Sign-in logs show admins using SMS, voice or synced passkeys."),
}


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    subject: str  # user UPN, profile name, or "tenant"
    subject_type: str  # "user", "profile", "tenant"
    detail: str
    evidence: list[str] = field(default_factory=list)
    action: str = ""
    cohort: str = ""
    user_id: str = ""
    variant: str = ""  # stable identity when the title changes with severity

    @property
    def key(self) -> str:
        """Stable identity across runs, used by the diff."""
        return f"{self.rule}|{self.subject_type}|{self.subject}|{self.variant or self.title}"

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "rule": self.rule,
            "ruleName": RULES[self.rule][0],
            "severity": self.severity,
            "title": self.title,
            "subject": self.subject,
            "subjectType": self.subject_type,
            "userId": self.user_id,
            "cohort": self.cohort,
            "detail": self.detail,
            "evidence": self.evidence,
            "action": self.action,
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], int(f.rule[1:]), f.subject))


# ------------------------------------------------------------ user facts


def phone_only(user: User) -> bool:
    """True if every MFA method the user has registered is SMS or voice."""
    mfa = user.methods - NON_MFA_METHODS
    return bool(mfa) and mfa <= PHONE_METHODS


def has_phishing_resistant(user: User) -> bool:
    return bool(user.methods & PHISHING_RESISTANT_METHODS) or bool(user.keys)


def deadline_for(user: User) -> tuple[date, str]:
    if user.is_global_admin:
        return SMS_RETIREMENT_LATE, "1 Jul 2027 (Global Admin)"
    if user.category == "external":
        return SMS_RETIREMENT_LATE, "1 Jul 2027 (external user)"
    if user.category == "internalGuest":
        return SMS_RETIREMENT_MAIN, "1 Feb 2027 (internal guest)"
    return SMS_RETIREMENT_MAIN, "1 Feb 2027"


def role_names(user: User) -> str:
    parts = []
    for r in user.roles:
        s = r["name"]
        if r["assignment"].lower() == "eligible":
            s += " (PIM eligible)"
        if r.get("via"):
            s += f" via group '{r['via']}'"
        parts.append(s)
    return ", ".join(dict.fromkeys(parts))


# ------------------------------------------------------------ engine


class Auditor:
    def __init__(self, tenant: Tenant, as_of: date):
        self.tenant = tenant
        self.as_of = as_of
        self.resolver = Resolver(tenant)
        self.policies: dict[str, EffectivePolicy] = self.resolver.resolve_all()
        self.findings: list[Finding] = []

    # -- evidence helpers

    def _profile_line(self, p) -> str:
        types = " + ".join(sorted(p.passkey_types)) or "none"
        att = "attestation required" if p.attestation_enforced else "no attestation"
        if p.key_restriction_enforced:
            kr = f"{p.key_restriction_type}-list of {len(p.aaguids)} AAGUID(s)"
        else:
            kr = "no AAGUID restriction"
        return f"Profile '{p.name}': {types}; {att}; {kr}"

    def _scope_lines(self, pol: EffectivePolicy) -> list[str]:
        lines = []
        for sp in pol.profiles:
            for m in sp.via:
                lines.append(f"{self.resolver.describe_path(m)} → scoped to profile '{sp.profile.name}'")
        return lines

    def _privileged_line(self, user: User) -> str:
        return f"{user.label} holds privileged role(s): {role_names(user)}"

    def add(self, **kw):
        self.findings.append(Finding(**kw))

    # -- rules

    def run(self) -> list[Finding]:
        for uid, pol in self.policies.items():
            u = pol.user
            self.r1(u, pol)
            self.r2(u)
            self.r3(u, pol)
            self.r4(u, pol)
            self.r5(u, pol)
            self.r7(u)
            self.r9(u, pol)
        self.r6()
        self.r8()
        self.r10()
        self.deep = DeepRules(self)
        self.deep.run()
        self.findings = sort_findings(self.findings)
        return self.findings

    def r1(self, u: User, pol: EffectivePolicy):
        if not u.is_privileged or pol.rank < 3:
            return
        loose = pol.loosest_profiles()
        strict = [sp for sp in pol.profiles if sp.rank <= 2]
        ev = [self._privileged_line(u)] + self._scope_lines(pol)
        ev += [self._profile_line(sp.profile) for sp in pol.profiles]
        ev.append("Microsoft rule: a passkey is allowed if it satisfies at least one scoped profile; there is no most-restrictive-wins.")
        ev.append(f"Effective weakest credential: {RANK_LABELS[pol.rank]} (permitted by {', '.join(repr(sp.profile.name) for sp in loose)})")
        if strict:
            ev.append(f"The stricter profile(s) {', '.join(repr(sp.profile.name) for sp in strict)} never get a say for this credential.")
        synced = pol.synced_allowed
        loose_targets = sorted({self.tenant.group_name(m.target_id) for sp in loose for m in sp.via})
        self.add(
            rule="R1",
            variant="overlap",
            severity="critical" if synced else "high",
            title=("Privileged user can register a synced passkey" if synced
                   else "Privileged user can register an unattested passkey"),
            subject=u.label,
            subject_type="user",
            user_id=u.id,
            detail=(f"{u.label} ({role_names(u)}) can register: {RANK_LABELS[pol.rank]}."
                    + (" Their stricter admin profile is overridden." if strict else " No strict profile covers them at all.")),
            evidence=ev,
            action=(f"Exclude privileged users from the target(s) {', '.join(repr(t) for t in loose_targets)} of the loose profile "
                    "(e.g. scope it to a group that excludes admins), and scope admins only to a device-bound, attested profile."),
        )

    def r2(self, u: User):
        if not u.is_privileged:
            return
        weak = [k for k in u.keys if k.passkey_type == "synced" or k.attested is False]
        if not weak and not u.keys_known and "passKeySynced" in u.methods:
            self.add(
                rule="R2", severity="critical", title="Privileged user holds a synced passkey",
                subject=u.label, subject_type="user", user_id=u.id,
                detail=f"{u.label} has a synced passkey registered (from the registration details report).",
                evidence=[self._privileged_line(u), "methodsRegistered includes 'passKeySynced'"],
                action="Have the user register a device-bound key, then delete the synced passkey from their methods.",
            )
            return
        for k in weak:
            kind = "synced" if k.passkey_type == "synced" else "unattested"
            self.add(
                rule="R2", severity="critical",
                title=f"Privileged user holds a {kind} passkey",
                subject=u.label, subject_type="user", user_id=u.id,
                detail=f"{u.label} holds '{k.display_name or k.model or k.aaguid}' ({kind}, AAGUID {k.aaguid or 'unknown'}).",
                evidence=[
                    self._privileged_line(u),
                    f"Registered FIDO2 method '{k.display_name}', model '{k.model or 'unknown'}', AAGUID {k.aaguid or 'unknown'}",
                    f"Classified as {k.passkey_type}; attestation: {'not attested' if k.attested is False else 'attested' if k.attested else 'unknown'}",
                    f"Created {k.created or 'unknown'}",
                ],
                action="Register a device-bound, attested key for this admin, then remove this passkey.",
            )

    def r3(self, u: User, pol: EffectivePolicy):
        if not phone_only(u):
            return
        when, cohort = deadline_for(u)
        days = (when - self.as_of).days
        no_path = pol.status != "allowed"
        phones = ", ".join(sorted(u.methods & PHONE_METHODS))
        ev = [
            f"Registered MFA methods: {phones} (no non-phone MFA method)",
            f"User category: {u.category}{', Global Administrator' if u.is_global_admin else ''}",
            f"Deadline cohort: {cohort}; {days} day(s) from {self.as_of.isoformat()}",
            f"Passkey policy status: {pol.weakest_label}",
        ]
        if no_path:
            ev.append("They will be prompted to register a passkey, but current policy does not let them register one.")
        self.add(
            rule="R3",
            variant="sms-only",
            severity="critical" if no_path else "high",
            title=("SMS/voice-only user with no passkey path" if no_path else "SMS/voice-only user"),
            subject=u.label, subject_type="user", user_id=u.id, cohort=cohort,
            detail=f"{u.label} relies only on {phones}. Blocking registration prompt from {cohort}.",
            evidence=ev,
            action=("Fix policy targeting first (they are " + pol.weakest_label.lower() + "), then have them register a passkey."
                    if no_path else "Have the user register a passkey (device-bound preferred) before the deadline."),
        )

    def r4(self, u: User, pol: EffectivePolicy):
        if not (u.is_privileged and u.methods & PHONE_METHODS and pol.status == "allowed"):
            return
        allin = [sp for sp in pol.profiles
                 if {"deviceBound", "synced"} <= sp.profile.passkey_types
                 and not sp.profile.attestation_enforced and not sp.profile.key_restriction_enforced]
        if not allin:
            return
        self.add(
            rule="R4", severity="high", title="Privileged SMS/voice user in an 'all passkey types' profile",
            subject=u.label, subject_type="user", user_id=u.id,
            detail=f"{u.label} has phone MFA and sits in '{allin[0].profile.name}', which allows every passkey type with no attestation.",
            evidence=[self._privileged_line(u),
                      f"Phone methods registered: {', '.join(sorted(u.methods & PHONE_METHODS))}",
                      "Microsoft auto-enabled passkeys for SMS/voice users on 1 Sep 2026 in a profile allowing all passkey types."]
                     + [self._profile_line(sp.profile) for sp in allin],
            action="Move this admin into an admin-only device-bound profile and out of the all-types profile's target.",
        )

    def r5(self, u: User, pol: EffectivePolicy):
        if not u.keys or pol.status != "allowed":
            return
        restricted = [sp for sp in pol.profiles if sp.profile.key_restriction_enforced or sp.profile.attestation_enforced]
        if not restricted:
            return
        for k in u.keys:
            ptype = k.passkey_type if k.passkey_type != "unknown" else "deviceBound"
            if pol.permits(ptype, k.aaguid, k.attested):
                continue
            self.add(
                rule="R5", severity="high", title="Registered passkey not accepted by any scoped profile",
                subject=u.label, subject_type="user", user_id=u.id,
                detail=f"{u.label}'s key '{k.display_name or k.model}' (AAGUID {k.aaguid or 'unknown'}) satisfies none of their profiles.",
                evidence=[f"Registered key: {k.display_name or k.model}, {k.passkey_type}, AAGUID {k.aaguid or 'unknown'}"]
                         + [self._profile_line(sp.profile) + " → rejects this key" for sp in pol.profiles],
                action=f"Add AAGUID {k.aaguid} to an allow list that covers this user, or have them register a permitted key before the change lands.",
            )

    def r6(self):
        fido = self.tenant.fido2
        for p in fido.profiles.values():
            if p.attestation_enforced and "synced" in p.passkey_types:
                self.add(
                    rule="R6", severity="medium", title="Attested profile lists synced passkeys",
                    subject=p.name, subject_type="profile",
                    detail=f"'{p.name}' requires attestation and also lists synced passkeys. Synced passkeys cannot be attested, so that setting is dead weight and suggests a misunderstanding.",
                    evidence=[self._profile_line(p),
                              "Attestation is not possible for synced passkeys (Microsoft Learn)."],
                    action="Remove 'synced' from this profile, or drop the attestation claim and document it as a synced profile.",
                )
            if p.synthesized and not p.attestation_enforced:
                self.add(
                    rule="R6", severity="medium", title="Legacy FIDO2 settings imply synced passkeys",
                    subject=p.name, subject_type="profile",
                    detail="This tenant has no passkey profiles in the export. Microsoft's migration derives passkey type from the old attestation toggle, so with attestation off, synced passkeys are allowed.",
                    evidence=["policy.json FIDO2 config has no passkeyProfiles", "isAttestationEnforced is false"],
                    action="Create explicit passkey profiles and decide on synced passkeys deliberately.",
                )

        if not fido.enabled:
            return
        for p in fido.profiles.values():
            if not p.attestation_enforced:
                continue
            scoped = [pol for pol in self.policies.values() if any(sp.profile.id == p.id for sp in pol.profiles)]
            bypass = [pol for pol in scoped if pol.unattested_allowed]
            if not bypass:
                continue
            names = ", ".join(pol.user.label for pol in bypass[:5]) + (" …" if len(bypass) > 5 else "")
            self.add(
                rule="R6", severity="medium", title="Attested profile is bypassed by an overlapping profile",
                subject=p.name, subject_type="profile",
                detail=f"{len(bypass)} of {len(scoped)} users scoped to attested profile '{p.name}' can still register unattested passkeys through another profile.",
                evidence=[f"Users affected: {names}",
                          "Union semantics: the attested profile only constrains users who have no looser profile."],
                action=f"Remove the users of '{p.name}' from the targets of looser profiles, or accept that '{p.name}' is not an attestation control for them.",
            )

    def r7(self, u: User):
        if u.is_privileged and not has_phishing_resistant(u):
            self.add(
                rule="R7", severity="critical", title="Privileged user has no phishing-resistant method",
                subject=u.label, subject_type="user", user_id=u.id,
                detail=f"{u.label} ({role_names(u)}) has no passkey, Windows Hello for Business or certificate registered.",
                evidence=[self._privileged_line(u), f"Registered methods: {', '.join(sorted(u.methods)) or 'none'}"],
                action="Issue this admin a device-bound passkey (security key or Authenticator) and require it with an authentication strength.",
            )

    def _campaign_covers(self, u: User) -> bool:
        c = self.tenant.campaign
        if any(self.resolver.membership(u, t) for t in c.exclude_targets):
            return False
        return any(self.resolver.membership(u, t) for t in c.include_targets)

    def r8(self):
        cohort = [pol.user for pol in self.policies.values() if phone_only(pol.user)]
        if not cohort:
            return
        c = self.tenant.campaign
        if not c.present or c.state.lower() == "disabled":
            self.add(
                rule="R8", severity="medium", title="Registration campaign is off",
                subject="tenant", subject_type="tenant",
                detail=f"{len(cohort)} SMS/voice-only user(s) and no registration campaign to nudge them before the deadline.",
                evidence=[f"Campaign state: {c.state if c.present else 'not present in export'}"],
                action="Enable the registration campaign for the SMS/voice cohort, targeting passkeys, with limited snoozes.",
            )
            return
        uncovered = [u for u in cohort if not self._campaign_covers(u)]
        if uncovered:
            names = ", ".join(u.label for u in uncovered[:5]) + (" …" if len(uncovered) > 5 else "")
            self.add(
                rule="R8", severity="medium", title="Campaign misses part of the SMS/voice cohort",
                subject="tenant", subject_type="tenant",
                detail=f"{len(uncovered)} of {len(cohort)} SMS/voice-only users are not targeted (or are excluded) by the campaign.",
                evidence=[f"Not covered: {names}"],
                action="Target the campaign at all users, or at a group containing the whole cohort.",
            )
        if c.enforce_after_snoozes is False and (c.snooze_days or 0) > 0:
            self.add(
                rule="R8", severity="medium", title="Campaign allows unlimited snoozes",
                subject="tenant", subject_type="tenant",
                detail=f"Users can snooze for {c.snooze_days} day(s) indefinitely, so the campaign may never convert them before the deadline.",
                evidence=[f"snoozeDurationInDays = {c.snooze_days}", "enforceRegistrationAfterAllowedSnoozes = false"],
                action="Set enforceRegistrationAfterAllowedSnoozes to true.",
            )
        if c.targeted_method and "passkey" not in c.targeted_method.lower() and "fido" not in c.targeted_method.lower():
            self.add(
                rule="R8", severity="low", title="Campaign nudges a non-passkey method",
                subject="tenant", subject_type="tenant",
                detail=f"The campaign targets '{c.targeted_method}', not passkeys.",
                evidence=[f"targetedAuthenticationMethod = {c.targeted_method}"],
                action="Point the campaign at passkeys if your goal is phishing-resistant MFA for this cohort.",
            )

    def r9(self, u: User, pol: EffectivePolicy):
        if not (u.is_privileged and pol.status == "excluded"):
            return
        looks_breakglass = u.looks_breakglass
        self.add(
            rule="R9", severity="medium" if looks_breakglass else "high",
            title="Privileged user excluded from passkey policy",
            subject=u.label, subject_type="user", user_id=u.id,
            detail=(f"{u.label} is excluded, so no passkey can be registered or used."
                    + (" Name suggests a break-glass account: confirm this is intentional." if looks_breakglass else "")),
            evidence=[self._privileged_line(u)] + [f"Exclusion: {self.resolver.describe_path(m)}" for m in pol.exclusions]
                     + ["Exclusion wins over every inclusion (Microsoft Learn)."],
            action=("Confirm the break-glass design (e.g. certificate-based auth or a dedicated FIDO2 key) is documented and tested."
                    if looks_breakglass else "Remove this admin from the exclusion group and scope them to the admin profile."),
        )

    def r10(self):
        fido = self.tenant.fido2
        if not fido.enabled:
            priv = sum(1 for u in self.tenant.users.values() if u.is_privileged)
            self.add(
                rule="R10", severity="high", title="Passkeys (FIDO2) disabled tenant-wide",
                subject="tenant", subject_type="tenant",
                detail=f"FIDO2 is disabled, so none of {len(self.tenant.users)} users (incl. {priv} privileged) can register passkeys before SMS/voice retires.",
                evidence=[f"FIDO2 state: {fido.state}"],
                action="Enable passkeys with an admin device-bound profile and a workforce profile.",
            )
        if len(fido.profiles) > MAX_PROFILES_SOFT:
            self.add(
                rule="R10", severity="low", title="Many passkey profiles",
                subject="tenant", subject_type="tenant",
                detail=f"{len(fido.profiles)} profiles (soft threshold {MAX_PROFILES_SOFT}). More profiles mean more overlap to reason about.",
                evidence=[", ".join(p.name for p in fido.profiles.values())],
                action="Consolidate to an admin profile and a workforce profile where possible.",
            )
        referenced = {pid for t in fido.include_targets for pid in (t.profile_ids or [fido.default_profile_id])}
        for p in fido.profiles.values():
            if len(p.aaguids) > MAX_AAGUIDS_SOFT:
                self.add(
                    rule="R10", severity="low", title="Large AAGUID list", subject=p.name, subject_type="profile",
                    detail=f"'{p.name}' lists {len(p.aaguids)} AAGUIDs (soft threshold {MAX_AAGUIDS_SOFT}).",
                    evidence=[], action="Review the list for stale entries.",
                )
            auto = p.aaguids & AUTHENTICATOR_AAGUIDS
            if p.key_restriction_enforced and p.key_restriction_type == "allow" and auto:
                self.add(
                    rule="R10", severity="info", title="Authenticator AAGUIDs in allow list",
                    subject=p.name, subject_type="profile",
                    detail=f"'{p.name}' allows Microsoft Authenticator AAGUIDs, which Entra adds automatically when Authenticator passkeys are enabled.",
                    evidence=[f"AAGUIDs: {', '.join(sorted(auto))}"],
                    action="Confirm Authenticator passkeys are intended for the users of this profile.",
                )
            if p.id not in referenced:
                self.add(
                    rule="R10", severity="low", title="Profile not targeted by any group",
                    subject=p.name, subject_type="profile",
                    detail=f"'{p.name}' is defined but no include target uses it. It protects nobody.",
                    evidence=[], action="Target it at the intended group or delete it.",
                )
        for t in fido.include_targets + fido.exclude_targets:
            if t.id != "all_users" and t.target_type.lower() == "group" and t.id not in self.tenant.groups:
                self.add(
                    rule="R10", severity="low", title="Target group missing from groups export",
                    subject=t.id, subject_type="tenant",
                    detail=f"The policy targets group {t.id}, but groups.json has no members for it, so its users could not be resolved.",
                    evidence=[], action="Re-run the collector so this group's members are exported.",
                )
            for pid in t.profile_ids:
                if pid not in fido.profiles:
                    self.add(
                        rule="R10", severity="low", title="Target references unknown profile",
                        subject=pid, subject_type="tenant",
                        detail=f"Target {self.tenant.group_name(t.id)} references profile id '{pid}' that is not defined.",
                        evidence=[], action="Fix the target or re-export the policy.",
                    )
