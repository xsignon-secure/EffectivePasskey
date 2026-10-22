"""Sign-in and attack-path rules (R11 to R16).

Registration and sign-in follow opposite logic in Entra:

* Passkey profiles UNION: a passkey can be registered if any scoped profile
  allows it.
* Conditional Access INTERSECTS: every enforced policy that applies must be
  satisfied, so a credential works at sign-in only if every applicable grant
  accepts it.

These rules read the optional conditional_access.json and signins.json, the
Temporary Access Pass (TAP) config and migration state in policy.json, and the
ownership fields in groups.json. Rules whose input is absent stay silent.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .constants import GLOBAL_ADMIN_TEMPLATE_ID, KNOWN_AAGUIDS
from .model import AuthStrength, CaPolicy, Target, User
from .resolver import profile_rank

PRIV_AUTH_ADMIN = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"
AUTH_ADMIN = "c4e39bd9-1100-46d3-8c65-fb160da0071f"
# Roles an Authentication Administrator may still manage methods for (Microsoft Learn,
# "Who can perform sensitive actions"). Any other privileged role needs a Privileged
# Authentication Administrator or Global Administrator.
AUTH_ADMIN_MANAGEABLE = {
    "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # Helpdesk Administrator
    "966707d0-3269-4727-9be2-8c3a10f19b9d",  # Password Administrator
}
SYNCED_AAGUIDS = {a for a, (_, kind) in KNOWN_AAGUIDS.items() if kind == "synced"}
DEVICE_CONTROLS = {"compliantdevice", "domainjoineddevice", "approvedapplication", "compliantapplication"}
PHONE_WORDS = ("text message", "phone call", "sms", "voice")


def is_phone_method(m: str) -> bool:
    return any(w in m.lower() for w in PHONE_WORDS)


def is_synced_method(m: str) -> bool:
    return "synced" in m.lower()


@dataclass
class Gate:
    """What an admin can sign in with, after every applicable CA policy is applied."""

    evaluated: bool
    applicable: list[CaPolicy] = field(default_factory=list)
    report_only: list[CaPolicy] = field(default_factory=list)
    accepts_synced: bool = True
    accepts_phone: bool = True
    deciding: list[str] = field(default_factory=list)  # policies that reject synced passkeys

    @property
    def label(self) -> str:
        if not self.evaluated:
            return "Not evaluated (no Conditional Access export)"
        if not self.applicable:
            return "No enforced CA policy requires MFA"
        if self.accepts_phone:
            return "SMS/voice accepted"
        if self.accepts_synced:
            return "Synced passkey accepted"
        return "Device-bound, approved keys only"


def _strength_accepts(st: AuthStrength | None, kind: str) -> bool:
    if st is None:
        return True
    if kind == "phone":
        return any(("sms" in c or "voice" in c) for c in st.combinations)
    if kind == "synced":
        if "fido2" not in st.combinations:
            return False
        return st.fido2_aaguids is None or bool(st.fido2_aaguids & SYNCED_AAGUIDS)
    return True


def _policy_accepts(p: CaPolicy, strengths: dict[str, AuthStrength], kind: str) -> bool:
    """Does one CA policy's grant accept this credential class?

    OR grants are satisfied by any one control, so a device control (compliant or
    joined device) offered as an alternative lets any credential through. AND
    grants need every control, and device controls do not constrain the credential.
    """
    controls = [c.lower() for c in p.builtin_controls]
    if "block" in controls:
        return False
    credential_checks = []
    if p.strength_id:
        credential_checks.append(_strength_accepts(strengths.get(p.strength_id), kind))
    if "mfa" in controls:
        credential_checks.append(True)
    device_alternative = any(c in DEVICE_CONTROLS for c in controls)
    if p.operator == "OR":
        return device_alternative or not credential_checks or any(credential_checks)
    return all(credential_checks)


class DeepRules:
    def __init__(self, auditor):
        self.a = auditor
        self.t = auditor.tenant
        self.r = auditor.resolver
        self.gates: dict[str, Gate] = {}

    # ---------------------------------------------------------- scope helpers

    def _in_targets(self, u: User, ids: list[str]) -> bool:
        for gid in ids:
            if gid.lower() == "all":
                return True
            if gid == u.id:
                return True
            if self.r.membership(u, Target(id=gid)):
                return True
        return False

    def ca_applies(self, p: CaPolicy, u: User) -> bool:
        role_ids = {r["templateId"] for r in u.roles}
        inc = (any(x.lower() == "all" or x == u.id for x in p.include_users)
               or ("guestsorexternalusers" in [x.lower() for x in p.include_users] and u.category != "member")
               or self._in_targets(u, p.include_groups)
               or bool(role_ids & set(p.include_roles)))
        if not inc:
            return False
        exc = (u.id in p.exclude_users or self._in_targets(u, p.exclude_groups)
               or bool(role_ids & set(p.exclude_roles)))
        return not exc

    def gate(self, u: User) -> Gate:
        if u.id in self.gates:
            return self.gates[u.id]
        if self.t.ca_policies is None:
            g = Gate(evaluated=False)
        else:
            g = Gate(evaluated=True)
            for p in self.t.ca_policies:
                if not p.admin_relevant_apps or not self.ca_applies(p, u):
                    continue
                if not (p.strength_id or {"mfa", "block"} & {c.lower() for c in p.builtin_controls}):
                    continue
                (g.applicable if p.enforced else g.report_only).append(p)
            if g.applicable:
                g.accepts_phone = all(_policy_accepts(p, self.t.strengths, "phone") for p in g.applicable)
                g.accepts_synced = all(_policy_accepts(p, self.t.strengths, "synced") for p in g.applicable)
                g.deciding = [p.name for p in g.applicable if not _policy_accepts(p, self.t.strengths, "synced")]
        self.gates[u.id] = g
        return g

    def _strength_line(self, p: CaPolicy) -> str:
        st = self.t.strengths.get(p.strength_id or "")
        if p.strength_id and st:
            aag = ("any passkey or security key" if st.fido2_aaguids is None
                   else f"FIDO2 limited to {len(st.fido2_aaguids)} AAGUID(s)")
            return f"CA '{p.name}' requires strength '{st.name}' ({', '.join(sorted(st.combinations))}; {aag})"
        return f"CA '{p.name}' grant: {', '.join(p.builtin_controls) or 'none'}"

    # ---------------------------------------------------------- rules

    def run(self):
        for pol in self.a.policies.values():
            u = pol.user
            if u.is_privileged:
                self.r11(u, pol)
                self.r12(u)
                self.r13(u)
        self.r14()
        self.r15()
        self.r16()

    def r11(self, u: User, pol):
        g = self.gate(u)
        if not g.evaluated or not g.applicable:
            return
        holds_synced = any(k.passkey_type == "synced" for k in u.keys) or "passKeySynced" in u.methods
        can_register = pol.synced_allowed
        if not g.accepts_synced:
            # Sign-in blocks synced passkeys: soften R1 and say why.
            for f in self.a.findings:
                if f.rule == "R1" and f.user_id == u.id and f.severity == "critical":
                    f.severity = "high"
                    f.evidence.append(f"Sign-in gate: {', '.join(repr(n) for n in g.deciding)} rejects synced passkeys, "
                                      "so a registered synced passkey cannot be used to sign in to covered apps. "
                                      "Registration is still weaker than intended.")
            return
        ev = [f"{u.label} holds privileged role(s)"] + [self._strength_line(p) for p in g.applicable]
        ev.append("Conditional Access requires every applicable policy to be satisfied; none of these rejects a synced passkey.")
        ev.append("Microsoft's built-in 'Phishing-resistant MFA' strength accepts synced passkeys; only a custom strength "
                  "with a FIDO2 AAGUID allow list of device-bound keys excludes them.")
        if can_register or holds_synced:
            ev.append("Registration also allows a synced passkey" if can_register else "User already holds a synced passkey")
            self.a.add(rule="R11", variant="signin-synced", severity="critical",
                       title="Admin can register and sign in with a synced passkey", subject=u.label,
                       subject_type="user", user_id=u.id,
                       detail=f"{u.label}'s sign-in gate accepts synced passkeys and nothing upstream stops one being registered.",
                       evidence=ev,
                       action="Create a custom authentication strength allowing only FIDO2 with your approved device-bound "
                              "AAGUIDs and require it for admin roles in Conditional Access.")
        else:
            self.a.add(rule="R11", variant="signin-synced", severity="medium",
                       title="Sign-in would accept a synced passkey; only registration blocks it", subject=u.label,
                       subject_type="user", user_id=u.id,
                       detail=f"{u.label} cannot register a synced passkey today, but Conditional Access would accept one.",
                       evidence=ev, action="Add a device-bound AAGUID allow list to the admin authentication strength as a second layer.")

    def r12(self, u: User):
        g = self.gate(u)
        if not g.evaluated:
            return
        ga = any(r["templateId"] == GLOBAL_ADMIN_TEMPLATE_ID for r in u.roles)
        if not g.applicable:
            ev = [f"{u.label} holds privileged role(s)",
                  f"{len(self.t.ca_policies)} CA policies exported; none enforced for this user on all apps or admin portals with MFA or a strength"]
            ev += [f"Report-only (not enforced): '{p.name}'" for p in g.report_only]
            if u.looks_breakglass:
                ev.append("Name suggests an emergency-access account. Excluding it from CA can be intentional; "
                          "it then needs a strong credential, sign-in alerts and a tested procedure.")
            self.a.add(rule="R12", variant="signin-gate",
                       severity="medium" if u.looks_breakglass else ("critical" if ga else "high"),
                       title="Admin sign-in not gated by any enforced MFA policy", subject=u.label,
                       subject_type="user", user_id=u.id,
                       detail=f"No enforced Conditional Access policy requires MFA or an authentication strength for {u.label}.",
                       evidence=ev,
                       action=("Confirm the emergency-access design and alert on every sign-in by this account."
                               if u.looks_breakglass else
                               "Require a phishing-resistant authentication strength for all admin roles, on all apps."))
            return
        if g.accepts_phone:
            self.a.add(rule="R12", variant="signin-gate", severity="critical" if ga else "high",
                       title="Admin sign-in accepts SMS or voice", subject=u.label, subject_type="user", user_id=u.id,
                       detail=f"Every CA policy covering {u.label} can be satisfied with SMS or voice MFA.",
                       evidence=[self._strength_line(p) for p in g.applicable],
                       action="Replace plain MFA with a phishing-resistant authentication strength for admin roles.")

    def _issuers(self, target: User) -> list[User]:
        """Other users who can create a TAP for this user (role-based)."""
        target_roles = {r["templateId"] for r in target.roles}
        need_paa = bool(target_roles - AUTH_ADMIN_MANAGEABLE)
        allowed = {GLOBAL_ADMIN_TEMPLATE_ID, PRIV_AUTH_ADMIN} | (set() if need_paa else {AUTH_ADMIN})
        return sorted((u for u in self.t.users.values()
                       if u.id != target.id and {r["templateId"] for r in u.roles} & allowed),
                      key=lambda u: u.label)

    def r13(self, u: User):
        tap = self.t.tap
        if not tap.present or not tap.enabled:
            return
        if any(self.r.membership(u, t) for t in tap.exclude_targets):
            return
        if not any(self.r.membership(u, t) for t in tap.include_targets):
            return
        issuers = self._issuers(u)
        long_lived = (tap.max_lifetime or 0) > 60
        multi = tap.usable_once is False
        ev = [f"TAP is enabled and {u.label} is in its target",
              f"isUsableOnce = {tap.usable_once}; maximum lifetime = {tap.max_lifetime} min",
              f"{len(issuers)} other user(s) can issue a TAP to them: "
              + (", ".join(i.label for i in issuers[:6]) + (" …" if len(issuers) > 6 else "") or "none listed"),
              "A TAP lets the holder register a new passkey on the account. Whoever issues it can enrol their own key."]
        g = self.gate(u)
        if g.evaluated and g.applicable and any(
                (self.t.strengths.get(p.strength_id or "") and
                 {"temporaryAccessPassOneTime", "temporaryAccessPassMultiUse"} & self.t.strengths[p.strength_id].combinations)
                for p in g.applicable):
            ev.append("A CA authentication strength covering them also accepts TAP as a sign-in method.")
        self.a.add(rule="R13", variant="tap", severity="high" if (multi or long_lived) else "medium",
                   title="Temporary Access Pass can bootstrap a new passkey on an admin", subject=u.label,
                   subject_type="user", user_id=u.id,
                   detail=f"{len(issuers)} other user(s) can issue {u.label} a TAP and register a passkey with it.",
                   evidence=ev,
                   action="Exclude admin groups from the TAP policy (issue admin TAPs through a break-glass process), "
                          "or set isUsableOnce = true and a maximum lifetime of 60 minutes or less.")

    def _risky_groups(self):
        """(group id, how it is used, severity, consequence) for every policy-relevant group."""
        out = []
        f = self.t.fido2
        for t in f.include_targets:
            pids = t.profile_ids or [f.default_profile_id]
            if any(profile_rank(f.profiles[p]) >= 4 for p in pids if p in f.profiles):
                out.append((t.id, "targets a passkey profile that allows synced passkeys", "high",
                            "Adding an admin to it lets them register a synced passkey (R1)."))
        for t in f.exclude_targets:
            out.append((t.id, "is the passkey (FIDO2) exclusion", "medium",
                        "Adding a user to it switches off their passkeys entirely."))
        if self.t.tap.present and self.t.tap.enabled:
            for t in self.t.tap.include_targets:
                out.append((t.id, "is a Temporary Access Pass target", "high",
                            "Adding an admin to it makes them TAP-eligible (R13)."))
        for p in self.t.ca_policies or []:
            if not p.enforced:
                continue
            admins = [u for u in self.t.users.values() if u.is_privileged and
                      (set(r["templateId"] for r in u.roles) & set(p.include_roles) or self._in_targets(u, p.include_groups)
                       or any(x.lower() == "all" for x in p.include_users))]
            if admins:
                for gid in p.exclude_groups:
                    out.append((gid, f"is excluded from CA '{p.name}', which covers admins", "critical",
                                "Adding an admin to it removes their sign-in requirement."))
        return out

    def r14(self):
        order = {"critical": 0, "high": 1, "medium": 2}
        by_group: dict[str, list] = {}
        for gid, use, sev, consequence in self._risky_groups():
            g = self.t.groups.get(gid)
            if g is None or g.role_assignable is not False:
                continue
            if all(use != u for u, _, _ in by_group.get(gid, [])):
                by_group.setdefault(gid, []).append((use, sev, consequence))
        for gid in sorted(by_group):
            g = self.t.groups[gid]
            uses = by_group[gid]
            sev = min((s for _, s, _ in uses), key=order.get)
            owners = [self.t.users[o].label if o in self.t.users else o for o in g.owners]
            ev = [f"Group '{g.name}' {use}" for use, _, _ in uses]
            ev.append("isAssignableToRole = false, so Groups Administrators, User Administrators and the group's owners "
                      "can change its membership")
            if owners:
                ev.append(f"Owners: {', '.join(owners)}")
            if g.membership_rule:
                ev.append(f"Dynamic membership rule: {g.membership_rule} (whoever can edit those user attributes controls membership)")
            ev += list(dict.fromkeys(c for _, _, c in uses))
            self.a.add(rule="R14", variant="group", severity=sev, title="Policy group can be changed by non-privileged admins",
                       subject=g.name, subject_type="group",
                       detail=f"'{g.name}' {uses[0][0]}" + (f" (and {len(uses) - 1} more use)" if len(uses) > 1 else "")
                              + f" but is not role-assignable. {uses[0][2]}",
                       evidence=ev,
                       action="Use a role-assignable group (isAssignableToRole = true, no owners) for this target, "
                              "so only Privileged Role Administrators can change it.")

    def r15(self):
        state = self.t.migration_state
        if not state or state == "migrationComplete":
            return
        phone_users = sum(1 for u in self.t.users.values() if u.methods & {"mobilePhone", "sms", "voice", "officePhone"})
        self.a.add(rule="R15", severity="high" if phone_users else "medium", title="Authentication methods migration not complete",
                   subject="tenant", subject_type="tenant",
                   detail=f"policyMigrationState is '{state}'. Legacy per-user MFA and SSPR settings still decide SMS and voice "
                          f"for {phone_users} user(s) with phone methods, so disabling them in the methods policy alone may not hold.",
                   evidence=[f"policyMigrationState = {state}",
                             "Microsoft retired the legacy MFA and SSPR method settings; the methods policy is the only one that should govern."],
                   action="Finish the migration (Authentication methods > Manage migration > Migration complete).")

    def r16(self):
        if self.t.signins is None:
            return
        by_user: dict[str, list] = {}
        for s in self.t.signins:
            if s.succeeded:
                by_user.setdefault(s.user_id, []).append(s)
        phone_workforce = 0
        for uid, items in by_user.items():
            u = self.t.users.get(uid)
            if u is None:
                continue
            phone = [s for s in items if any(is_phone_method(m) for m in s.methods)]
            synced = [s for s in items if any(is_synced_method(m) for m in s.methods)]
            if not u.is_privileged:
                phone_workforce += bool(phone)
                continue
            if synced:
                self.a.add(rule="R16", variant="synced", severity="critical",
                           title="Admin signed in with a synced passkey", subject=u.label, subject_type="user", user_id=u.id,
                           detail=f"{len(synced)} successful sign-in(s) by {u.label} used a synced passkey.",
                           evidence=[f"{s.when} · {s.app or 'app'} · {', '.join(s.methods)}" for s in synced[:5]],
                           action="Replace the synced passkey with a device-bound key and block synced passkeys at sign-in (R11).")
            if phone:
                self.a.add(rule="R16", variant="phone", severity="high",
                           title="Admin still signs in with SMS or voice", subject=u.label, subject_type="user", user_id=u.id,
                           detail=f"{len(phone)} successful sign-in(s) by {u.label} used SMS or voice.",
                           evidence=[f"{s.when} · {s.app or 'app'} · {', '.join(s.methods)}" for s in phone[:5]],
                           action="Move this admin to a device-bound passkey now; their SMS sign-ins stop working on the retirement date.")
        if phone_workforce:
            self.a.add(rule="R16", variant="phone-workforce", severity="info",
                       title="Users still signing in with SMS or voice", subject="tenant", subject_type="tenant",
                       detail=f"{phone_workforce} non-admin user(s) signed in with SMS or voice in the exported window.",
                       evidence=["From signins.json"], action="Prioritize these users in the registration campaign.")
