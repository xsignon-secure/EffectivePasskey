"""Remediation generator.

Proposes policy and group changes that would clear the findings, applies them
to an in-memory copy of the tenant, and re-runs the audit to prove the effect.
The output is a plan for a human to review plus a "proposed" export directory
that can itself be analyzed. Nothing is ever written to a tenant.
"""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
from dataclasses import dataclass, field

from .constants import ALL_USERS_TARGET
from .model import AuthStrength, CaPolicy, Group, PasskeyProfile, Target, Tenant
from .resolver import RANK_LABELS, Resolver, profile_rank
from .rules import Auditor, phone_only, deadline_for

PROPOSED_PREFIX = "ep-proposed-"


@dataclass
class Change:
    id: str
    kind: str  # "policy", "group", "campaign"
    title: str
    rationale: str
    fixes: list[str]  # rule ids
    before: object = None
    after: object = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "title": self.title, "rationale": self.rationale,
                "fixes": self.fixes, "before": self.before, "after": self.after, "notes": self.notes}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40] or "group"


def _profile_summary(p: PasskeyProfile) -> dict:
    return {
        "displayName": p.name,
        "passkeyTypes": sorted(p.passkey_types),
        "attestation": "required" if p.attestation_enforced else "off",
        "keyRestriction": (f"{p.key_restriction_type}: {sorted(p.aaguids)}" if p.key_restriction_enforced else "none"),
        "weakestCredential": RANK_LABELS[profile_rank(p)],
    }


class Planner:
    def __init__(self, auditor: Auditor):
        self.before = auditor
        self.tenant: Tenant = copy.deepcopy(auditor.tenant)
        self.changes: list[Change] = []
        self.user_tasks: list[dict] = []
        self.priv = {u.id for u in self.tenant.users.values() if u.is_privileged}

    # -- helpers

    def _add(self, kind, title, rationale, fixes, before=None, after=None, notes=None):
        self.changes.append(Change(id=f"C{len(self.changes) + 1}", kind=kind, title=title, rationale=rationale,
                                   fixes=fixes, before=before, after=after, notes=notes or []))

    def _new_group(self, name: str, members: list[str]) -> Group:
        gid = PROPOSED_PREFIX + _slug(name)
        n = 2
        while gid in self.tenant.groups:
            gid = f"{PROPOSED_PREFIX}{_slug(name)}-{n}"
            n += 1
        g = Group(id=gid, name=name, members=sorted(members), role_assignable=True)
        self.tenant.groups[gid] = g
        return g

    def _labels(self, uids) -> list[str]:
        return sorted(self.tenant.users[u].label for u in uids if u in self.tenant.users)

    def _resolver(self) -> Resolver:
        # Membership only depends on groups, so reuse the index until a group is added or changed
        key = tuple((g.id, len(g.members)) for g in self.tenant.groups.values())
        if getattr(self, "_resolver_key", None) != key:
            self._resolver_cache, self._resolver_key = Resolver(self.tenant), key
        return self._resolver_cache

    def _covered_users(self, target: Target) -> set[str]:
        r = self._resolver()
        return {u.id for u in self.tenant.users.values() if r.membership(u, target)}

    # -- steps, in dependency order

    def plan(self) -> "Plan":
        self.enable_fido2()
        self.convert_legacy()
        self.fix_attested_synced()
        self.unexclude_admins()
        self.split_loose_targets()
        self.scope_admins_strict()
        self.give_sms_users_a_path()
        self.fix_aaguid_traps()
        self.fix_campaign()
        self.gate_admin_signin()
        self.close_tap_path()
        self.harden_policy_groups()
        self.finish_migration()
        self.collect_user_tasks()
        after = Auditor(self.tenant, self.before.as_of)
        after.run()
        return Plan(self.before, after, self.changes, self.user_tasks, self.tenant)

    def enable_fido2(self):
        f = self.tenant.fido2
        if f.enabled:
            return
        f.state = "enabled"
        if not f.include_targets:
            f.include_targets.append(Target(id=ALL_USERS_TARGET, profile_ids=[f.default_profile_id]))
        self._add("policy", "Enable the passkey (FIDO2) method", "Nobody can register a passkey while it is disabled.",
                  ["R10", "R3"], before={"state": "disabled"}, after={"state": "enabled"})

    def convert_legacy(self):
        f = self.tenant.fido2
        if not f.legacy:
            return
        p = f.profiles["default"]
        p.synthesized = False
        p.name = "Default"
        f.legacy = False
        self._add("policy", "Convert legacy FIDO2 settings to an explicit Default passkey profile",
                  "Makes the synced-passkey decision explicit instead of inherited from the old attestation toggle.",
                  ["R6"], after=_profile_summary(p))

    def fix_attested_synced(self):
        for p in self.tenant.fido2.profiles.values():
            if p.attestation_enforced and "synced" in p.passkey_types:
                before = _profile_summary(p)
                p.passkey_types.discard("synced")
                p.passkey_types.add("deviceBound")
                self._add("policy", f"Remove 'synced' from attested profile '{p.name}'",
                          "Synced passkeys cannot be attested, so listing them in an attested profile is misleading.",
                          ["R6"], before=before, after=_profile_summary(p))

    def unexclude_admins(self):
        pols = self.before.policies
        for uid in sorted(self.priv):
            pol = pols[uid]
            u = pol.user
            if pol.status != "excluded":
                continue
            if u.looks_breakglass:
                continue  # break-glass stays excluded; R9 asks a human to confirm
            for m in pol.exclusions:
                if m.path:
                    direct = self.tenant.groups.get(m.path[0])
                    if direct and uid in direct.members:
                        direct.members.remove(uid)
                        self._add("group", f"Remove {u.label} from exclusion group '{direct.name}'",
                                  "Exclusion beats every inclusion, so this admin cannot use passkeys at all.",
                                  ["R9"], before={"group": direct.name, "member": True},
                                  after={"group": direct.name, "member": False},
                                  notes=["Confirm this account is not an intentional break-glass account."])

    def split_loose_targets(self):
        f = self.tenant.fido2
        for t in list(f.include_targets):
            pids = t.profile_ids or [f.default_profile_id]
            loose = [f.profiles[p] for p in pids if p in f.profiles and profile_rank(f.profiles[p]) >= 3]
            if not loose:
                continue
            covered = self._covered_users(t)
            r = self._resolver()
            admins = {u for u in covered & self.priv if r.resolve(self.tenant.users[u]).status != "excluded"}
            if not admins:
                continue
            old_name = self.tenant.group_name(t.id)
            g = self._new_group(f"{old_name} (excluding privileged users)", list(covered - self.priv))
            old_id = t.id
            t.id = g.id
            t.target_type = "group"
            self._add(
                "policy",
                f"Retarget profile(s) {', '.join(repr(p.name) for p in loose)} from '{old_name}' to a group without admins",
                "Entra allows a passkey if any scoped profile allows it, so a loose profile on a target that contains "
                "admins overrides their strict profile.",
                ["R1", "R4", "R6"],
                before={"target": old_name, "targetId": old_id, "privilegedUsersCovered": self._labels(admins)},
                after={"target": g.name, "targetId": g.id, "members": len(g.members)},
                notes=["The proposed group is a static snapshot. In production, keep it current with a dynamic "
                       "membership rule or by excluding your role-assignable admin groups from it."],
            )

    def scope_admins_strict(self):
        if not self.priv:
            return
        f = self.tenant.fido2
        if not f.enabled:
            return
        strict = [p for p in f.profiles.values() if 0 < profile_rank(p) <= 2]
        if strict:
            target_profile = min(strict, key=profile_rank)
        else:
            # Pre-seed the allow list with device-bound, attested keys admins already hold, so nobody is locked out.
            held = {k.aaguid for uid in self.priv for k in self.tenant.users[uid].keys
                    if k.aaguid and k.passkey_type == "deviceBound" and k.attested is not False}
            target_profile = PasskeyProfile(
                id=PROPOSED_PREFIX + "admin-profile", name="Admins - device-bound, attested",
                passkey_types={"deviceBound"}, attestation_enforced=True,
                key_restriction_enforced=bool(held), key_restriction_type="allow", aaguids=held)
            f.profiles[target_profile.id] = target_profile
            self._add("policy", f"Create profile '{target_profile.name}'",
                      "Admins need a profile that only accepts device-bound, attested passkeys.",
                      ["R1"], after=_profile_summary(target_profile),
                      notes=["Allow list pre-seeded with AAGUIDs of device-bound keys your admins already hold."
                             if held else "Add an AAGUID allow list for your approved security keys."])

        r = self._resolver()
        missing = []
        for uid in sorted(self.priv):
            pol = r.resolve(self.tenant.users[uid])
            if pol.status == "excluded":
                continue
            if not any(sp.profile.id == target_profile.id for sp in pol.profiles):
                missing.append(uid)
        if not missing:
            return
        g = self._new_group("Privileged users (passkey admin profile)", missing)
        f.include_targets.append(Target(id=g.id, profile_ids=[target_profile.id]))
        self._add("policy", f"Scope privileged users to '{target_profile.name}'",
                  "Every admin should be scoped to the strict profile, and only to it.",
                  ["R1"], after={"target": g.name, "profile": target_profile.name, "users": self._labels(missing)},
                  notes=["Prefer targeting your existing role-assignable admin group instead of this snapshot group."])

    def _workforce_profile(self) -> PasskeyProfile | None:
        f = self.tenant.fido2
        r = self._resolver()
        counts: dict[str, int] = {}
        for u in self.tenant.users.values():
            if u.id in self.priv:
                continue
            for sp in r.resolve(u).profiles:
                counts[sp.profile.id] = counts.get(sp.profile.id, 0) + 1
        if counts:
            return f.profiles[max(counts, key=lambda k: (counts[k], k))]
        return f.profiles.get(f.default_profile_id or "")

    def give_sms_users_a_path(self):
        if not self.tenant.fido2.enabled:
            return
        r = self._resolver()
        stranded = [u.id for u in self.tenant.users.values()
                    if phone_only(u) and u.id not in self.priv and r.resolve(u).status == "not_targeted"]
        if not stranded:
            return
        p = self._workforce_profile()
        if p is None:
            return
        g = self._new_group("SMS/voice users without a passkey path", stranded)
        self.tenant.fido2.include_targets.append(Target(id=g.id, profile_ids=[p.id]))
        self._add("policy", f"Scope {len(stranded)} SMS/voice-only user(s) to profile '{p.name}'",
                  "They will get a blocking passkey prompt when SMS/voice retires, but policy does not let them register one.",
                  ["R3"], after={"target": g.name, "profile": p.name, "users": self._labels(stranded)},
                  notes=["Or widen the existing workforce target so it includes them."])

    def fix_aaguid_traps(self):
        r = self._resolver()
        additions: dict[str, set[str]] = {}
        for u in self.tenant.users.values():
            pol = r.resolve(u)
            if pol.status != "allowed":
                continue
            for k in u.keys:
                if k.passkey_type == "synced" or not k.aaguid:
                    continue
                if pol.permits("deviceBound", k.aaguid, k.attested):
                    continue
                allow = [sp.profile for sp in pol.profiles
                         if sp.profile.key_restriction_enforced and sp.profile.key_restriction_type == "allow"
                         and (k.attested is not False or not sp.profile.attestation_enforced)]
                if allow:
                    target = min(allow, key=profile_rank)
                    additions.setdefault(target.id, set()).add(k.aaguid)
        for pid, aaguids in sorted(additions.items()):
            p = self.tenant.fido2.profiles[pid]
            before = sorted(p.aaguids)
            p.aaguids |= aaguids
            self._add("policy", f"Add {len(aaguids)} AAGUID(s) to the allow list of '{p.name}'",
                      "Users hold keys this profile would reject, so they would lose sign-in with them.",
                      ["R5"], before={"aaGuids": before}, after={"aaGuids": sorted(p.aaguids)},
                      notes=["Only add AAGUIDs of authenticator models you approve; otherwise have the users re-register."])

    def fix_campaign(self):
        cohort = [u for u in self.tenant.users.values() if phone_only(u)]
        if not cohort:
            return
        c = self.tenant.campaign
        before = {"state": c.state, "snoozeDurationInDays": c.snooze_days,
                  "enforceRegistrationAfterAllowedSnoozes": c.enforce_after_snoozes,
                  "targets": [self.tenant.group_name(t.id) for t in c.include_targets],
                  "targetedAuthenticationMethod": c.targeted_method}
        changed = False
        if not c.present or c.state.lower() == "disabled":
            c.present, c.state, changed = True, "enabled", True
        r = self._resolver()
        if any(not any(r.membership(u, t) for t in c.include_targets) for u in cohort):
            c.include_targets = [Target(id=ALL_USERS_TARGET)]
            changed = True
        if c.enforce_after_snoozes is not True:
            c.enforce_after_snoozes = True
            c.snooze_days = c.snooze_days or 1
            changed = True
        if not c.targeted_method or "passkey" not in c.targeted_method.lower():
            c.targeted_method = "passkey"
            changed = True
        if changed:
            after = {"state": c.state, "snoozeDurationInDays": c.snooze_days,
                     "enforceRegistrationAfterAllowedSnoozes": True, "targets": ["All users"],
                     "targetedAuthenticationMethod": c.targeted_method}
            self._add("campaign", "Point the registration campaign at passkeys for all users, with limited snoozes",
                      f"{len(cohort)} SMS/voice-only user(s) need a nudge before their deadline.",
                      ["R8"], before=before, after=after,
                      notes=["Check the targetedAuthenticationMethod value your tenant's Graph version accepts."])

    def _admin_ids(self, include_breakglass=False) -> list[str]:
        return sorted(u for u in self.priv if include_breakglass or not self.tenant.users[u].looks_breakglass)

    def _admin_group(self) -> Group:
        """One role-assignable group of admins for TAP and CA scoping, created once."""
        for g in self.tenant.groups.values():
            if g.id == PROPOSED_PREFIX + "privileged-users-sign-in-and-tap":
                return g
        return self._new_group("Privileged users (sign-in and TAP)", self._admin_ids())

    def gate_admin_signin(self):
        t = self.tenant
        if t.ca_policies is None:
            return
        probe = Auditor(t, self.before.as_of)
        probe.run()
        weak = [u for u in self._admin_ids() if probe.deep.gate(t.users[u]).evaluated
                and (probe.deep.gate(t.users[u]).accepts_synced or probe.deep.gate(t.users[u]).accepts_phone
                     or not probe.deep.gate(t.users[u]).applicable)]
        if not weak:
            return
        # Allow list: the admin profile's approved keys, else device-bound keys admins already hold.
        admin_profiles = [p for p in t.fido2.profiles.values() if 0 < profile_rank(p) <= 2 and p.key_restriction_enforced]
        aaguids = set().union(*(p.aaguids for p in admin_profiles)) if admin_profiles else set()
        if not aaguids:
            aaguids = {k.aaguid for uid in self.priv for k in t.users[uid].keys
                       if k.aaguid and k.passkey_type == "deviceBound" and k.attested is not False}
        st = AuthStrength(id=PROPOSED_PREFIX + "admin-strength", name="Admins - device-bound keys only",
                          combinations={"fido2", "windowsHelloForBusiness", "x509CertificateMultiFactor"},
                          fido2_aaguids=set(aaguids) if aaguids else None)
        t.strengths[st.id] = st
        g = self._admin_group()
        ca = CaPolicy(id=PROPOSED_PREFIX + "ca-admins", name="Admins: device-bound keys only (EffectivePasskey)",
                      state="enabled", include_users=[], exclude_users=[], include_groups=[g.id], exclude_groups=[],
                      include_roles=[], exclude_roles=[], apps=["All"], builtin_controls=[], strength_id=st.id,
                      operator="AND")
        t.ca_policies.append(ca)
        self._add("conditional_access", f"Require '{st.name}' for admins on all apps",
                  "Conditional Access must be satisfied by every applicable policy, so one strict policy closes the "
                  "sign-in gap left by plain MFA or the built-in phishing-resistant strength (which accepts synced passkeys).",
                  ["R11", "R12"],
                  before={"adminsWithWeakGate": self._labels(weak)},
                  after={"authenticationStrength": {"name": st.name, "allowedCombinations": sorted(st.combinations),
                                                    "fido2AllowedAAGUIDs": sorted(aaguids) or "any (add your keys)"},
                         "policy": ca.name, "target": g.name, "breakGlassExcluded": "not targeted"},
                  notes=["Roll out in report-only first and check sign-in logs for admins without an approved key.",
                         "Emergency-access accounts are left out on purpose; protect them separately."]
                        + ([] if aaguids else ["No approved AAGUIDs found: add your security key AAGUIDs, or synced passkeys stay accepted."]))

    def close_tap_path(self):
        tap = self.tenant.tap
        if not (tap.present and tap.enabled):
            return
        r = self._resolver()
        exposed = [u for u in self._admin_ids(include_breakglass=True)
                   if any(r.membership(self.tenant.users[u], x) for x in tap.include_targets)
                   and not any(r.membership(self.tenant.users[u], x) for x in tap.exclude_targets)]
        if not exposed:
            return
        before = {"isUsableOnce": tap.usable_once, "maximumLifetimeInMinutes": tap.max_lifetime,
                  "excluded": [self.tenant.group_name(x.id) for x in tap.exclude_targets]}
        g = self._new_group("Privileged users (TAP excluded)", exposed)
        tap.exclude_targets.append(Target(id=g.id))
        tap.usable_once = True
        tap.max_lifetime = min(tap.max_lifetime or 60, 60)
        tap.default_lifetime = min(tap.default_lifetime or 60, tap.max_lifetime)
        self._add("policy", "Exclude admins from Temporary Access Pass and make TAP single-use, 60 minutes",
                  "Anyone who can issue an admin a TAP can register a passkey on that account.", ["R13"],
                  before=before, after={"isUsableOnce": True, "maximumLifetimeInMinutes": tap.max_lifetime,
                                        "excluded": [self.tenant.group_name(x.id) for x in tap.exclude_targets]},
                  notes=["Issue admin TAPs only through a documented, two-person process, by temporarily removing the admin from this group."])

    def _references(self):
        """Every place a group id is referenced by passkey, TAP or CA policy."""
        t = self.tenant
        refs = list(t.fido2.include_targets) + list(t.fido2.exclude_targets)
        if t.tap.present:
            refs += t.tap.include_targets + t.tap.exclude_targets
        return refs

    def harden_policy_groups(self):
        probe = Auditor(self.tenant, self.before.as_of)
        probe.run()
        risky = sorted({gid for gid, *_ in probe.deep._risky_groups()
                        if gid in self.tenant.groups and self.tenant.groups[gid].role_assignable is False})
        for gid in risky:
            old = self.tenant.groups[gid]
            members = list(old.members)
            new = self._new_group(f"{old.name} (role-assignable)", members)
            for t in self._references():
                if t.id == gid:
                    t.id = new.id
            for p in self.tenant.ca_policies or []:
                p.exclude_groups = [new.id if x == gid else x for x in p.exclude_groups]
                p.include_groups = [new.id if x == gid else x for x in p.include_groups]
            self._add("group", f"Replace '{old.name}' with a role-assignable group",
                      "Only Privileged Role Administrators can change a role-assignable group, so owners and Groups "
                      "Administrators can no longer move admins in or out of policy scope.", ["R14"],
                      before={"group": old.name, "isAssignableToRole": False, "owners": len(old.owners),
                              "membershipRule": old.membership_rule or None},
                      after={"group": new.name, "isAssignableToRole": True, "owners": 0, "members": len(members)},
                      notes=["isAssignableToRole can only be set when a group is created, so this is a new group."]
                            + (["The old group was dynamic; role-assignable groups can be dynamic too, but review who can "
                                "edit the attributes in its rule."] if old.membership_rule else []))

    def finish_migration(self):
        state = self.tenant.migration_state
        if not state or state == "migrationComplete":
            return
        self.tenant.migration_state = "migrationComplete"
        self._add("policy", "Complete the authentication methods migration",
                  "Legacy MFA and SSPR settings keep governing SMS and voice until the migration is marked complete.",
                  ["R15"], before={"policyMigrationState": state}, after={"policyMigrationState": "migrationComplete"},
                  notes=["Check that the methods policy enables everything users rely on before you complete it."])

    def collect_user_tasks(self):
        for f in self.before.findings:
            if f.rule == "R2":
                self.user_tasks.append({"user": f.subject, "task": "Register a device-bound key, then delete the weak passkey", "rule": "R2", "due": "now"})
            elif f.rule == "R7":
                self.user_tasks.append({"user": f.subject, "task": "Issue and register a device-bound passkey", "rule": "R7", "due": "now"})
            elif f.rule == "R3":
                u = self.tenant.users.get(f.user_id)
                due = deadline_for(u)[0].isoformat() if u else ""
                self.user_tasks.append({"user": f.subject, "task": "Register a passkey to replace SMS/voice", "rule": "R3", "due": due})


@dataclass
class Plan:
    before: Auditor
    after: Auditor
    changes: list[Change]
    user_tasks: list[dict]
    tenant: Tenant

    def outcome(self) -> dict:
        b = {f.key: f for f in self.before.findings}
        a = {f.key: f for f in self.after.findings}
        def line(f, was=None):
            s = f"[{f.severity}] {f.rule} {f.title}: {f.subject}"
            return s + (f" (was {was})" if was and was != f.severity else "")

        return {
            "resolved": sorted(line(b[k]) for k in b.keys() - a.keys()),
            "remaining": sorted(line(a[k], b[k].severity) for k in a.keys() & b.keys()),
            "introduced": sorted(line(a[k]) for k in a.keys() - b.keys()),
            "beforeBySeverity": _count(self.before.findings),
            "afterBySeverity": _count(self.after.findings),
            "privilegedSyncedBefore": sum(1 for p in self.before.policies.values() if p.user.is_privileged and p.synced_allowed),
            "privilegedSyncedAfter": sum(1 for p in self.after.policies.values() if p.user.is_privileged and p.synced_allowed),
        }

    def to_dict(self) -> dict:
        return {"tenant": self.tenant.name, "asOf": self.before.as_of.isoformat(),
                "changes": [c.to_dict() for c in self.changes], "userTasks": self.user_tasks,
                "outcome": self.outcome(),
                "disclaimer": "Proposed changes for human review. EffectivePasskey never applies changes to a tenant."}


def _count(findings) -> dict:
    out: dict[str, int] = {}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


def build_plan(auditor: Auditor) -> Plan:
    return Planner(auditor).plan()


# ------------------------------------------------------------ output


def to_markdown(plan: Plan) -> str:
    d = plan.to_dict()
    o = d["outcome"]
    sev = lambda c: ", ".join(f"{v} {k}" for k, v in sorted(c.items(), key=lambda kv: ["critical", "high", "medium", "low", "info"].index(kv[0]))) or "none"
    out = [f"# Remediation plan: {d['tenant']}", "",
           f"_{d['disclaimer']}_", "",
           "## Simulated outcome", "",
           "Re-running the audit on the proposed configuration:",
           "",
           f"- Findings before: {sev(o['beforeBySeverity'])}",
           f"- Findings after policy changes: {sev(o['afterBySeverity'])}",
           f"- Privileged users who can register a synced passkey: {o['privilegedSyncedBefore']} → {o['privilegedSyncedAfter']}",
           f"- {len(o['resolved'])} finding(s) resolved by policy changes; the rest need the user tasks below or a human decision.",
           ""]
    if o["introduced"]:
        out += ["**Findings the proposal introduces (review before applying):**", ""]
        out += [f"- {k}" for k in o["introduced"]]
        out += ["", "An R5 here usually means a weak key the user holds stops working once the loose profile no longer "
                "covers them. Complete that user's task (register a device-bound key) before applying the change.", ""]
    out += ["## Proposed changes", ""]
    if not d["changes"]:
        out.append("No policy changes proposed.")
    for c in d["changes"]:
        out += [f"### {c['id']} · {c['title']}", "", f"{c['rationale']} (fixes {', '.join(c['fixes'])})", ""]
        if c["before"] is not None:
            out += ["Before:", "```json", json.dumps(c["before"], indent=2), "```"]
        if c["after"] is not None:
            out += ["After:", "```json", json.dumps(c["after"], indent=2), "```"]
        out += [f"> {n}" for n in c["notes"]] + [""]
    out += ["## User tasks", ""]
    if d["userTasks"]:
        out += ["| User | Task | Rule | Due |", "|---|---|---|---|"]
        out += [f"| {t['user']} | {t['task']} | {t['rule']} | {t['due']} |" for t in d["userTasks"]]
    else:
        out.append("None.")
    out += ["", "## Still open after the proposal", ""]
    out += [f"- {k}" for k in o["remaining"]] or ["Nothing."]
    out.append("")
    return "\n".join(out)


def to_html(plan: Plan, brand=None) -> str:
    from html import escape as esc

    from .html_report import CSS, Brand

    brand = brand or Brand()
    d = plan.to_dict()
    o = d["outcome"]

    def sev(c):
        order = ["critical", "high", "medium", "low", "info"]
        return ", ".join(f"{v} {k}" for k, v in sorted(c.items(), key=lambda kv: order.index(kv[0]))) or "none"

    def block(label, obj):
        return "" if obj is None else f"<div class='meta'>{label}</div><pre>{esc(json.dumps(obj, indent=2))}</pre>"

    changes = "".join(
        f"<details class='f' open><summary><span class='rule'>{esc(c['id'])}</span><strong>{esc(c['title'])}</strong>"
        f"<span class='subj'>fixes {esc(', '.join(c['fixes']))}</span></summary><div class='body'><p>{esc(c['rationale'])}</p>"
        f"{block('Before', c['before'])}{block('After', c['after'])}"
        + "".join(f"<p class='meta'>{esc(n)}</p>" for n in c["notes"]) + "</div></details>"
        for c in d["changes"]
    ) or "<p>No policy changes proposed.</p>"
    tasks = "".join(f"<tr><td>{esc(t['user'])}</td><td>{esc(t['task'])}</td><td>{esc(t['rule'])}</td><td>{esc(t['due'])}</td></tr>"
                    for t in d["userTasks"])
    lst = lambda xs: "<ul>" + "".join(f"<li>{esc(x)}</li>" for x in xs) + "</ul>" if xs else "<p>None.</p>"
    intro = ("<div class='callout'><strong>Introduced by the proposal:</strong>" + lst(o["introduced"]) +
             "An R5 here usually means a weak key the user holds stops working once the loose profile no longer covers "
             "them. Complete that user's task first.</div>") if o["introduced"] else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Remediation plan</title><style>{CSS}{brand.css()}</style></head><body><main>
{brand.header()}
<h1>Remediation plan: {esc(d['tenant'])}</h1>
<div class="meta">As of {esc(d['asOf'])} · {esc(d['disclaimer'])}</div>
<div class="tiles">
<div class="tile"><b>{len(d['changes'])}</b><span>proposed policy changes</span></div>
<div class="tile"><b>{len(o['resolved'])}</b><span>findings resolved in simulation</span></div>
<div class="tile"><b>{o['privilegedSyncedBefore']} → {o['privilegedSyncedAfter']}</b><span>admins who can register a synced passkey</span></div>
<div class="tile"><b>{len(d['userTasks'])}</b><span>user tasks</span></div>
</div>
<div class="callout">Simulated by re-running the audit on the proposed configuration. Findings before: {esc(sev(o['beforeBySeverity']))}.
After policy changes: {esc(sev(o['afterBySeverity']))}. The proposed export is in <code>proposed-export/</code>; analyze it to verify.</div>
{intro}
<h2>Proposed changes</h2>{changes}
<h2>User tasks</h2>
<div class="tablewrap"><table><thead><tr><th>User</th><th>Task</th><th>Rule</th><th>Due</th></tr></thead><tbody>{tasks or '<tr><td colspan=4>None.</td></tr>'}</tbody></table></div>
<h2>Still open after the proposal</h2>{lst(o['remaining'])}
<footer><p>{('Prepared by ' + esc(brand.name) + '. ') if brand.name else ''}Generated by EffectivePasskey. Changes are proposals for human approval and are never applied automatically.</p></footer>
</main></body></html>
"""


def _raw_profile(p: PasskeyProfile, default_id: str | None) -> dict:
    return {
        "id": p.id, "displayName": p.name, "isDefault": p.id == default_id,
        "passkeyTypes": ",".join(sorted(p.passkey_types)),
        "attestationEnforcement": "registrationOnly" if p.attestation_enforced else "disabled",
        "keyRestrictions": {"isEnforced": p.key_restriction_enforced, "enforcementType": p.key_restriction_type,
                            "aaGuids": sorted(p.aaguids)},
    }


def _raw_target(t: Target, with_profiles=True) -> dict:
    d = {"id": t.id, "targetType": t.target_type}
    if with_profiles and t.profile_ids:
        d["passkeyProfileIds"] = list(t.profile_ids)
    return d


def proposed_conditional_access(plan: Plan) -> dict | None:
    t = plan.tenant
    if t.ca_policies is None:
        return None
    raw = copy.deepcopy(t.raw_ca) if t.raw_ca else {"policies": [], "authenticationStrengths": []}
    by_id = {p.get("id"): p for p in raw.get("policies", [])}
    out = []
    for p in t.ca_policies:
        base = copy.deepcopy(by_id.get(p.id, {}))
        base.update({"id": p.id, "displayName": p.name, "state": p.state})
        cond = base.setdefault("conditions", {})
        cond["users"] = {"includeUsers": p.include_users, "excludeUsers": p.exclude_users,
                         "includeGroups": p.include_groups, "excludeGroups": p.exclude_groups,
                         "includeRoles": p.include_roles, "excludeRoles": p.exclude_roles}
        cond.setdefault("applications", {})["includeApplications"] = p.apps
        grant = {"operator": p.operator, "builtInControls": p.builtin_controls}
        if p.strength_id:
            grant["authenticationStrength"] = {"id": p.strength_id}
        base["grantControls"] = grant
        out.append(base)
    strengths = []
    for st in t.strengths.values():
        if st.builtin:
            continue
        d = {"id": st.id, "displayName": st.name, "policyType": "custom", "allowedCombinations": sorted(st.combinations)}
        if st.fido2_aaguids is not None:
            d["combinationConfigurations"] = [{"@odata.type": "#microsoft.graph.fido2CombinationConfiguration",
                                               "appliesToCombinations": ["fido2"],
                                               "allowedAAGUIDs": sorted(st.fido2_aaguids)}]
        strengths.append(d)
    return {"policies": out, "authenticationStrengths": strengths}


def proposed_policy(plan: Plan) -> dict:
    t = plan.tenant
    raw = copy.deepcopy(t.raw_policy)
    configs = raw.get("authenticationMethodConfigurations") or raw.get("value") or []
    f = t.fido2
    default_id = f.default_profile_id
    for cfg in configs:
        if "fido2" in (cfg.get("@odata.type", "") + " " + str(cfg.get("id", ""))).lower():
            cfg["state"] = f.state
            cfg["passkeyProfiles"] = [_raw_profile(p, default_id) for p in f.profiles.values()]
            cfg["includeTargets"] = [_raw_target(x) for x in f.include_targets]
            cfg["excludeTargets"] = [_raw_target(x, False) for x in f.exclude_targets]
            for legacy_key in ("isAttestationEnforced", "keyRestrictions"):
                cfg.pop(legacy_key, None)
    tap = t.tap
    for cfg in configs:
        if tap.present and "temporaryaccesspass" in (cfg.get("@odata.type", "") + " " + str(cfg.get("id", ""))).lower():
            cfg.update({"state": tap.state, "isUsableOnce": tap.usable_once,
                        "defaultLifetimeInMinutes": tap.default_lifetime, "maximumLifetimeInMinutes": tap.max_lifetime,
                        "includeTargets": [_raw_target(x, False) for x in tap.include_targets],
                        "excludeTargets": [_raw_target(x, False) for x in tap.exclude_targets]})
    if t.migration_state:
        raw["policyMigrationState"] = t.migration_state
    c = t.campaign
    if c.present:
        raw.setdefault("registrationEnforcement", {})["authenticationMethodsRegistrationCampaign"] = {
            "state": c.state,
            "snoozeDurationInDays": c.snooze_days,
            "enforceRegistrationAfterAllowedSnoozes": c.enforce_after_snoozes,
            "includeTargets": [dict(_raw_target(x, False), targetedAuthenticationMethod=c.targeted_method)
                               for x in c.include_targets],
            "excludeTargets": [_raw_target(x, False) for x in c.exclude_targets],
        }
    return raw


def write_plan(plan: Plan, out_dir: str, brand=None) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    written = []
    page = os.path.join(out_dir, "remediation.html")
    with open(page, "w", encoding="utf-8") as fh:
        fh.write(to_html(plan, brand))
    written.append(page)
    md = os.path.join(out_dir, "remediation.md")
    with open(md, "w", encoding="utf-8") as fh:
        fh.write(to_markdown(plan))
    js = os.path.join(out_dir, "remediation.json")
    with open(js, "w", encoding="utf-8") as fh:
        json.dump(plan.to_dict(), fh, indent=2)
    written += [md, js]

    proposed = os.path.join(out_dir, "proposed-export")
    os.makedirs(proposed, exist_ok=True)
    with open(os.path.join(proposed, "policy.json"), "w", encoding="utf-8") as fh:
        json.dump(proposed_policy(plan), fh, indent=2)
    groups = []
    for g in plan.tenant.groups.values():
        d = {"id": g.id, "displayName": g.name, "members": g.members}
        if g.role_assignable is not None:
            d["isAssignableToRole"] = g.role_assignable
        if g.owners:
            d["owners"] = g.owners
        if g.membership_rule:
            d["membershipRule"] = g.membership_rule
        groups.append(d)
    with open(os.path.join(proposed, "groups.json"), "w", encoding="utf-8") as fh:
        json.dump({"value": groups}, fh, indent=2)
    src = plan.tenant.source_dir
    for name in ("users.json", "roles.json", "signins.json"):
        if os.path.isfile(os.path.join(src, name)):
            shutil.copyfile(os.path.join(src, name), os.path.join(proposed, name))
    ca = proposed_conditional_access(plan)
    if ca is not None:
        with open(os.path.join(proposed, "conditional_access.json"), "w", encoding="utf-8") as fh:
            json.dump(ca, fh, indent=2)
    written.append(proposed + os.sep)
    return written
