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
from .model import PasskeyProfile, Target, Tenant, Group
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
        g = Group(id=gid, name=name, members=sorted(members))
        self.tenant.groups[gid] = g
        return g

    def _labels(self, uids) -> list[str]:
        return sorted(self.tenant.users[u].label for u in uids if u in self.tenant.users)

    def _resolver(self) -> Resolver:
        return Resolver(self.tenant)

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
            if any(w in u.label.lower() for w in ("break", "glass", "emergency", "bg-")):
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
            admins = {u for u in covered & self.priv if self._resolver().resolve(self.tenant.users[u]).status != "excluded"}
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
    groups = [{"id": g.id, "displayName": g.name, "members": g.members} for g in plan.tenant.groups.values()]
    with open(os.path.join(proposed, "groups.json"), "w", encoding="utf-8") as fh:
        json.dump({"value": groups}, fh, indent=2)
    src = plan.tenant.source_dir
    for name in ("users.json", "roles.json"):
        shutil.copyfile(os.path.join(src, name), os.path.join(proposed, name))
    written.append(proposed + os.sep)
    return written
