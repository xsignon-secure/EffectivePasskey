"""Turn an audit into the canonical result dict, then render JSON, CSV and Markdown.

The HTML renderer lives in html_report.py. Every renderer reads the same
dict, so the JSON is a faithful record of what the human reports say.
"""

from __future__ import annotations

import csv
import io
import json
from collections import Counter

from . import __version__
from .constants import SEVERITY_ORDER, SMS_RETIREMENT_LATE, SMS_RETIREMENT_MAIN, TOOL_NAME
from .resolver import RANK_LABELS, profile_rank
from .rules import RULES, Auditor, deadline_for, phone_only, role_names

SCALING_NOTE = (
    "Per-user FIDO2 detail is exported for privileged users and the SMS/voice cohort only, "
    "which keeps Graph calls bounded. Rules that read registered keys (R2, R5) cover that scope."
)


def build_deadlines(as_of) -> dict:
    return {
        "main": SMS_RETIREMENT_MAIN.isoformat(),
        "late": SMS_RETIREMENT_LATE.isoformat(),
        "daysToMain": (SMS_RETIREMENT_MAIN - as_of).days,
        "daysToLate": (SMS_RETIREMENT_LATE - as_of).days,
    }


def build_result(auditor: Auditor) -> dict:
    t = auditor.tenant
    findings = [f.to_dict() for f in auditor.findings]
    sev = Counter(f["severity"] for f in findings)
    rules_by_user: dict[str, set] = {}
    for f in findings:
        if f["userId"]:
            rules_by_user.setdefault(f["userId"], set()).add(f["rule"])

    users = []
    for pol in sorted(auditor.policies.values(), key=lambda p: (-p.rank, not p.user.is_privileged, p.user.label)):
        u = pol.user
        cohort = deadline_for(u)[1] if phone_only(u) else ""
        users.append({
            "id": u.id,
            "upn": u.upn,
            "displayName": u.display_name,
            "category": u.category,
            "privileged": u.is_privileged,
            "roles": role_names(u),
            "status": pol.status,
            "rank": pol.rank,
            "weakestCredential": pol.weakest_label,
            "syncedAllowed": pol.synced_allowed,
            "profiles": [sp.profile.name for sp in pol.profiles],
            "permittedBy": [sp.profile.name for sp in pol.loosest_profiles()],
            "phoneOnly": phone_only(u),
            "smsCohort": cohort,
            "keys": [{"name": k.display_name or k.model, "aaguid": k.aaguid, "type": k.passkey_type,
                      "attested": k.attested} for k in u.keys],
            "findings": sorted(rules_by_user.get(u.id, ()), key=lambda r: int(r[1:])),
        })

    scoped_count = Counter(pid for pol in auditor.policies.values() for pid in {sp.profile.id for sp in pol.profiles})
    profiles = []
    for p in t.fido2.profiles.values():
        scoped = scoped_count[p.id]
        profiles.append({
            "id": p.id, "name": p.name,
            "passkeyTypes": sorted(p.passkey_types),
            "attestationEnforced": p.attestation_enforced,
            "keyRestriction": (f"{p.key_restriction_type} ({len(p.aaguids)})" if p.key_restriction_enforced else "none"),
            "weakestCredential": RANK_LABELS[profile_rank(p)],
            "usersScoped": scoped,
            "legacy": p.synthesized,
        })

    priv = [u for u in users if u["privileged"]]
    feb = [u for u in users if u["phoneOnly"] and u["smsCohort"].startswith("1 Feb")]
    jul = [u for u in users if u["phoneOnly"] and u["smsCohort"].startswith("1 Jul")]
    return {
        "tool": {"name": TOOL_NAME, "version": __version__},
        "tenant": t.name,
        "asOf": auditor.as_of.isoformat(),
        "deadlines": build_deadlines(auditor.as_of),
        "summary": {
            "users": len(users),
            "privileged": len(priv),
            "privilegedSyncedAllowed": sum(1 for u in priv if u["syncedAllowed"]),
            "smsFebCohort": len(feb),
            "smsJulCohort": len(jul),
            "fido2State": t.fido2.state,
            "legacyPolicy": t.fido2.legacy,
            "findingsBySeverity": {s: sev.get(s, 0) for s in SEVERITY_ORDER},
            "grade": grade(sev),
        },
        "findings": findings,
        "users": users,
        "profiles": profiles,
        "rules": {k: {"name": v[0], "definition": v[1]} for k, v in RULES.items()},
        "attackPaths": attack_paths(auditor),
        "coverage": coverage(auditor),
        "notes": [SCALING_NOTE],
    }


def coverage(auditor: Auditor) -> dict:
    """Which optional inputs were present, so readers know what the silence of R11-R16 means."""
    t = auditor.tenant
    return {
        "conditionalAccess": t.ca_policies is not None,
        "signIns": t.signins is not None,
        "temporaryAccessPass": t.tap.present,
        "migrationState": t.migration_state is not None,
        "groupOwnership": any(g.role_assignable is not None for g in t.groups.values()),
    }


def attack_paths(auditor: Auditor) -> list[dict]:
    """Per admin: the chain from role to what they can register, hold, sign in with, and who can bootstrap them."""
    out = []
    deep = auditor.deep
    t = auditor.tenant
    by_user: dict[str, list] = {}
    for f in auditor.findings:
        if f.user_id:
            by_user.setdefault(f.user_id, []).append(f)
    for pol in sorted(auditor.policies.values(), key=lambda p: p.user.label):
        u = pol.user
        if not u.is_privileged:
            continue
        steps = [{"label": "Role", "value": role_names(u), "risk": "info"}]
        if pol.status == "allowed":
            via = sorted({auditor.resolver.describe_path(m) for sp in pol.profiles for m in sp.via})
            steps.append({"label": "Passkey scope", "value": ", ".join(sp.profile.name for sp in pol.profiles)
                          + (f" ({'; '.join(via)})" if via else ""), "risk": "info"})
        steps.append({"label": "Can register", "value": pol.weakest_label,
                      "risk": "bad" if pol.rank >= 4 else "warn" if pol.rank == 3 or pol.status != "allowed" else "ok"})
        weak = [k for k in u.keys if k.passkey_type == "synced" or k.attested is False]
        if u.keys_known or u.methods:
            held = ("synced/unattested key held" if weak or "passKeySynced" in u.methods
                    else "device-bound key held" if u.keys or u.methods & {"passKeyDeviceBound", "fido2SecurityKey"}
                    else "no passkey")
            steps.append({"label": "Holds", "value": held,
                          "risk": "bad" if "synced" in held else "ok" if "device" in held else "warn"})
        g = deep.gate(u)
        steps.append({"label": "Sign-in gate", "value": g.label,
                      "risk": "info" if not g.evaluated else "bad" if (g.accepts_phone or g.accepts_synced or not g.applicable) else "ok"})
        if t.tap.present:
            tap = [f for f in by_user.get(u.id, []) if f.rule == "R13"]
            n = len(deep._issuers(u)) if tap else 0
            steps.append({"label": "TAP bootstrap", "value": f"{n} other user(s) can issue a TAP" if tap else "not TAP-eligible",
                          "risk": "bad" if tap else "ok"})
        if t.signins is not None:
            used = sorted({m for s in t.signins if s.user_id == u.id and s.succeeded for m in s.methods})
            steps.append({"label": "Signed in with", "value": ", ".join(used) or "no sign-ins in export",
                          "risk": "info" if not used else "bad" if any(("synced" in m.lower() or "text" in m.lower() or "phone" in m.lower()) for m in used) else "ok"})
        risks = [s["risk"] for s in steps]
        out.append({"user": u.label, "userId": u.id, "steps": steps,
                    "verdict": "exposed" if "bad" in risks else "partial" if "warn" in risks else "protected",
                    "rules": sorted({f.rule for f in by_user.get(u.id, [])}, key=lambda r: int(r[1:]))})
    order = {"exposed": 0, "partial": 1, "protected": 2}
    return sorted(out, key=lambda p: (order[p["verdict"]], p["user"]))


def grade(sev: Counter) -> str:
    if sev.get("critical"):
        return "F" if sev["critical"] >= 3 else "D"
    if sev.get("high"):
        return "C"
    if sev.get("medium"):
        return "B"
    return "A"


def to_json(result: dict) -> str:
    return json.dumps(result, indent=2, sort_keys=False)


def to_csv(result: dict) -> str:
    """Action list: one row per finding, cohort first so it can be split by deadline."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "rule", "rule_name", "cohort", "subject", "subject_type", "title", "action", "detail"])
    for f in result["findings"]:
        w.writerow([f["severity"], f["rule"], f["ruleName"], f["cohort"], f["subject"], f["subjectType"],
                    f["title"], f["action"], f["detail"]])
    return buf.getvalue()


def _path_row(p: dict, labels: list[str]) -> str:
    vals = {st["label"]: st["value"] for st in p["steps"]}
    cells = [vals.get(label, "-").replace("|", "/") for label in labels]
    return f"| {p['user']} | {p['verdict']} | " + " | ".join(cells) + " |"


# Per-user detail for ordinary users is capped in the readable reports; CSV and JSON stay complete.
REPORT_USER_FINDINGS_PER_RULE = 200
REPORT_USER_ROWS = 2000


def to_markdown(result: dict) -> str:
    s = result["summary"]
    d = result["deadlines"]
    sev = s["findingsBySeverity"]
    out = [
        f"# EffectivePasskey report: {result['tenant']}",
        "",
        f"As of {result['asOf']} · grade **{s['grade']}** · {result['tool']['name']} {result['tool']['version']}",
        "",
        f"- **{d['daysToMain']} days** to 1 Feb 2027 (SMS/voice retirement); {d['daysToLate']} days to 1 Jul 2027 (Global Admins, external users)",
        f"- {s['users']} users analyzed, {s['privileged']} privileged, "
        f"**{s['privilegedSyncedAllowed']} privileged users can register a synced passkey**",
        f"- SMS/voice-only: {s['smsFebCohort']} in the 1 Feb cohort, {s['smsJulCohort']} in the 1 Jul cohort",
        f"- Findings: {sev['critical']} critical, {sev['high']} high, {sev['medium']} medium, {sev['low']} low, {sev['info']} info",
        "",
        "Overlapping passkey profiles resolve by *at least one profile allows it*, not most-restrictive-wins. "
        "Each user's effective policy below is the union of every profile they are scoped to.",
        "",
        "## Admin attack paths",
        "",
        "| Admin | Verdict | " + " | ".join(dict.fromkeys(st["label"] for p in result["attackPaths"] for st in p["steps"][1:])) + " |"
        if result["attackPaths"] else "No privileged users found.",
        "|---|---|" + "---|" * len(dict.fromkeys(st["label"] for p in result["attackPaths"] for st in p["steps"][1:]))
        if result["attackPaths"] else "",
        *(_path_row(p, list(dict.fromkeys(st["label"] for q in result["attackPaths"] for st in q["steps"][1:])))
          for p in result["attackPaths"]),
        "",
        "## Findings",
        "",
    ]
    if not result["findings"]:
        out.append("No findings.")
    priv_ids = {u["id"] for u in result["users"] if u["privileged"]}
    shown: Counter = Counter()
    hidden: Counter = Counter()
    for f in result["findings"]:
        if f["userId"] and f["userId"] not in priv_ids:
            if shown[f["rule"]] >= REPORT_USER_FINDINGS_PER_RULE:
                hidden[f["rule"]] += 1
                continue
            shown[f["rule"]] += 1
        out.append(f"### [{f['severity'].upper()}] {f['rule']} {f['title']}: {f['subject']}")
        out.append("")
        out.append(f["detail"])
        out.append("")
        out.append("Evidence:")
        for i, e in enumerate(f["evidence"], 1):
            out.append(f"{i}. {e}")
        out.append("")
        out.append(f"**Action:** {f['action']}")
        out.append("")
    for rule, n in sorted(hidden.items(), key=lambda kv: int(kv[0][1:])):
        out += [f"_{n} more {rule} finding(s) for non-privileged users are not shown. They are all in actions.csv and result.json._", ""]
    out += ["## Effective policy per user", "",
            "| User | Privileged | Status / weakest credential | Permitted by | SMS cohort | Rules |",
            "|---|---|---|---|---|---|"]
    for u in result["users"][:REPORT_USER_ROWS]:
        out.append(f"| {u['upn'] or u['displayName']} | {u['roles'] or 'no'} | {u['weakestCredential']} | "
                   f"{', '.join(u['permittedBy']) or '-'} | {u['smsCohort'] or '-'} | {', '.join(u['findings']) or '-'} |")
    if len(result["users"]) > REPORT_USER_ROWS:
        out.append(f"\n_Showing the {REPORT_USER_ROWS} highest-risk of {len(result['users'])} users. Every user is in result.json._")
    out += ["", "## Passkey profiles", "",
            "| Profile | Types | Attestation | AAGUID restriction | Weakest credential | Users scoped |",
            "|---|---|---|---|---|---|"]
    for p in result["profiles"]:
        out.append(f"| {p['name']} | {', '.join(p['passkeyTypes'])} | {'required' if p['attestationEnforced'] else 'off'} | "
                   f"{p['keyRestriction']} | {p['weakestCredential']} | {p['usersScoped']} |")
    out += ["", "## Rules", ""]
    for k, r in result["rules"].items():
        out.append(f"- **{k} {r['name']}**: {r['definition']}")
    out += ["", "---", "", *(f"_{n}_" for n in result["notes"]),
            "", f"_Generated offline by {result['tool']['name']} {result['tool']['version']}. No tenant credentials were used by the analyzer._", ""]
    return "\n".join(out)
