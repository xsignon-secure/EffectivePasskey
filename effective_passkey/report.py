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
            "findings": sorted({f["rule"] for f in findings if f["userId"] == u.id}, key=lambda r: int(r[1:])),
        })

    profiles = []
    for p in t.fido2.profiles.values():
        scoped = sum(1 for pol in auditor.policies.values() if any(sp.profile.id == p.id for sp in pol.profiles))
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
        "notes": [SCALING_NOTE],
    }


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
        "## Findings",
        "",
    ]
    if not result["findings"]:
        out.append("No findings.")
    for f in result["findings"]:
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
    out += ["## Effective policy per user", "",
            "| User | Privileged | Status / weakest credential | Permitted by | SMS cohort | Rules |",
            "|---|---|---|---|---|---|"]
    for u in result["users"]:
        out.append(f"| {u['upn'] or u['displayName']} | {u['roles'] or 'no'} | {u['weakestCredential']} | "
                   f"{', '.join(u['permittedBy']) or '-'} | {u['smsCohort'] or '-'} | {', '.join(u['findings']) or '-'} |")
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
