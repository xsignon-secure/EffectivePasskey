"""Compare two JSON results from separate runs (drift between audits)."""

from __future__ import annotations

import json


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def diff(old: dict, new: dict) -> dict:
    old_f = {f["key"]: f for f in old["findings"]}
    new_f = {f["key"]: f for f in new["findings"]}
    old_u = {u["id"]: u for u in old["users"]}
    new_u = {u["id"]: u for u in new["users"]}

    changed = []
    for uid in sorted(old_u.keys() & new_u.keys()):
        a, b = old_u[uid], new_u[uid]
        if a["rank"] != b["rank"] or a["status"] != b["status"]:
            changed.append({
                "user": b["upn"] or b["displayName"],
                "privileged": b["privileged"],
                "before": a["weakestCredential"],
                "after": b["weakestCredential"],
                "direction": "weaker" if b["rank"] > a["rank"] else "stronger" if b["rank"] < a["rank"] else "status",
            })
    return {
        "from": old["asOf"],
        "to": new["asOf"],
        "newFindings": [new_f[k] for k in new_f.keys() - old_f.keys()],
        "resolvedFindings": [old_f[k] for k in old_f.keys() - new_f.keys()],
        "effectivePolicyChanges": changed,
        "usersAdded": sorted(new_u[u]["upn"] for u in new_u.keys() - old_u.keys()),
        "usersRemoved": sorted(old_u[u]["upn"] for u in old_u.keys() - new_u.keys()),
    }


def to_text(d: dict) -> str:
    lines = [f"Drift {d['from']} → {d['to']}"]
    lines.append(f"  new findings: {len(d['newFindings'])}, resolved: {len(d['resolvedFindings'])}, "
                 f"effective-policy changes: {len(d['effectivePolicyChanges'])}")
    for f in sorted(d["newFindings"], key=lambda f: f["key"]):
        lines.append(f"  + [{f['severity']}] {f['rule']} {f['title']}: {f['subject']}")
    for f in sorted(d["resolvedFindings"], key=lambda f: f["key"]):
        lines.append(f"  - [{f['severity']}] {f['rule']} {f['title']}: {f['subject']}")
    for c in d["effectivePolicyChanges"]:
        tag = " (privileged)" if c["privileged"] else ""
        lines.append(f"  ~ {c['user']}{tag}: {c['before']} → {c['after']} [{c['direction']}]")
    return "\n".join(lines)
