"""Multi-tenant runner: audit many tenant exports at once.

Point it at a folder of tenant exports (one sub-folder per client) and it
writes every client's report plus one consolidated dashboard, so you can see
which clients are exposed and how many days each has left.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
from datetime import date
from html import escape

from . import __version__, html_report, remediation, report
from .constants import TOOL_NAME
from .diff import diff
from .model import INPUT_FILES, InputError, load_tenant
from .rules import Auditor


def discover(parent: str) -> list[str]:
    """Sub-folders of parent that hold a complete export, sorted by name."""
    if not os.path.isdir(parent):
        raise InputError(f"fleet directory not found: {parent}")
    out = []
    for name in sorted(os.listdir(parent)):
        d = os.path.join(parent, name)
        if os.path.isdir(d) and all(os.path.isfile(os.path.join(d, f)) for f in INPUT_FILES.values()):
            out.append(d)
    if not out:
        raise InputError(f"no tenant exports found under {parent} (each needs {', '.join(INPUT_FILES.values())})")
    return out


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "tenant"


def run_fleet(parent: str, out_dir: str, as_of: date, brand: html_report.Brand | None = None,
              previous: str | None = None, with_remediation: bool = False, aaguid_map: str | None = None,
              dashboard_dir: str | None = None) -> dict:
    """Write per-tenant reports under out_dir and the dashboard in dashboard_dir (default out_dir)."""
    brand = brand or html_report.Brand()
    os.makedirs(out_dir, exist_ok=True)
    dashboard_dir = dashboard_dir or out_dir
    os.makedirs(dashboard_dir, exist_ok=True)
    link = lambda *parts: os.path.relpath(os.path.join(out_dir, *parts), dashboard_dir).replace(os.sep, "/")
    rows, errors = [], []
    for d in discover(parent):
        folder = os.path.basename(os.path.normpath(d))
        key = slug(folder)
        try:
            tenant = load_tenant(d, aaguid_map_path=aaguid_map)
        except InputError as exc:
            errors.append({"tenant": folder, "error": str(exc)})
            continue
        auditor = Auditor(tenant, as_of)
        auditor.run()
        result = report.build_result(auditor)
        tdir = os.path.join(out_dir, key)
        os.makedirs(tdir, exist_ok=True)
        tenant_brand = html_report.Brand(name=brand.name, color=brand.color, logo_data_uri=brand.logo_data_uri,
                                         prepared_for=brand.prepared_for or tenant.name)
        with open(os.path.join(tdir, "report.html"), "w", encoding="utf-8") as fh:
            fh.write(html_report.render(result, tenant_brand))
        for name, fn in (("report.md", report.to_markdown), ("actions.csv", report.to_csv), ("result.json", report.to_json)):
            with open(os.path.join(tdir, name), "w", encoding="utf-8", newline="") as fh:
                fh.write(fn(result))

        s = result["summary"]
        sev = s["findingsBySeverity"]
        row = {
            "key": key, "tenant": result["tenant"], "grade": s["grade"],
            "users": s["users"], "privileged": s["privileged"],
            "privilegedSyncedAllowed": s["privilegedSyncedAllowed"],
            "critical": sev["critical"], "high": sev["high"], "medium": sev["medium"],
            "smsFeb": s["smsFebCohort"], "smsJul": s["smsJulCohort"],
            "report": link(key, "report.html"),
            "drift": None, "remediation": None,
        }
        if previous:
            prev = os.path.join(previous, key, "result.json")
            if os.path.isfile(prev):
                with open(prev, encoding="utf-8") as fh:
                    dd = diff(json.load(fh), result)
                row["drift"] = {
                    "newFindings": len(dd["newFindings"]),
                    "resolvedFindings": len(dd["resolvedFindings"]),
                    "weaker": sum(1 for c in dd["effectivePolicyChanges"] if c["direction"] == "weaker"),
                }
                with open(os.path.join(tdir, "drift.json"), "w", encoding="utf-8") as fh:
                    json.dump(dd, fh, indent=2)
        if with_remediation:
            plan = remediation.build_plan(auditor)
            remediation.write_plan(plan, os.path.join(tdir, "remediation"), tenant_brand)
            o = plan.outcome()
            row["remediation"] = {"changes": len(plan.changes), "resolves": len(o["resolved"]),
                                  "link": link(key, "remediation", "remediation.html")}
        rows.append(row)

    rows.sort(key=lambda r: ("FDCBA".index(r["grade"]), -r["critical"], -r["privilegedSyncedAllowed"], r["tenant"]))
    fleet = {
        "tool": {"name": TOOL_NAME, "version": __version__},
        "asOf": as_of.isoformat(),
        "deadlines": report.build_deadlines(as_of),
        "brand": brand.name,
        "tenants": rows,
        "errors": errors,
        "totals": {
            "tenants": len(rows),
            "users": sum(r["users"] for r in rows),
            "privilegedSyncedAllowed": sum(r["privilegedSyncedAllowed"] for r in rows),
            "critical": sum(r["critical"] for r in rows),
            "smsFeb": sum(r["smsFeb"] for r in rows),
            "smsJul": sum(r["smsJul"] for r in rows),
            "tenantsFailing": sum(1 for r in rows if r["grade"] in ("D", "F")),
        },
    }
    with open(os.path.join(dashboard_dir, "fleet.json"), "w", encoding="utf-8") as fh:
        json.dump(fleet, fh, indent=2)
    with open(os.path.join(dashboard_dir, "fleet.csv"), "w", encoding="utf-8", newline="") as fh:
        fh.write(to_csv(fleet))
    with open(os.path.join(dashboard_dir, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(render_dashboard(fleet, brand))
    return fleet


def to_csv(fleet: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["tenant", "grade", "users", "privileged", "privileged_synced_allowed", "critical", "high", "medium",
                "sms_feb_2027", "sms_jul_2027", "new_findings_since_last", "report"])
    for r in fleet["tenants"]:
        w.writerow([r["tenant"], r["grade"], r["users"], r["privileged"], r["privilegedSyncedAllowed"], r["critical"],
                    r["high"], r["medium"], r["smsFeb"], r["smsJul"],
                    "" if r["drift"] is None else r["drift"]["newFindings"], r["report"]])
    return buf.getvalue()


def render_dashboard(fleet: dict, brand: html_report.Brand) -> str:
    e = lambda x: escape(str(x), quote=True)
    t = fleet["totals"]
    d = fleet["deadlines"]
    has_drift = any(r["drift"] for r in fleet["tenants"])
    has_rem = any(r["remediation"] for r in fleet["tenants"])
    tiles = [
        (d["daysToMain"], "days to 1 Feb 2027", False),
        (t["tenants"], "tenants audited", False),
        (t["tenantsFailing"], "tenants graded D or F", t["tenantsFailing"] > 0),
        (t["privilegedSyncedAllowed"], "admins who can register a synced passkey", t["privilegedSyncedAllowed"] > 0),
        (t["critical"], "critical findings", t["critical"] > 0),
        (t["smsFeb"] + t["smsJul"], f"SMS/voice-only users ({t['smsFeb']} Feb, {t['smsJul']} Jul)", False),
    ]
    tile_html = "".join(f'<div class="tile{" alert" if a else ""}"><b>{e(v)}</b><span>{e(l)}</span></div>' for v, l, a in tiles)

    def drift_cell(r):
        if not r["drift"]:
            return "<td>-</td>"
        dr = r["drift"]
        cls = ' class="r5"' if dr["newFindings"] or dr["weaker"] else ""
        return f"<td{cls}>+{dr['newFindings']} / -{dr['resolvedFindings']}{' · ' + str(dr['weaker']) + ' weaker' if dr['weaker'] else ''}</td>"

    rows = "".join(
        f"<tr><td><a href=\"{e(r['report'])}\">{e(r['tenant'])}</a></td>"
        f"<td><span class=\"grade g-{e(r['grade'])}\">{e(r['grade'])}</span></td>"
        f"<td class=\"{'r5' if r['privilegedSyncedAllowed'] else ''}\">{e(r['privilegedSyncedAllowed'])} / {e(r['privileged'])}</td>"
        f"<td>{e(r['critical'])}</td><td>{e(r['high'])}</td><td>{e(r['medium'])}</td>"
        f"<td>{e(r['smsFeb'])}</td><td>{e(r['smsJul'])}</td><td>{e(r['users'])}</td>"
        + (drift_cell(r) if has_drift else "")
        + ((f"<td><a href=\"{e(r['remediation']['link'])}\">{e(r['remediation']['changes'])} change(s)</a></td>"
            if r["remediation"] else "<td>-</td>") if has_rem else "")
        + "</tr>"
        for r in fleet["tenants"]
    )
    errors = "".join(f"<li>{e(x['tenant'])}: {e(x['error'])}</li>" for x in fleet["errors"])
    tool = f"{fleet['tool']['name']} {fleet['tool']['version']}"
    title = f"{brand.name} passkey fleet" if brand.name else "Passkey fleet"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title><style>{html_report.CSS}{brand.css()}
.grade{{margin-left:0;font-size:13px;padding:1px 8px}}</style></head>
<body><main>
{html_report.Brand(name=brand.name, color=brand.color, logo_data_uri=brand.logo_data_uri).header()}
<h1>Effective passkey policy across {e(t['tenants'])} tenant(s)</h1>
<div class="meta">As of {e(fleet['asOf'])} · {e(tool)} · computed offline from read-only exports</div>
<div class="tiles">{tile_html}</div>
<div class="callout">Sorted worst first. "Admins synced" counts privileged users whose overlapping passkey profiles let them
register a synced, unattested passkey. SMS and voice retire on 1 Feb 2027 ({e(d['daysToMain'])} days);
Global Admins and external users on 1 Jul 2027 ({e(d['daysToLate'])} days).</div>
<div class="tablewrap"><table><thead><tr><th>Tenant</th><th>Grade</th><th>Admins synced</th><th>Critical</th><th>High</th>
<th>Medium</th><th>SMS 1 Feb</th><th>SMS 1 Jul</th><th>Users</th>{'<th>Since last run</th>' if has_drift else ''}
{'<th>Remediation</th>' if has_rem else ''}</tr></thead><tbody>{rows}</tbody></table></div>
{f'<h2>Could not analyze</h2><ul>{errors}</ul>' if errors else ''}
<footer><p>{('Prepared by ' + e(brand.name) + '. ') if brand.name else ''}Generated by {e(tool)}, an offline, read-only
Entra ID passkey auditor. Each tenant's full report, CSV action list and JSON are linked above.</p></footer>
</main></body></html>
"""
