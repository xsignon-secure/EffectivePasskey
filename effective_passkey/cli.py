"""Command line interface.

    effective-passkey analyze <export-dir> [-o out-dir] [--format html,md,csv,json]
    effective-passkey explain <export-dir> <user>
    effective-passkey diff <old.json> <new.json>
    effective-passkey validate <export-dir>

Exit codes: 0 clean, 1 findings at or above --fail-on, 2 input error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date

from . import __version__, fleet, html_report, remediation, report
from .constants import SEVERITY_ORDER
from .diff import diff, load, to_text
from .model import InputError, load_tenant
from .resolver import RANK_LABELS
from .rules import Auditor, role_names

FORMATS = {
    "html": ("report.html", html_report.render),
    "md": ("report.md", report.to_markdown),
    "csv": ("actions.csv", report.to_csv),
    "json": ("result.json", report.to_json),
}


def _as_of(s: str | None) -> date:
    if not s:
        return date.today()
    try:
        return date.fromisoformat(s)
    except ValueError:
        raise InputError(f"--as-of must be a date like 2026-10-22, got '{s}'") from None


def _audit(args) -> Auditor:
    tenant = load_tenant(args.input, name=args.tenant_name, aaguid_map_path=args.aaguid_map)
    auditor = Auditor(tenant, _as_of(args.as_of))
    auditor.run()
    return auditor


def _brand(args) -> html_report.Brand:
    try:
        return html_report.Brand.build(name=args.brand_name, color=args.brand_color, logo=args.brand_logo,
                                       prepared_for=args.prepared_for)
    except (ValueError, OSError) as exc:
        raise InputError(str(exc)) from None


def write_reports(result: dict, out_dir: str, formats: str, brand: html_report.Brand) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for fmt in [f.strip() for f in formats.split(",") if f.strip()]:
        if fmt not in FORMATS:
            raise InputError(f"unknown format '{fmt}' (choose from {', '.join(FORMATS)})")
        name, fn = FORMATS[fmt]
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(html_report.render(result, brand) if fmt == "html" else fn(result))
        written.append(path)
    return written


def cmd_analyze(args) -> int:
    brand = _brand(args)
    auditor = _audit(args)
    result = report.build_result(auditor)
    written = write_reports(result, args.output, args.format, brand)

    s = result["summary"]
    sev = s["findingsBySeverity"]
    if not args.quiet:
        print(f"{result['tenant']}: grade {s['grade']} · {s['users']} users, {s['privileged']} privileged, "
              f"{s['privilegedSyncedAllowed']} privileged can register synced passkeys")
        print(f"findings: {sev['critical']} critical, {sev['high']} high, {sev['medium']} medium, "
              f"{sev['low']} low, {sev['info']} info · SMS cohorts: {s['smsFebCohort']} (1 Feb), {s['smsJulCohort']} (1 Jul)")
        for p in written:
            print(f"wrote {p}")

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f["severity"]] <= threshold for f in result["findings"]):
            return 1
    return 0


def cmd_explain(args) -> int:
    auditor = _audit(args)
    needle = args.user.lower()
    matches = [p for p in auditor.policies.values()
               if needle in (p.user.upn.lower(), p.user.id.lower(), p.user.display_name.lower())]
    if not matches:
        matches = [p for p in auditor.policies.values() if needle in p.user.upn.lower()]
    if not matches:
        print(f"no user matches '{args.user}'", file=sys.stderr)
        return 2
    r = auditor.resolver
    for pol in matches:
        u = pol.user
        print(f"{u.label} ({u.category})")
        print(f"  roles: {role_names(u) or 'none'}")
        print(f"  status: {pol.status}")
        for m in pol.exclusions:
            print(f"  excluded: {r.describe_path(m)}")
        for sp in pol.profiles:
            print(f"  profile '{sp.profile.name}' → {RANK_LABELS[sp.rank]}")
            for m in sp.via:
                print(f"      via {r.describe_path(m)}")
        print(f"  EFFECTIVE (at least one profile allows it): {pol.weakest_label}")
        for f in auditor.findings:
            if f.user_id == u.id:
                print(f"  [{f.severity}] {f.rule} {f.title}")
    return 0


def cmd_remediate(args) -> int:
    brand = _brand(args)
    plan = remediation.build_plan(_audit(args))
    written = remediation.write_plan(plan, args.output, brand)
    o = plan.outcome()
    if not args.quiet:
        print(f"{plan.tenant.name}: {len(plan.changes)} proposed change(s), {len(plan.user_tasks)} user task(s)")
        print(f"simulated: {len(o['resolved'])} finding(s) resolved, {len(o['remaining'])} remaining, "
              f"{len(o['introduced'])} introduced; privileged users able to register synced passkeys "
              f"{o['privilegedSyncedBefore']} → {o['privilegedSyncedAfter']}")
        for p in written:
            print(f"wrote {p}")
    return 0


def cmd_fleet(args) -> int:
    brand = _brand(args)
    f = fleet.run_fleet(args.input, args.output, _as_of(args.as_of), brand=brand, previous=args.previous,
                        with_remediation=args.remediate, aaguid_map=args.aaguid_map)
    t = f["totals"]
    if not args.quiet:
        print(f"{t['tenants']} tenant(s): {t['tenantsFailing']} graded D/F, {t['critical']} critical findings, "
              f"{t['privilegedSyncedAllowed']} admins can register synced passkeys")
        for r in f["tenants"]:
            print(f"  {r['grade']}  {r['tenant']}  ({r['critical']} critical)")
        for err in f["errors"]:
            print(f"  !  {err['tenant']}: {err['error']}")
        print(f"wrote {os.path.join(args.output, 'index.html')}")
    if args.fail_on_grade:
        worst = "ABCDF"
        if any(worst.index(r["grade"]) >= worst.index(args.fail_on_grade) for r in f["tenants"]):
            return 1
    return 1 if f["errors"] and args.strict else 0


def cmd_diff(args) -> int:
    d = diff(load(args.old), load(args.new))
    print(json.dumps(d, indent=2) if args.json else to_text(d))
    return 1 if args.fail_on_new and d["newFindings"] else 0


def cmd_validate(args) -> int:
    tenant = load_tenant(args.input, aaguid_map_path=args.aaguid_map)
    f = tenant.fido2
    print(f"tenant: {tenant.name}")
    print(f"FIDO2: {f.state}, {len(f.profiles)} profile(s){' (legacy, synthesized)' if f.legacy else ''}, "
          f"{len(f.include_targets)} include / {len(f.exclude_targets)} exclude target(s)")
    print(f"groups: {len(tenant.groups)}, users: {len(tenant.users)}, "
          f"privileged: {sum(u.is_privileged for u in tenant.users.values())}, "
          f"with FIDO2 detail: {sum(u.keys_known for u in tenant.users.values())}")
    print(f"registration campaign: {tenant.campaign.state if tenant.campaign.present else 'not in export'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="effective-passkey", description="Offline effective passkey policy auditor for Entra ID.")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("input", help="directory with policy.json, groups.json, users.json, roles.json")
        p.add_argument("--as-of", help="date to compute deadlines from (YYYY-MM-DD, default today)")
        p.add_argument("--tenant-name", help="name shown on the report")
        p.add_argument("--aaguid-map", help="JSON file extending the known AAGUID → (name, synced|deviceBound) map")

    def branding(p):
        g = p.add_argument_group("report branding")
        g.add_argument("--brand-name", help="your firm's name, shown on the report header")
        g.add_argument("--brand-color", help="accent colour, e.g. #0a5cff")
        g.add_argument("--brand-logo", help="logo file (png, jpg, svg, gif; max 512 KB), embedded in the report")
        g.add_argument("--prepared-for", help="client name shown on the report header")

    a = sub.add_parser("analyze", help="audit an export and write reports")
    common(a)
    a.add_argument("-o", "--output", default="effective-passkey-report", help="output directory")
    a.add_argument("--format", default="html,md,csv,json", help="comma-separated: html,md,csv,json")
    a.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 1 if any finding is at or above this severity")
    a.add_argument("-q", "--quiet", action="store_true")
    branding(a)
    a.set_defaults(fn=cmd_analyze)

    x = sub.add_parser("explain", help="show one user's effective policy and how it was derived")
    common(x)
    x.add_argument("user", help="UPN, object id or display name")
    x.set_defaults(fn=cmd_explain)

    r = sub.add_parser("remediate", help="propose policy changes, simulate them, and write a plan (never applied)")
    common(r)
    r.add_argument("-o", "--output", default="effective-passkey-remediation", help="output directory")
    r.add_argument("-q", "--quiet", action="store_true")
    branding(r)
    r.set_defaults(fn=cmd_remediate)

    fl = sub.add_parser("fleet", help="audit every tenant export under a folder and build one dashboard")
    fl.add_argument("input", help="folder with one sub-folder of exports per tenant")
    fl.add_argument("-o", "--output", default="effective-passkey-fleet", help="output directory")
    fl.add_argument("--as-of", help="date to compute deadlines from (YYYY-MM-DD, default today)")
    fl.add_argument("--aaguid-map")
    fl.add_argument("--previous", help="a previous fleet output directory, to show drift per tenant")
    fl.add_argument("--remediate", action="store_true", help="also write a remediation plan per tenant")
    fl.add_argument("--fail-on-grade", choices=list("BCDF"), help="exit 1 if any tenant grades this or worse")
    fl.add_argument("--strict", action="store_true", help="exit 1 if any tenant export fails to load")
    fl.add_argument("-q", "--quiet", action="store_true")
    branding(fl)
    fl.set_defaults(fn=cmd_fleet)

    d = sub.add_parser("diff", help="compare two result.json files")
    d.add_argument("old")
    d.add_argument("new")
    d.add_argument("--json", action="store_true")
    d.add_argument("--fail-on-new", action="store_true", help="exit 1 if there are new findings")
    d.set_defaults(fn=cmd_diff)

    v = sub.add_parser("validate", help="check that an export loads and summarize it")
    v.add_argument("input")
    v.add_argument("--aaguid-map")
    v.set_defaults(fn=cmd_validate)
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
