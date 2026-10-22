# Changelog

## 0.3.0

- Sign-in analysis (R11, R12): Conditional Access policies and authentication strengths are evaluated per admin with
  intersection semantics, including OR/AND grants, device-control bypasses, report-only policies, role, group and
  user targeting, and FIDO2 AAGUID allow lists. R1 drops to high when CA blocks synced passkeys at sign-in.
- Temporary Access Pass bootstrap path (R13) with the list of users who can issue a TAP to each admin.
- Tamperable policy groups (R14): non-role-assignable groups that scope passkeys, TAP or CA exclusions, with owners
  and dynamic rules.
- Authentication methods migration state (R15) and sign-in evidence (R16).
- Admin attack paths in HTML and Markdown reports, plus an "Inputs analyzed" coverage strip.
- Remediation proposes a custom device-bound authentication strength and CA policy, TAP lockdown, role-assignable
  replacement groups and migration completion, and writes them into the proposed export.
- Collector exports Conditional Access, TAP, group ownership and (optionally) sign-ins.

## 0.2.0

- `remediate`: proposes policy, group and campaign changes, simulates them by re-running every rule, and writes an
  HTML/Markdown/JSON plan plus a proposed export that can be analyzed. Never applied automatically.
- `fleet`: multi-tenant runner with a consolidated dashboard (worst first), per-tenant reports, CSV/JSON roll-up,
  drift against a previous run, optional remediation per tenant, `--fail-on-grade`.
- White-label options on reports: brand name, accent colour, embedded logo, client name.
- `diff` reports severity changes; finding keys stay stable when a finding's severity changes.
- GitHub Pages landing page with live deadline countdown, demo reports, remediation plans and fleet dashboard.

## 0.1.0

- Effective passkey policy resolver, rules R1-R10, HTML/Markdown/CSV/JSON reports, `explain`, `diff`, `validate`,
  read-only collector, SKILL.md package, three demo tenants.
