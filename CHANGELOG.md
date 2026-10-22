# Changelog

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
