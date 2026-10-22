# EffectivePasskey

**See the passkey security your Entra ID tenant really has, not the one your policy screen suggests.**

EffectivePasskey is a free, open-source auditor for Microsoft Entra ID (formerly Azure AD). You export a few
read-only JSON files from your tenant, run one command, and get a report that answers three questions for every user
and every admin:

1. **What passkey can this person actually register?** (after all overlapping passkey profiles are combined)
2. **What can this admin actually sign in with?** (after every Conditional Access policy is applied)
3. **Who gets blocked when Microsoft retires SMS and voice MFA?** (1 February 2027, and 1 July 2027 for Global
   Admins and external users)

It runs entirely on your machine, needs only Python 3.10+ (no packages to install), never signs in to your tenant
and never changes anything. It also ships as an agent skill for Claude Code, Codex, Cursor and other tools that read
`SKILL.md`.

---

## Why you need it

Entra combines passkey settings in a way most admins don't expect, and the portal never shows you the result per user.

**Registration is a union.** When a user is in more than one passkey profile, a passkey is allowed if *any one* of
those profiles allows it. It is not "most restrictive wins". So a Global Admin in a strict "security keys only"
admin profile who is *also* covered by an All Users profile that allows synced passkeys can register an iCloud or
Google passkey. Your strict profile did nothing.

**Sign-in is an intersection.** Conditional Access works the other way: every policy that applies must be
satisfied. But Microsoft's built-in *Phishing-resistant MFA* strength accepts synced passkeys, so a policy that looks
strict may still let a synced passkey through.

**The deadlines are fixed.**

| Date | What happens |
|---|---|
| Mar to May 2026 | FIDO2 tenants auto-migrated to a Default passkey profile; synced passkeys allowed wherever attestation was off |
| 1 Sep 2026 | SMS/voice users auto-enabled for passkeys in a profile that allows all passkey types |
| **1 Feb 2027** | Microsoft-provided SMS and voice MFA retire. SMS/voice-only users get a blocking passkey registration prompt with no opt-out. Internal guests are in this group |
| **1 Jul 2027** | The same happens to Global Administrators and external users |

EffectivePasskey computes all of this per user, shows you exactly which group and which profile caused each problem,
and tells you what to change.

---

## Try it in one minute (no tenant needed)

Three synthetic demo tenants with planted problems are included.

```bash
git clone https://github.com/xsignon-secure/EffectivePasskey
cd EffectivePasskey
python3 -m effective_passkey analyze examples/demo-tenants/contoso -o out
```

Open `out/report.html` in a browser. Ready-made output for all three demo tenants is in
[`examples/reports`](examples/reports).

To install it as a command instead:

```bash
pip install .
effective-passkey --version
```

---

## Features

### 1. Effective policy per user (`analyze`)

The core of the tool. For every user it works out which passkey profiles apply (following nested groups and
exclusions), combines them the way Entra does, and reports the weakest credential that person can register, from
"device-bound, attested, approved keys only" down to "synced passkey from any provider". It then runs 16 rules
(R1 to R16, listed below) and writes one report.

**What you get:**

| File | Use it for |
|---|---|
| `report.html` | The main report. One self-contained file, light and dark themes, works on phones, safe to email |
| `report.md` | The same report as Markdown, for tickets and wikis |
| `actions.csv` | One row per finding with severity, subject and action, for spreadsheets and trackers |
| `result.json` | Everything, machine-readable, for scripts and for `diff` |

The report contains:

- **A grade (A to F)** and headline numbers: days to each deadline, how many admins can register a synced passkey,
  critical findings, and the size of each SMS cohort.
- **Admin attack paths.** One row per admin showing, step by step: their role → which passkey profiles apply →
  what they can register → what they already hold → what Conditional Access lets them sign in with → who could give
  them a Temporary Access Pass → what the sign-in logs show they actually used. Each step is marked safe or exposed.
- **Findings** you can filter by severity, by privileged users or by deadline cohort. Each one has an evidence chain
  (role → group path → profile → setting → Microsoft rule) and a concrete action.
- **A table of every user's effective policy** and which profile is responsible for it.
- **An "Inputs analyzed" strip** so readers know which optional files were included and what a silent rule means.

```bash
effective-passkey analyze ./my-export -o ./report
effective-passkey analyze ./my-export -o ./report --format html,csv     # only some formats
effective-passkey analyze ./my-export --fail-on critical               # exit 1 if anything critical (for CI)
```

### 2. Explain one user (`explain`)

Answers "why can this person do that?" for a single user: their roles, every profile they're scoped to and the exact
group chain that put them there, the combined result, and the findings that apply to them.

```bash
effective-passkey explain examples/demo-tenants/contoso bob@contoso.example
```

```
bob@contoso.example (member)
  roles: Security Administrator
  profile 'Default' → Synced passkey, any provider, unattested
      via All users (tenant-wide target)
  profile 'Admins - device-bound' → Device-bound, attested, allow-listed authenticators only
      via member of group 'Privileged Admins'
  EFFECTIVE (at least one profile allows it): Synced passkey, any provider, unattested
  [critical] R1 Privileged user can register a synced passkey
  [critical] R11 Admin can register and sign in with a synced passkey
  ...
```

### 3. Remediation plan, tested before you touch anything (`remediate`)

Works out the smallest set of changes that fixes the findings, applies them to an in-memory copy of your tenant,
re-runs every rule, and shows you the before and after. It never writes to your tenant; a person makes the changes in
the portal.

Depending on what it finds, it proposes to:

- move a loose profile off any target that contains admins, and scope admins to a strict device-bound, attested profile
  (pre-filled with the security keys your admins already own, so nobody is locked out);
- create a custom authentication strength that accepts only those keys, plus a Conditional Access policy for admins;
- make Temporary Access Passes one-time, short-lived and limited to admins' own role-assignable group;
- replace policy groups that non-privileged admins could edit with role-assignable groups;
- give SMS-only users a passkey path and fix the registration campaign;
- fix AAGUID allow lists that lock out keys people already use;
- finish the authentication methods migration.

It also lists per-user tasks (for example "register a device-bound key, then delete your synced passkey") and
warns you about anything a change would break. Break-glass accounts are left alone.

```bash
effective-passkey remediate ./my-export -o ./plan
```

You get `remediation.html`, `.md` and `.json`, plus `proposed-export/`: your tenant with the changes applied. You can
run `analyze` on that folder to see the result for yourself.

### 4. Track progress over time (`diff`)

Compares two runs and shows new findings, resolved findings, severity changes, and users whose effective policy got
weaker or stronger.

```bash
effective-passkey diff ./october/result.json ./november/result.json
effective-passkey diff old.json new.json --fail-on-new   # exit 1 if anything new appeared
```

### 5. Many tenants at once, for MSPs and consultants (`fleet`)

Put one export folder per client under a parent folder and run one command. You get a dashboard of every client,
worst first, with grade, admins exposed to synced passkeys, critical findings, both SMS cohorts, change since last
run and a link to each client's report and plan.

```bash
effective-passkey fleet ./clients -o ./fleet-2026-11 --remediate --previous ./fleet-2026-10
```

Output: `index.html` (the dashboard), `fleet.csv`, `fleet.json` and one report folder per client.
`--fail-on-grade D` makes a scheduled pipeline fail when any client is at D or worse.

### 6. White-label reports

`analyze`, `remediate` and `fleet` can carry your brand: `--brand-name`, `--brand-color`, `--brand-logo` (embedded,
so the report stays a single file) and `--prepared-for "Client name"`.

```bash
effective-passkey analyze ./client-a -o ./client-a-report \
  --brand-name "Your MSP" --brand-color "#0a5cff" --brand-logo logo.svg --prepared-for "Client A"
```

### 7. Check an export (`validate`)

Confirms an export loads and summarizes what is in it, before you run a full audit.

```bash
effective-passkey validate ./my-export
```

### 8. Agent skill

[`skills/effective-passkey`](skills/effective-passkey/SKILL.md) lets an AI coding agent run the audit and explain the
results in plain language. Copy that folder into your agent's skills directory (for Claude Code,
`~/.claude/skills/`) and ask something like "audit the passkey export in ./my-export".

---

## Use it on your own tenant

### Step 1: Export (read-only)

You run the collector yourself in PowerShell 7 with the `Microsoft.Graph.Authentication` module:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
./collector/Export-EffectivePasskeyData.ps1 -OutputPath ./my-export
# optional: also export admins' sign-ins from the last 7 days (needs Entra ID P1)
./collector/Export-EffectivePasskeyData.ps1 -OutputPath ./my-export -IncludeSignIns -SignInDays 7
```

It signs in with these delegated, read-only scopes and changes nothing: `Policy.Read.All`,
`UserAuthenticationMethod.Read.All`, `GroupMember.Read.All`, `RoleManagement.Read.Directory` and `AuditLog.Read.All`.

It writes:

| File | Contains | Needed |
|---|---|---|
| `policy.json` | Authentication methods policy: passkey profiles, TAP settings, registration campaign, migration state | Yes |
| `groups.json` | Groups used by the policy, CA and role assignments, with nesting, owners and role-assignability | Yes |
| `users.json` | Registered methods per user (`userRegistrationDetails`) | Yes |
| `roles.json` | Active and PIM-eligible privileged role assignments, and FIDO2 key details | Yes |
| `conditional_access.json` | Conditional Access policies and authentication strengths | Optional: enables R11, R12 and part of R14 |
| `signins.json` | Recent sign-ins of privileged users | Optional: enables R16 |

To limit Graph calls on large tenants, key details are read only for admins, SMS/voice-only users and (when an
AAGUID allow list is enforced) users who hold a passkey. You can also build the files by hand from Graph Explorer;
see [docs/export-format.md](docs/export-format.md).

### Step 2: Analyze

```bash
effective-passkey analyze ./my-export -o ./report
```

Start with the grade and the **Admin attack paths** section, then work through the critical findings.

### Step 3: Plan the fix

```bash
effective-passkey remediate ./my-export -o ./plan
```

Review `plan/remediation.html`, make the changes in the Entra portal, then export and analyze again.

### Step 4: Confirm and keep watching

```bash
effective-passkey diff ./report/result.json ./report-after/result.json
```

Run it monthly, or in CI with `--fail-on critical`, so a new group or profile can't quietly undo your work.

**Your data stays with you.** The analyzer never holds a token. Exports contain user names and method details: keep
them local and delete them when you're done.

---

## What it checks

| Rule | Finding |
|---|---|
| R1 | **Overlap weakening:** an admin can register a synced (critical) or unattested (high) passkey through any profile |
| R2 | An admin already holds a synced or unattested passkey |
| R3 | SMS/voice-only users, split into the 1 Feb and 1 Jul 2027 cohorts; critical if policy gives them no passkey path |
| R4 | An admin who uses SMS/voice sits in an "all passkey types" profile (the auto-enable shape) |
| R5 | AAGUID trap: a registered key that no profile accepts any more, so its owner will be locked out |
| R6 | Attestation illusion: an "attested" profile that lists synced types, legacy settings that imply synced, or an attested profile bypassed by an overlap |
| R7 | An admin with no phishing-resistant method at all |
| R8 | Registration campaign off, missing part of the SMS cohort, unlimited snoozes, or not targeting passkeys |
| R9 | An admin excluded from the passkey policy (exclusion beats inclusion; checks break-glass accounts) |
| R10 | Hygiene: FIDO2 disabled, too many profiles, unused profiles, targets that point at nothing, auto-added Authenticator AAGUIDs |
| R11 | **Synced passkey at sign-in:** every Conditional Access policy covering an admin accepts a synced passkey |
| R12 | Weak admin sign-in: no enforced MFA policy, or every policy accepts SMS/voice |
| R13 | Temporary Access Pass path: who can issue an admin a TAP and enrol a new passkey on their account |
| R14 | Editable policy group: a group that scopes passkeys, TAP or CA exclusions but is not role-assignable, so non-privileged admins or owners can change it |
| R15 | Authentication methods migration not finished, so legacy MFA/SSPR settings still control SMS and voice |
| R16 | Sign-in evidence: admins actually signing in with SMS, voice or a synced passkey |

Full definitions and the exact evaluation rules: [docs/rules.md](docs/rules.md).

**Severity and grade.** Findings are critical, high, medium, low or info. The grade is F with three or more critical
findings, D with one or two, C if the worst is high, B if the worst is medium, and A otherwise.

---

## Command reference

| Command | What it does |
|---|---|
| `analyze <dir> [-o out] [--format html,md,csv,json] [--as-of DATE] [--fail-on SEVERITY]` | Audit an export and write reports |
| `explain <dir> <upn>` | Show one user's profiles, group chain, effective result and findings |
| `remediate <dir> [-o out]` | Propose changes, simulate them, write the plan and a proposed export |
| `fleet <parent-dir> [-o out] [--remediate] [--previous last-run] [--fail-on-grade D] [--strict]` | Audit every tenant folder and build one dashboard |
| `diff old/result.json new/result.json [--fail-on-new] [--json]` | Show what changed between two runs |
| `validate <dir>` | Check that an export loads and summarize it |

Common options: `--as-of YYYY-MM-DD` (count deadlines from a fixed date), `--tenant-name`, `--aaguid-map map.json`
(teach it about authenticators it doesn't know), `-q` (quiet), and the white-label options above.

Exit codes: `0` ok, `1` findings at or above `--fail-on` (or new findings with `diff --fail-on-new`, or a tenant at or
below `--fail-on-grade`), `2` input error.

---

## Limits

- It has not yet been run against a real tenant's export. The Graph passkey-profile schema is new; the loader is
  tolerant and all field mapping lives in one file (`effective_passkey/model.py`). If your export looks different,
  please open an issue with a redacted copy.
- Synced versus device-bound for keys people already registered is decided from a list of known authenticator AAGUIDs.
  Extend it with `--aaguid-map`.
- Conditional Access evaluation covers users, groups, roles, apps, grant controls and authentication strengths. It
  does not model locations, device platforms, client apps or risk conditions.
- Temporary Access Pass issuers are worked out from built-in roles; custom roles and administrative units are not
  modelled.
- The collector exports sign-ins for admins only, so R16's numbers for ordinary users reflect what you export.
- The readable reports show every admin finding but cap ordinary users at 200 findings per rule and 2,000 table rows.
  `actions.csv` and `result.json` are always complete. 50,000 users analyze in about 4 seconds, 200,000 in about 20
  (about 1 GB of memory).
- Remediation is advice for a person to apply. The tool never writes to a tenant.

---

## Website

`scripts/build_site.py` builds a static landing page with the demo reports, plans and a fleet dashboard. The `Pages`
workflow publishes it once Pages is enabled (Settings > Pages > Source: GitHub Actions) and the repository variable
`PAGES_ENABLED` is set to `true`.

## Development

```bash
make test       # 69 unit tests, standard library unittest
make demo       # regenerate examples/reports (reports and remediation plans)
make collector  # run the PowerShell collector against a mocked Graph and compare (needs pwsh)
make site       # build the GitHub Pages site into ./site
```

CI runs the tests on Python 3.10, 3.12 and 3.13, checks the example reports are up to date, builds the site, installs
the package, and runs the collector against the mocked Graph.

MIT licensed. Use [Maester](https://maester.dev) for tenant-wide baselines and EffectivePasskey for effective passkey
and admin sign-in policy; they work well together.
