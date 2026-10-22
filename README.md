# EffectivePasskey

**Your admins can register a weaker passkey than your policy says. Prove it before 1 February 2027.**

EffectivePasskey is an offline, read-only auditor for Microsoft Entra ID. Feed it four exported JSON
files and it computes, for every user, the passkey they can *actually* register once overlapping
passkey profiles resolve, then writes one shareable report.

It ships as a small Python CLI (standard library only) and as an agent skill
([`skills/effective-passkey`](skills/effective-passkey/SKILL.md)) for Claude Code, Codex, Cursor and
other tools that read `SKILL.md`.

## Why

Entra passkey profiles do **not** resolve by "most restrictive wins". When a user is scoped to more
than one profile, a passkey is allowed if it satisfies **at least one** of them (Microsoft Learn,
passkey profiles). So a Global Admin in a strict "device-bound, attested" admin profile who is also
covered by an All Users profile that allows synced passkeys can register a synced, unattested
passkey. The portal shows both profiles side by side and never computes the result per user.

The clock is running:

| Date | What happens |
|---|---|
| Mar to May 2026 | FIDO2 tenants auto-migrated to a Default passkey profile; synced allowed wherever attestation was off |
| 1 Sep 2026 | SMS/voice users auto-enabled for passkeys in a profile allowing all passkey types |
| **1 Feb 2027** | Microsoft-provided SMS and voice MFA retire. SMS/voice-only users get a blocking passkey registration prompt, no opt-out. Internal guests are in this cohort |
| **1 Jul 2027** | Same for Global Administrators and external users |

## Quick start

```bash
git clone https://github.com/xsignon-secure/EffectivePasskey && cd EffectivePasskey
python3 -m effective_passkey analyze examples/demo-tenants/contoso -o out
open out/report.html
```

Or install the command: `pip install .` then `effective-passkey analyze <export-dir> -o <out-dir>`.

Sample output for the three synthetic demo tenants is committed under
[`examples/reports`](examples/reports) (HTML, Markdown, CSV, JSON).

## Getting your exports

Run the read-only collector yourself (PowerShell 7 + `Microsoft.Graph.Authentication`):

```powershell
./collector/Export-EffectivePasskeyData.ps1 -OutputPath ./my-export
```

It uses delegated scopes `Policy.Read.All`, `UserAuthenticationMethod.Read.All`,
`GroupMember.Read.All`, `RoleManagement.Read.Directory` and `AuditLog.Read.All` (for the
`userRegistrationDetails` report), and changes nothing. You can also build the four files from Graph
Explorer; see [docs/export-format.md](docs/export-format.md).

**The analyzer never holds a token.** You export, you analyze, you delete.

## Commands

| Command | What it does |
|---|---|
| `analyze <dir> [-o out] [--format html,md,csv,json] [--as-of DATE] [--fail-on SEVERITY]` | Audit and write reports. `--fail-on` exits 1 for CI gating |
| `explain <dir> <upn>` | One user's scoped profiles, the group chain that put them there, and the effective result |
| `diff old/result.json new/result.json` | Drift between two runs: new and resolved findings, users whose policy got weaker or stronger |
| `validate <dir>` | Check an export loads and summarize it |

Exit codes: `0` ok, `1` findings at or above `--fail-on` (or new findings with `diff --fail-on-new`), `2` input error.

## What it checks

| Rule | Finding |
|---|---|
| R1 | **Overlap weakening:** a privileged user can register a synced (critical) or unattested (high) passkey via any profile |
| R2 | A privileged user already holds a synced or unattested passkey |
| R3 | SMS/voice-only users, split into the 1 Feb and 1 Jul 2027 cohorts; critical if policy gives them no passkey path |
| R4 | Privileged SMS/voice user in an "all passkey types" profile (the auto-enable shape) |
| R5 | AAGUID trap: a registered key that no scoped profile accepts any more |
| R6 | Attestation illusion: attested profile listing synced, legacy policy implying synced, or attested profile bypassed by overlap |
| R7 | Privileged user with no phishing-resistant method |
| R8 | Registration campaign off, missing part of the SMS cohort, unlimited snoozes, or not targeting passkeys |
| R9 | Privileged user excluded from the passkey policy (exclusion beats inclusion; break-glass check) |
| R10 | Hygiene: FIDO2 disabled, profile sprawl, unused profiles, dangling targets, auto-added Authenticator AAGUIDs |

Every finding carries an evidence chain (role → group path → profile → setting → Microsoft rule) and
an action. Full definitions: [docs/rules.md](docs/rules.md).

## Limits, stated plainly

- Per-user FIDO2 detail is exported for privileged users and the SMS/voice cohort only, so R2 and R5
  cover that scope. This keeps Graph calls bounded on large tenants.
- Synced vs device-bound for already-registered keys is classified from a list of known provider
  AAGUIDs; extend it with `--aaguid-map`.
- The Graph passkey-profile schema is new. The loader is tolerant, and field mapping lives in one
  file (`effective_passkey/model.py`). Please open an issue with a redacted export if yours differs.
- Remediation is advice for a human. The tool never writes to a tenant.

## Development

```bash
make test   # 26 unit tests, stdlib unittest
make demo   # regenerate examples/reports
```

MIT licensed. Use [Maester](https://maester.dev) for tenant baselines and EffectivePasskey for the
effective passkey policy; they work well together.
