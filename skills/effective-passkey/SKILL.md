---
name: effective-passkey
description: Audit Microsoft Entra ID passkey (FIDO2) policy offline. Use when someone asks which passkeys their users or admins can actually register, whether overlapping passkey profiles weaken admin policy, who will be blocked when SMS/voice MFA retires (1 Feb 2027, Global Admins and external users 1 Jul 2027), or wants an Entra passkey audit report from exported JSON.
---

# EffectivePasskey

Computes each user's *effective* passkey policy from four read-only Entra exports and writes a
shareable report. The analyzer is offline: it never signs in and never holds a token.

## The one fact to explain

When a user is scoped to more than one passkey profile, Entra allows a passkey if it satisfies
**at least one** of them (Microsoft Learn, passkey profiles). There is no "most restrictive wins".
So a Global Admin in a strict device-bound profile who is also in an All Users profile that allows
synced passkeys can register a synced, unattested passkey. Exclusion from the FIDO2 policy is the
only thing that beats inclusion.

## Workflow

1. **Find the CLI.** Try in order and use the first that works:
   - `effective-passkey --version`
   - `python3 -m effective_passkey --version` (from a clone of the repo)
   - `pip install git+https://github.com/xsignon-secure/EffectivePasskey` then retry.
   It needs Python 3.10+ and has no dependencies.

2. **Get the exports.** Ask for a directory with `policy.json`, `groups.json`, `users.json`,
   `roles.json`. If they do not have one, point them to `collector/Export-EffectivePasskeyData.ps1`
   (PowerShell 7, read-only delegated scopes; *they* run it, you never handle tenant credentials).
   For a dry run, use `examples/demo-tenants/contoso`. Shapes are in `references/export-format.md`.

3. **Check the export loads:** `effective-passkey validate <dir>`.

4. **Analyze:** `effective-passkey analyze <dir> -o <out-dir>`.
   Writes `report.html` (self-contained, emailable), `report.md`, `actions.csv`, `result.json`.
   Use `--as-of YYYY-MM-DD` to pin the deadline countdown.

5. **Explain the results** by reading `report.md`:
   - Lead with the grade, the count of privileged users who can register synced passkeys, and the
     two SMS/voice cohorts with days left.
   - Then critical findings, each in one plain sentence plus its action. Quote the evidence chain
     when the user asks "why".
   - For a single user, run `effective-passkey explain <dir> <upn>` and walk through the chain.
   Rule meanings are in `references/rules.md`.

6. **Remediation.** Run `effective-passkey remediate <dir> -o <plan-dir>`. It proposes changes,
   simulates them and writes `remediation.md`. Walk the user through each change in order, point out
   anything listed under "introduced" (usually a weak key that stops working, so the user task comes
   first), and offer `analyze <plan-dir>/proposed-export` as proof. Present changes as steps for a
   human in the Entra portal. Never apply changes to a tenant and never write to Graph.

   For an MSP with many clients: `effective-passkey fleet <parent-dir> -o <out> --remediate`, with
   `--brand-name/--brand-color/--brand-logo` for white-label reports and `--previous <last-out>` for
   month-over-month drift.

7. **Drift.** For a later run, `effective-passkey diff old/result.json new/result.json` lists new
   and resolved findings and users whose effective policy got weaker or stronger.

## Guardrails

- Exports contain user names and method metadata. Keep them local; suggest deleting them after.
- Say what the analysis does not cover: per-user FIDO2 detail is exported only for privileged users
  and the SMS/voice cohort, and AAGUID → synced classification uses a known-provider list
  (extend with `--aaguid-map`).
- Deadlines: 1 Feb 2027 for most users (internal guests included); 1 Jul 2027 for Global Admins
  and external users.
