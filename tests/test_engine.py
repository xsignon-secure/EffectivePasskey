import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import date

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from effective_passkey import html_report, report  # noqa: E402
from effective_passkey.diff import diff  # noqa: E402
from effective_passkey.model import (  # noqa: E402
    PasskeyProfile, parse_fido2, load_tenant, InputError,
)
from effective_passkey.resolver import Resolver, profile_rank  # noqa: E402
from effective_passkey.rules import Auditor  # noqa: E402

DEMOS = os.path.join(ROOT, "examples", "demo-tenants")
AS_OF = date(2026, 10, 22)


def audit(name):
    a = Auditor(load_tenant(os.path.join(DEMOS, name)), AS_OF)
    a.run()
    return a


def rules_for(a, upn):
    return {(f.rule, f.severity) for f in a.findings if f.subject == upn}


class ProfileRankTests(unittest.TestCase):
    def p(self, **kw):
        base = dict(id="x", name="x", passkey_types={"deviceBound"}, attestation_enforced=True)
        base.update(kw)
        return PasskeyProfile(**base)

    def test_ladder(self):
        self.assertEqual(profile_rank(self.p(key_restriction_enforced=True, aaguids={"a"})), 1)
        self.assertEqual(profile_rank(self.p()), 2)
        self.assertEqual(profile_rank(self.p(attestation_enforced=False)), 3)
        self.assertEqual(profile_rank(self.p(passkey_types={"synced"}, attestation_enforced=False,
                                             key_restriction_enforced=True, aaguids={"a"})), 4)
        self.assertEqual(profile_rank(self.p(passkey_types={"synced", "deviceBound"}, attestation_enforced=False)), 5)

    def test_attested_synced_only_profile_admits_nothing(self):
        self.assertEqual(profile_rank(self.p(passkey_types={"synced"})), 0)

    def test_permits_respects_attestation_and_aaguid(self):
        p = self.p(key_restriction_enforced=True, aaguids={"good"})
        self.assertTrue(p.permits("deviceBound", "good", True))
        self.assertFalse(p.permits("deviceBound", "bad", True))
        self.assertFalse(p.permits("deviceBound", "good", False))
        self.assertFalse(p.permits("synced", "good", None))
        block = self.p(key_restriction_enforced=True, key_restriction_type="block", aaguids={"bad"})
        self.assertFalse(block.permits("deviceBound", "bad", True))
        self.assertTrue(block.permits("deviceBound", "other", True))


class ResolverTests(unittest.TestCase):
    def test_union_semantics_loose_profile_wins(self):
        a = audit("contoso")
        alice = a.policies["u-alice"]
        self.assertEqual({sp.profile.id for sp in alice.profiles}, {"pp-admin", "pp-default"})
        self.assertEqual(alice.rank, 5)
        self.assertEqual(alice.strictest_rank, 1)
        self.assertEqual([sp.profile.id for sp in alice.loosest_profiles()], ["pp-default"])

    def test_exclusion_beats_inclusion(self):
        a = audit("contoso")
        self.assertEqual(a.policies["u-bg1"].status, "excluded")
        self.assertEqual(a.policies["u-bg1"].rank, 0)

    def test_nested_group_membership(self):
        a = audit("contoso")
        carol = a.policies["u-carol"]
        admin = [sp for sp in carol.profiles if sp.profile.id == "pp-admin"][0]
        self.assertEqual(admin.via[0].path, ["g-tier0", "g-admins"])

    def test_untargeted_user(self):
        a = audit("northwind")
        self.assertEqual(a.policies["u-ravi"].status, "not_targeted")

    def test_disabled_fido2(self):
        t = load_tenant(os.path.join(DEMOS, "contoso"))
        t.fido2.state = "disabled"
        a = Auditor(t, AS_OF)
        a.run()
        self.assertTrue(all(p.status == "disabled" for p in a.policies.values()))
        self.assertIn(("R10", "high"), {(f.rule, f.severity) for f in a.findings})

    def test_group_cycle_does_not_hang(self):
        t = load_tenant(os.path.join(DEMOS, "contoso"))
        t.groups["g-tier0"].members.append("g-admins")
        Resolver(t).resolve_all()

    def test_legacy_policy_synthesizes_profile(self):
        f = parse_fido2({"authenticationMethodConfigurations": [
            {"@odata.type": "#microsoft.graph.fido2AuthenticationMethodConfiguration",
             "state": "enabled", "isAttestationEnforced": True, "includeTargets": []}]})
        self.assertTrue(f.legacy)
        self.assertEqual(f.profiles["default"].passkey_types, {"deviceBound"})
        f2 = parse_fido2({"value": [{"id": "Fido2", "state": "enabled", "isAttestationEnforced": False}]})
        self.assertEqual(f2.profiles["default"].passkey_types, {"deviceBound", "synced"})


class RuleTests(unittest.TestCase):
    def test_contoso_planted_flaws(self):
        a = audit("contoso")
        self.assertIn(("R1", "critical"), rules_for(a, "alice@contoso.example"))
        bob = rules_for(a, "bob@contoso.example")
        self.assertTrue({("R1", "critical"), ("R3", "high"), ("R4", "high"), ("R7", "critical")} <= bob)
        self.assertIn(("R2", "critical"), rules_for(a, "carol@contoso.example"))
        self.assertIn(("R9", "medium"), rules_for(a, "breakglass01@contoso.example"))
        # Erin holds Helpdesk Administrator through a role-assignable group; only plain MFA covers her sign-in.
        self.assertIn(("R12", "high"), rules_for(a, "erin@contoso.example"))

    def test_deadline_cohorts(self):
        a = audit("northwind")
        cohort = {f.subject: f.cohort for f in a.findings if f.rule == "R3"}
        self.assertEqual(cohort["nora@northwind.example"], "1 Jul 2027 (Global Admin)")
        self.assertEqual(cohort["tom_supplier.example#EXT#@northwind.example"], "1 Jul 2027 (external user)")
        self.assertEqual(cohort["sara.contractor@northwind.example"], "1 Feb 2027 (internal guest)")
        self.assertEqual(cohort["quinn@northwind.example"], "1 Feb 2027")  # email does not count as MFA
        self.assertNotIn("uma@northwind.example", cohort)
        self.assertNotIn("oscar@northwind.example", cohort)  # has Authenticator too

    def test_no_passkey_path_is_critical(self):
        a = audit("northwind")
        sev = {f.subject: f.severity for f in a.findings if f.rule == "R3"}
        self.assertEqual(sev["ravi@northwind.example"], "critical")

    def test_aaguid_trap(self):
        a = audit("fabrikam")
        r5 = {f.subject for f in a.findings if f.rule == "R5"}
        self.assertEqual(r5, {"hank@fabrikam.example", "jack@fabrikam.example"})

    def test_attestation_illusion_and_hygiene(self):
        a = audit("fabrikam")
        titles = {(f.rule, f.title) for f in a.findings}
        self.assertIn(("R6", "Attested profile lists synced passkeys"), titles)
        self.assertIn(("R6", "Attested profile is bypassed by an overlapping profile"), titles)
        self.assertIn(("R8", "Registration campaign is off"), titles)
        self.assertIn(("R10", "Profile not targeted by any group"), titles)
        self.assertIn(("R10", "Authenticator AAGUIDs in allow list"), titles)

    def test_nested_overlap_reaches_admin(self):
        a = audit("fabrikam")
        # Registration is still weakened through the nested Contractors group, but the admin CA
        # strength's AAGUID allow list blocks synced passkeys at sign-in, so R1 drops to high.
        gina = rules_for(a, "gina@fabrikam.example")
        self.assertIn(("R1", "high"), gina)
        self.assertFalse(any(r == "R11" for r, _ in gina))
        r1 = [f for f in a.findings if f.rule == "R1" and f.subject == "gina@fabrikam.example"][0]
        self.assertTrue(any("Sign-in gate" in e for e in r1.evidence))

    def test_campaign_rules(self):
        a = audit("northwind")
        titles = {f.title for f in a.findings if f.rule == "R8"}
        self.assertEqual(titles, {"Campaign misses part of the SMS/voice cohort", "Campaign nudges a non-passkey method"})

    def test_every_finding_has_evidence_and_action(self):
        for name in ("contoso", "fabrikam", "northwind"):
            for f in audit(name).findings:
                self.assertTrue(f.evidence or f.rule == "R10", f.key)
                self.assertTrue(f.action, f.key)


class OutputTests(unittest.TestCase):
    def test_result_and_renderers(self):
        r = report.build_result(audit("contoso"))
        self.assertEqual(r["summary"]["grade"], "F")
        self.assertEqual(r["deadlines"]["daysToMain"], 102)
        self.assertEqual(r["summary"]["privilegedSyncedAllowed"], 4)
        json.loads(report.to_json(r))
        self.assertTrue(report.to_csv(r).startswith("severity,rule"))
        self.assertIn("at least one profile allows it", report.to_markdown(r))
        page = html_report.render(r)
        self.assertNotIn("http://", page.replace("http://www.w3.org", ""))
        self.assertNotIn("<script src", page)
        self.assertIn("frank_partner.example#EXT#@contoso.example", page)

    def test_html_escapes_untrusted_names(self):
        t = load_tenant(os.path.join(DEMOS, "contoso"))
        t.users["u-dave"].upn = "<img src=x onerror=alert(1)>"
        a = Auditor(t, AS_OF)
        a.run()
        page = html_report.render(report.build_result(a))
        self.assertNotIn("<img src=x", page)
        self.assertIn("&lt;img src=x", page)

    def test_diff_detects_fix(self):
        old = report.build_result(audit("contoso"))
        t = load_tenant(os.path.join(DEMOS, "contoso"))
        t.fido2.include_targets[0].id = "g-nobody"  # stop targeting All Users with the loose profile
        a = Auditor(t, AS_OF)
        a.run()
        new = report.build_result(a)
        d = diff(old, new)
        resolved = {(f["rule"], f["subject"]) for f in d["resolvedFindings"]}
        self.assertIn(("R1", "alice@contoso.example"), resolved)
        alice = [c for c in d["effectivePolicyChanges"] if c["user"] == "alice@contoso.example"][0]
        self.assertEqual(alice["direction"], "stronger")


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-m", "effective_passkey", *args], cwd=ROOT,
                              capture_output=True, text=True)

    def test_analyze_writes_all_formats_and_fail_on(self):
        with tempfile.TemporaryDirectory() as out:
            p = self.run_cli("analyze", os.path.join(DEMOS, "contoso"), "-o", out, "--as-of", "2026-10-22",
                             "--fail-on", "critical")
            self.assertEqual(p.returncode, 1, p.stderr)
            self.assertEqual(sorted(os.listdir(out)), ["actions.csv", "report.html", "report.md", "result.json"])

    def test_missing_input_is_exit_2(self):
        p = self.run_cli("analyze", "/nonexistent")
        self.assertEqual(p.returncode, 2)
        self.assertIn("error:", p.stderr)

    def test_explain(self):
        p = self.run_cli("explain", os.path.join(DEMOS, "contoso"), "alice@contoso.example")
        self.assertEqual(p.returncode, 0)
        self.assertIn("EFFECTIVE", p.stdout)
        self.assertIn("Synced passkey", p.stdout)

    def test_validate(self):
        p = self.run_cli("validate", os.path.join(DEMOS, "northwind"))
        self.assertEqual(p.returncode, 0)
        self.assertIn("legacy", p.stdout)


class InputTests(unittest.TestCase):
    def test_policy_without_fido2_is_input_error(self):
        with tempfile.TemporaryDirectory() as d:
            for f in ("groups", "users", "roles"):
                with open(os.path.join(d, f + ".json"), "w") as fh:
                    json.dump({"value": []}, fh)
            with open(os.path.join(d, "policy.json"), "w") as fh:
                json.dump({"authenticationMethodConfigurations": []}, fh)
            with self.assertRaises(InputError):
                load_tenant(d)


if __name__ == "__main__":
    unittest.main()
