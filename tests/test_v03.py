import copy
import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import date

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from effective_passkey import remediation, report  # noqa: E402
from effective_passkey.deep import _policy_accepts  # noqa: E402
from effective_passkey.model import (  # noqa: E402
    BUILTIN_STRENGTHS, CaPolicy, InputError, load_tenant, parse_conditional_access,
)
from effective_passkey.rules import Auditor  # noqa: E402

DEMOS = os.path.join(ROOT, "examples", "demo-tenants")
AS_OF = date(2026, 10, 22)
PR = "00000000-0000-0000-0000-000000000004"
ICLOUD = "fbfc3007-154e-4ecc-8c0b-6e020557d7bd"
YK = "ee882879-721c-4913-9775-3dfcce97072a"


def audit(name_or_dir):
    d = name_or_dir if os.path.isdir(name_or_dir) else os.path.join(DEMOS, name_or_dir)
    a = Auditor(load_tenant(d), AS_OF)
    a.run()
    return a


def found(a, rule, subject=None):
    return [f for f in a.findings if f.rule == rule and (subject is None or f.subject == subject)]


def ca(**kw):
    base = dict(id="p", name="p", state="enabled", include_users=["All"], exclude_users=[], include_groups=[],
                exclude_groups=[], include_roles=[], exclude_roles=[], apps=["All"], builtin_controls=[],
                strength_id=None, operator="OR")
    base.update(kw)
    return CaPolicy(**base)


class GrantSemanticsTests(unittest.TestCase):
    def setUp(self):
        _, self.st = parse_conditional_access({"policies": [], "authenticationStrengths": [
            {"id": "keys", "displayName": "keys", "allowedCombinations": ["fido2"],
             "combinationConfigurations": [{"@odata.type": "#microsoft.graph.fido2CombinationConfiguration",
                                            "allowedAAGUIDs": [YK]}]}]})

    def test_builtin_phishing_resistant_accepts_synced_but_not_sms(self):
        p = ca(strength_id=PR)
        self.assertTrue(_policy_accepts(p, self.st, "synced"))
        self.assertFalse(_policy_accepts(p, self.st, "phone"))

    def test_custom_aaguid_strength_blocks_synced(self):
        self.assertFalse(_policy_accepts(ca(strength_id="keys"), self.st, "synced"))
        self.assertTrue(self.st["keys"].accepts_passkey(YK))
        self.assertFalse(self.st["keys"].accepts_passkey(ICLOUD))

    def test_plain_mfa_accepts_everything(self):
        p = ca(builtin_controls=["mfa"])
        self.assertTrue(_policy_accepts(p, self.st, "phone"))
        self.assertTrue(_policy_accepts(p, self.st, "synced"))

    def test_or_with_compliant_device_is_a_bypass(self):
        p = ca(strength_id="keys", builtin_controls=["compliantDevice"], operator="OR")
        self.assertTrue(_policy_accepts(p, self.st, "phone"))
        p_and = ca(strength_id="keys", builtin_controls=["compliantDevice"], operator="AND")
        self.assertFalse(_policy_accepts(p_and, self.st, "phone"))

    def test_block_accepts_nothing(self):
        self.assertFalse(_policy_accepts(ca(builtin_controls=["block"]), self.st, "synced"))

    def test_builtins_always_available(self):
        self.assertEqual(set(BUILTIN_STRENGTHS) <= set(self.st), True)


class SignInRuleTests(unittest.TestCase):
    def test_contoso_builtin_strength_leaves_admins_exposed(self):
        a = audit("contoso")
        self.assertEqual({f.severity for f in found(a, "R11", "alice@contoso.example")}, {"critical"})
        gate = a.deep.gate(a.tenant.users["u-alice"])
        self.assertTrue(gate.accepts_synced)
        self.assertFalse(gate.accepts_phone)
        self.assertEqual([p.name for p in gate.report_only], [])

    def test_report_only_policy_does_not_count(self):
        t = load_tenant(os.path.join(DEMOS, "contoso"))
        for p in t.ca_policies:
            p.state = "enabledForReportingButNotEnforced"
        a = Auditor(t, AS_OF)
        a.run()
        gate = a.deep.gate(t.users["u-alice"])
        self.assertEqual(gate.applicable, [])
        self.assertEqual(len(gate.report_only), 2)
        self.assertEqual(found(a, "R12", "alice@contoso.example")[0].severity, "critical")

    def test_device_only_policy_is_not_an_mfa_gate(self):
        a = audit("contoso")
        erin = a.deep.gate(a.tenant.users["u-erin"])
        self.assertEqual([p.name for p in erin.applicable], ["All users: require MFA"])
        self.assertTrue(erin.accepts_phone)

    def test_ca_exclusion_group_and_breakglass(self):
        a = audit("contoso")
        r12 = found(a, "R12", "breakglass01@contoso.example")[0]
        self.assertEqual(r12.severity, "medium")
        self.assertIn("emergency-access", " ".join(r12.evidence))

    def test_pim_eligible_role_counts_for_ca_role_targeting(self):
        a = audit("contoso")
        gate = a.deep.gate(a.tenant.users["u-carol"])
        self.assertIn("Admins: require phishing-resistant MFA", [p.name for p in gate.applicable])

    def test_custom_strength_downgrades_r1(self):
        a = audit("fabrikam")
        self.assertFalse(found(a, "R11"))
        self.assertEqual(found(a, "R1", "gina@fabrikam.example")[0].severity, "high")

    def test_missing_optional_inputs_stay_silent(self):
        a = audit("northwind")
        for rule in ("R11", "R12", "R13", "R15", "R16"):
            self.assertFalse(found(a, rule), rule)
        # Group ownership comes from groups.json, which every export has
        self.assertEqual([f.subject for f in found(a, "R14")], ["Passkey Pilot"])
        cov = report.build_result(a)["coverage"]
        self.assertEqual(cov, {"conditionalAccess": False, "signIns": False, "temporaryAccessPass": False,
                               "migrationState": False, "groupOwnership": True})

    def test_single_item_arrays_from_powershell(self):
        # ConvertTo-Json writes a one-item array as a bare object; the loader must not drop it
        from effective_passkey.model import parse_conditional_access, parse_groups
        policies, strengths = parse_conditional_access({
            "policies": {"id": "p1", "displayName": "Admins", "state": "enabled",
                         "conditions": {"users": {"includeRoles": "62e90394-69f5-4237-9190-012177145e10"},
                                        "applications": {"includeApplications": "All"}},
                         "grantControls": {"operator": "OR", "authenticationStrength": {"id": "s1"}}},
            "authenticationStrengths": {"id": "s1", "displayName": "Keys", "allowedCombinations": "fido2",
                                        "combinationConfigurations": {
                                            "@odata.type": "#microsoft.graph.fido2CombinationConfiguration",
                                            "allowedAAGUIDs": ["ee882879-721c-4913-9775-3dfcce97072a"]}},
        })
        self.assertEqual([p.id for p in policies], ["p1"])
        self.assertEqual(policies[0].apps, ["All"])
        self.assertFalse(strengths["s1"].accepts_passkey("fbfc3007-154e-4ecc-8c0b-6e020557d7bd"))
        groups = parse_groups({"value": {"id": "g1", "displayName": "One", "members": "u1"}})
        self.assertEqual(groups["g1"].members, ["u1"])

    def test_no_policy_for_admin_is_critical(self):
        with tempfile.TemporaryDirectory() as d:
            shutil.copytree(os.path.join(DEMOS, "contoso"), d, dirs_exist_ok=True)
            with open(os.path.join(d, "conditional_access.json"), "w") as fh:
                json.dump({"policies": []}, fh)
            a = audit(d)
            self.assertEqual(found(a, "R12", "alice@contoso.example")[0].severity, "critical")
            self.assertEqual(found(a, "R12", "bob@contoso.example")[0].severity, "high")


class TapTests(unittest.TestCase):
    def test_multi_use_long_tap_is_high_and_lists_issuers(self):
        a = audit("contoso")
        bob = found(a, "R13", "bob@contoso.example")[0]
        self.assertEqual(bob.severity, "high")
        issuers = [u.label for u in a.deep._issuers(a.tenant.users["u-bob"])]
        self.assertEqual(issuers, ["alice@contoso.example", "breakglass01@contoso.example"])

    def test_helpdesk_admin_can_be_issued_by_auth_admin(self):
        t = load_tenant(os.path.join(DEMOS, "contoso"))
        t.users["u-dave"].roles.append({"name": "Authentication Administrator",
                                        "templateId": "c4e39bd9-1100-46d3-8c65-fb160da0071f",
                                        "assignment": "active", "via": None})
        a = Auditor(t, AS_OF)
        a.run()
        self.assertIn("dave@contoso.example", [u.label for u in a.deep._issuers(t.users["u-erin"])])
        self.assertNotIn("dave@contoso.example", [u.label for u in a.deep._issuers(t.users["u-bob"])])

    def test_single_use_short_tap_is_medium(self):
        self.assertEqual({f.severity for f in found(audit("fabrikam"), "R13")}, {"medium"})


class GroupMigrationSignInTests(unittest.TestCase):
    def test_r14_aggregates_uses_per_group(self):
        a = audit("contoso")
        r14 = found(a, "R14")
        self.assertEqual([f.subject for f in r14], ["CA exclusions (legacy apps)"])
        self.assertEqual(r14[0].severity, "critical")
        self.assertIn("Owners: dave@contoso.example", r14[0].evidence)

    def test_r14_dynamic_rule_and_unknown_ownership(self):
        a = audit("fabrikam")
        r14 = found(a, "R14")
        self.assertEqual([f.subject for f in r14], ["Contractors"])
        self.assertTrue(any("Dynamic membership rule" in e for e in r14[0].evidence))

    def test_r15(self):
        self.assertEqual(found(audit("contoso"), "R15")[0].severity, "high")
        self.assertFalse(found(audit("fabrikam"), "R15"))

    def test_r16_ignores_failed_signins(self):
        a = audit("contoso")
        self.assertEqual(len(found(a, "R16", "carol@contoso.example")), 1)
        bob = found(a, "R16", "bob@contoso.example")[0]
        self.assertIn("1 successful", bob.detail)
        self.assertEqual(found(a, "R16", "tenant")[0].severity, "info")


class AttackPathAndRemediationTests(unittest.TestCase):
    def test_attack_paths(self):
        r = report.build_result(audit("contoso"))
        paths = {p["user"]: p for p in r["attackPaths"]}
        self.assertEqual(set(paths), {"alice@contoso.example", "bob@contoso.example", "carol@contoso.example",
                                      "erin@contoso.example", "breakglass01@contoso.example"})
        carol = {s["label"]: s for s in paths["carol@contoso.example"]["steps"]}
        self.assertEqual(carol["Signed in with"]["value"], "Passkey (synced)")
        self.assertEqual(carol["Sign-in gate"]["risk"], "bad")
        self.assertIn("Admin attack paths", report.to_markdown(r))

    def test_remediation_closes_signin_tap_group_and_migration(self):
        plan = remediation.build_plan(audit("contoso"))
        fixed = {r for c in plan.changes for r in c.fixes}
        self.assertTrue({"R11", "R12", "R13", "R14", "R15"} <= fixed)
        after = {f.rule for f in plan.after.findings}
        for rule in ("R11", "R13", "R14", "R15"):
            self.assertNotIn(rule, after, rule)
        st = plan.tenant.strengths["ep-proposed-admin-strength"]
        self.assertEqual(st.fido2_aaguids, {"cb69481e-8ff7-4039-93ec-0a2729a154a8", YK,
                                            "a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa"})

    def test_remediation_does_not_touch_inputs(self):
        before = audit("contoso")
        snap = copy.deepcopy(before.tenant.ca_policies)
        remediation.build_plan(before)
        self.assertEqual(before.tenant.ca_policies, snap)

    def test_bad_conditional_access_json(self):
        with tempfile.TemporaryDirectory() as d:
            shutil.copytree(os.path.join(DEMOS, "contoso"), d, dirs_exist_ok=True)
            with open(os.path.join(d, "conditional_access.json"), "w") as fh:
                fh.write("{oops")
            with self.assertRaises(InputError):
                load_tenant(d)


class LargeTenantReportTests(unittest.TestCase):
    def test_readable_reports_cap_ordinary_user_detail(self):
        from unittest import mock
        from effective_passkey import html_report
        result = report.build_result(audit("northwind"))
        r3 = [f for f in result["findings"] if f["rule"] == "R3" and f["userId"]]
        self.assertTrue(r3)
        with mock.patch.object(html_report, "REPORT_USER_FINDINGS_PER_RULE", 0), \
                mock.patch.object(html_report, "REPORT_USER_ROWS", 1), \
                mock.patch.object(report, "REPORT_USER_FINDINGS_PER_RULE", 0), \
                mock.patch.object(report, "REPORT_USER_ROWS", 1):
            page = html_report.render(result)
            md = report.to_markdown(result)
        self.assertIn("more R3 finding(s) for non-privileged users", page)
        self.assertIn("more R3 finding(s) for non-privileged users", md)
        self.assertIn(f"Showing the 1 highest-risk of {len(result['users'])} users", page)
        # Admin findings are never capped
        self.assertIn("oscar@northwind.example", page)


if __name__ == "__main__":
    unittest.main()
