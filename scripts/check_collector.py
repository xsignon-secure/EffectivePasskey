"""Run the PowerShell collector against a mocked Graph for each demo tenant and
check that analyzing its output gives the same findings as the fixture.

Usage: python3 scripts/check_collector.py [--pwsh PATH]
"""
import argparse
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from effective_passkey.model import load_tenant  # noqa: E402
from effective_passkey.rules import Auditor  # noqa: E402
from effective_passkey.report import build_result  # noqa: E402

# The collector exports sign-ins for privileged users only, so tenant-wide
# sign-in statistics can differ from a fixture that holds everyone's sign-ins.
EXPECTED_ONLY_IN_FIXTURE = {"R16|tenant|tenant|phone-workforce"}


def findings(path):
    auditor = Auditor(load_tenant(path), date(2026, 10, 22))
    auditor.run()
    result = build_result(auditor)
    return {f["key"]: f["severity"] for f in result["findings"]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pwsh", default="pwsh")
    args = ap.parse_args()
    failed = False
    for tenant in sorted((ROOT / "examples" / "demo-tenants").iterdir()):
        with tempfile.TemporaryDirectory() as out:
            run = subprocess.run(
                [args.pwsh, "-NoProfile", "-File", str(ROOT / "collector" / "test" / "Invoke-CollectorMock.ps1"),
                 "-Tenant", str(tenant), "-OutputPath", out],
                capture_output=True, text=True)
            if run.returncode != 0:
                print(f"FAIL {tenant.name}: collector exited {run.returncode}\n{run.stdout}\n{run.stderr}")
                failed = True
                continue
            # A real export always has conditional_access.json; drop optional files the fixture
            # leaves out so both sides are analyzed from the same inputs.
            for name in ("conditional_access.json", "signins.json"):
                if not (tenant / name).exists():
                    (Path(out) / name).unlink(missing_ok=True)
            want, got = findings(tenant), findings(out)
            missing = set(want) - set(got) - EXPECTED_ONLY_IN_FIXTURE
            extra = set(got) - set(want)
            changed = {k for k in set(want) & set(got) if want[k] != got[k]}
            calls = run.stdout.strip().splitlines()[-1]
            if missing or extra or changed:
                failed = True
                print(f"FAIL {tenant.name}: missing={sorted(missing)} extra={sorted(extra)} changed={sorted(changed)}")
            else:
                print(f"ok   {tenant.name}: {len(got)} findings match the fixture ({calls})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
