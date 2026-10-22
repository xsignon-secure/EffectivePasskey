"""Build the static GitHub Pages site: landing page plus demo reports, plans and fleet dashboard.

    python3 scripts/build_site.py [--out site] [--as-of YYYY-MM-DD]
"""

import argparse
import os
import shutil
import sys
from datetime import date

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from effective_passkey import __version__  # noqa: E402
from effective_passkey.fleet import run_fleet  # noqa: E402
from effective_passkey.report import build_deadlines  # noqa: E402

REPO = "https://github.com/xsignon-secure/EffectivePasskey"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "site"))
    ap.add_argument("--as-of", default=None)
    args = ap.parse_args()
    as_of = date.fromisoformat(args.as_of) if args.as_of else date.today()

    if os.path.isdir(args.out):
        shutil.rmtree(args.out)
    demo = os.path.join(args.out, "demo")
    run_fleet(os.path.join(ROOT, "examples", "demo-tenants"), demo, as_of, with_remediation=True,
              dashboard_dir=os.path.join(demo, "fleet"))

    d = build_deadlines(as_of)
    with open(os.path.join(ROOT, "site_src", "index.html"), encoding="utf-8") as fh:
        page = fh.read()
    page = (page.replace("__DAYS_MAIN__", str(d["daysToMain"])).replace("__DAYS_LATE__", str(d["daysToLate"]))
                .replace("__REPO__", REPO).replace("__VERSION__", __version__))
    with open(os.path.join(args.out, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(page)
    open(os.path.join(args.out, ".nojekyll"), "w").close()
    print(f"site built in {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
