.PHONY: test demo site
AS_OF := 2026-10-22
test:
	python3 -m unittest discover -s tests -v
demo:
	for t in contoso fabrikam northwind; do \
	  python3 -m effective_passkey analyze examples/demo-tenants/$$t -o examples/reports/$$t --as-of $(AS_OF) -q; \
	  python3 -m effective_passkey remediate examples/demo-tenants/$$t -o examples/reports/$$t/remediation --as-of $(AS_OF) -q; \
	done
site:
	python3 scripts/build_site.py --out site
