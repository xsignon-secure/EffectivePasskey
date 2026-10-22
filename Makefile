.PHONY: test demo
test:
	python3 -m unittest discover -s tests -v
demo:
	for t in contoso fabrikam northwind; do \
	  python3 -m effective_passkey analyze examples/demo-tenants/$$t -o examples/reports/$$t --as-of 2026-10-22 -q; \
	done
