.PHONY: check validate test lint coverage deploy deploy-arm deploy-tf

# ── Quick sanity check (validator + depcheck + coverage) ──
check: validate test coverage

validate:
	@echo "=== Validating detection rules ==="
	python tools/rule-validator.py azure-sentinel/
	@echo "=== Validating hunting queries ==="
	python tools/rule-validator.py hunting-queries/

test:
	@echo "=== Running dependency checker ==="
	python tools/rule-dependency-checker.py
	@echo "=== Running KQL test framework ==="
	python tools/kql-test-framework.py

coverage:
	@echo "=== Checking ATT&CK coverage matrix is up to date ==="
	python tools/coverage-report.py --check

lint:
	@echo "=== Running FP hardening report ==="
	python tools/fp-report.py

# ── Deployment generators ──
deploy-arm:
	python tools/arm-exporter.py --out deploy/sentinel-rules.json
	@echo "ARM template written to deploy/sentinel-rules.json"

deploy-tf:
	python tools/terraform-exporter.py --out deploy/sentinel.tf
	@echo "Terraform config written to deploy/sentinel.tf"

# ── All-in-one ──
all: check lint deploy-arm deploy-tf
	@echo "All checks + deployment artifacts generated."
