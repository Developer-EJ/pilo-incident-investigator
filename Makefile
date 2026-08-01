PYTHON ?= python

.PHONY: check test eval package terraform-check verify

check:
	$(PYTHON) -m ruff check src tests scripts
	$(PYTHON) -m ruff format --check src tests scripts
	$(PYTHON) -m mypy src tests scripts

test:
	$(PYTHON) -m pytest tests/unit tests/integration -q

eval:
	$(PYTHON) -m pytest tests/eval -q
	$(PYTHON) scripts/run_eval.py

package:
	$(PYTHON) scripts/build_lambda.py

terraform-check: package
	terraform -chdir=infra fmt -check -recursive
	terraform -chdir=infra init -backend=false -input=false -lockfile=readonly
	terraform -chdir=infra validate
	terraform -chdir=infra test
	$(PYTHON) scripts/check_iam_policy.py infra

verify: check test eval terraform-check
