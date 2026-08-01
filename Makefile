PYTHON ?= python

.PHONY: check test eval terraform-check verify

check:
	$(PYTHON) -m ruff check src tests
	$(PYTHON) -m ruff format --check src tests
	$(PYTHON) -m mypy src tests

test:
	$(PYTHON) -m pytest tests/unit tests/integration -q

eval:
	$(PYTHON) -m pytest tests/eval -q

terraform-check:
	terraform -chdir=infra fmt -check -recursive
	terraform -chdir=infra init -backend=false
	terraform -chdir=infra validate

verify: check test terraform-check
