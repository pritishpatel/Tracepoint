.PHONY: format lint type test security secrets audit docs check clean

PYTHON := python
PACKAGE := tracepoint
TESTS := tests

format:
	ruff format .

lint:
	ruff check .

type:
	mypy $(PACKAGE)

test:
	pytest $(TESTS)

security:
	bandit -q -r $(PACKAGE)

secrets:
	detect-secrets scan --all-files --baseline .secrets.baseline

audit:
	pip-audit

docs:
	interrogate -q $(PACKAGE)

check: format lint type test security

clean:
	find . -name "__pycache__" -type d -prune -exec rm -rf {} +
	find . -name "*.pyc" -delete
	find . -name ".DS_Store" -delete
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
