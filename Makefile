.PHONY: test audit install

test:
	pytest -q --no-header

audit:
	@echo "Checking for known vulnerabilities in dependencies..."
	pip-audit --desc
	@echo ""
	heddle audit verify

install:
	pip install -e ".[dev]"
