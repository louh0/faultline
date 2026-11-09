.PHONY: test lint typecheck check clean

PYTHON ?= .venv/bin/python
PYTEST ?= .venv/bin/pytest
MYPY ?= .venv/bin/mypy
RUFF ?= .venv/bin/ruff

test:
	$(PYTEST)

lint:
	$(RUFF) check src tests

typecheck:
	$(MYPY) src tests

check: lint typecheck test

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache
	find . -name "__pycache__" -type d -exec rm -rf {} +
