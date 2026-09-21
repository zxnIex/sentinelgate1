.PHONY: install run test lint security verify redteam build

install:
	python -m pip install -e ".[dev]" -r requirements-dev.txt

run:
	python -m uvicorn sentinelgate.api:app --reload

test:
	python -m pytest --cov=sentinelgate

lint:
	python -m ruff check src tests

security:
	python -m bandit -q -r src
	python -m pip_audit -r requirements.txt

redteam:
	python -m sentinelgate.redteam

verify: lint test redteam security

build:
	python -m build
