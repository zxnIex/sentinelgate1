.PHONY: install run test lint security verify redteam evidence build

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

evidence:
	python -m sentinelgate.benchmark_suite --iterations 2000 --output evidence/benchmark-v0.9.json
	python -m sentinelgate.adversarial_evaluation --output evidence/adversarial-v0.9.json

verify: lint test redteam security

build:
	python -m build
