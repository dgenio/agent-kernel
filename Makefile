.PHONY: fmt fmt-check lint type test example ci

fmt:
	python -m ruff format src/ tests/ examples/

fmt-check:
	python -m ruff format --check src/ tests/ examples/

lint:
	python -m ruff check src/ tests/ examples/

type:
	python -m mypy src/

test:
	python -m pytest -q --cov=weaver_kernel --cov-branch --cov-report=term-missing

example:
	python examples/basic_cli.py
	python examples/billing_demo.py
	python examples/http_driver_demo.py
	python examples/tutorial.py
	python examples/readme_quickstart.py
	python examples/contextweaver_policy_flow.py
	python examples/repository_safety_check.py
	python examples/chainweaver_flow.py
	python examples/evaluation_artifact_policy.py
	python examples/trace_export_demo.py
	python examples/persistent_audit_demo.py
	python examples/ocsf_export_demo.py
	python examples/trace_replay_demo.py

ci: fmt-check lint type test example
