.PHONY: fmt lint type test example ci

fmt:
	ruff format src/ tests/ examples/

lint:
	ruff check src/ tests/ examples/

type:
	mypy src/

test:
	python -m pytest -q --cov=agent_kernel

example:
	python examples/basic_cli.py
	python examples/billing_demo.py
	python examples/http_driver_demo.py

ci: fmt lint type test example
