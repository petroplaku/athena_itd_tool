.PHONY: help install dev test lint demo serve report build clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

install:  ## Install the package
	python -m pip install .

dev:  ## Install with dev extras (tests, linters, pyinstaller)
	python -m pip install -e ".[dev]"

test:  ## Run the test suite
	pytest -q

lint:  ## Lint with ruff
	ruff check src tests

demo:  ## Generate synthetic data and run analysis
	athena init
	athena generate --users 30 --days 30 --reset
	athena analyze --respond
	athena report

serve:  ## Launch the web dashboard (opens browser)
	athena serve --open

report:  ## Generate HTML + JSON reports
	athena report

build:  ## Build a standalone binary for the current OS
	bash packaging/build.sh

clean:  ## Remove build artifacts
	rm -rf build dist release .build-venv *.egg-info src/*.egg-info .pytest_cache .ruff_cache
