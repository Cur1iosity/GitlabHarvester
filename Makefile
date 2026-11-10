# Thin convenience wrappers; every target maps to a plain command documented in
# docs/testing.md, so Windows users can run the same thing without make.
PYTHON ?= python
SCENARIO ?= default
PORT ?= 8080

.PHONY: help install test test-unit test-integration test-e2e test-contract \
        fake fake-up fake-down fake-logs fake-requests cli clean

help:             ## Show targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/'

install:          ## Install the package (editable) and pinned dev dependencies
	$(PYTHON) -m pip install -r requirements-dev.txt -e .

test:             ## All automated tests (unit + integration + e2e)
	$(PYTHON) -m pytest

test-unit:        ## Unit tests only (no HTTP)
	$(PYTHON) -m pytest -m unit

test-integration: ## python-gitlab against the Fake GitLab
	$(PYTHON) -m pytest -m integration

test-e2e:         ## CLI subprocess against the Fake GitLab
	$(PYTHON) -m pytest -m e2e

test-contract:    ## Optional: real GitLab (needs GLH_CONTRACT_URL / GLH_CONTRACT_TOKEN)
	$(PYTHON) -m pytest -m contract tests/contract

fake:             ## Run the Fake GitLab in the foreground (no Docker)
	$(PYTHON) -m fakegitlab --scenario $(SCENARIO) --port $(PORT)

fake-up:          ## Start the Fake GitLab container
	mkdir -p .dev/work .dev/scenarios
	FAKE_GITLAB_SCENARIO=$(SCENARIO) FAKE_GITLAB_PORT=$(PORT) docker compose up -d --build --wait fake-gitlab

fake-down:        ## Stop containers
	docker compose --profile cli down

fake-logs:        ## Follow the Fake GitLab request log
	docker compose logs -f fake-gitlab

fake-requests:    ## Dump the request journal as JSON
	@$(PYTHON) -c "import json,urllib.request;print(json.dumps(json.load(urllib.request.urlopen('http://127.0.0.1:$(PORT)/__admin/requests')),indent=2,ensure_ascii=False))"

cli:              ## Run the CLI in Docker: make cli ARGS="-s password -b all"
	mkdir -p .dev/work .dev/scenarios
	DEV_UID=$$(id -u) DEV_GID=$$(id -g) docker compose run --rm harvester $(ARGS)

clean:            ## Remove generated files of the dev environment
	rm -rf .dev/work .pytest_cache
