# Makefile - plsec build and test targets
#
# Run 'make' or 'make help' to see available targets.
#
# The build/ directory contains assembled output (checked in as curl target).
# The bin/bootstrap.default.sh is the promoted known-good reference.
# Uses uv for Python toolchain management throughout.

.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

VERSION := $(shell cat VERSION 2>/dev/null || echo "0.0.0-dev")

TEMPLATE_DIR  := templates/bootstrap
SKELETON      := $(TEMPLATE_DIR)/skeleton.bash
TEMPLATES     := $(wildcard $(TEMPLATE_DIR)/*.md) \
                 $(wildcard $(TEMPLATE_DIR)/*.json) \
                 $(wildcard $(TEMPLATE_DIR)/*.yaml) \
                 $(wildcard $(TEMPLATE_DIR)/*.sh)
ASSEMBLER     := scripts/assemble-bootstrap.sh

BUILD_OUTPUT  := build/bootstrap.sh
DEFAULT_REF   := bin/bootstrap.default.sh
GOLDEN_DIR    := tests/bats/golden

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

## Build
all: lint check test build verify  ## Lint, check, test, build, verify everything
ci: lint check build test-assembler test verify golden-check  ## Full CI pipeline (non-interactive)
	@echo ""
	@echo "CI passed."

build: $(BUILD_OUTPUT)  ## Assemble build/bootstrap.sh from templates

$(BUILD_OUTPUT): $(SKELETON) $(TEMPLATES) $(ASSEMBLER) VERSION
	@bash $(ASSEMBLER) "$(VERSION)+bootstrap" "$(BUILD_OUTPUT)"

promote: $(BUILD_OUTPUT)  ## Copy build to bin/bootstrap.default.sh
	@echo "Promoting build/bootstrap.sh -> bin/bootstrap.default.sh"
	@mkdir -p bin
	@cp $(BUILD_OUTPUT) $(DEFAULT_REF)
	@chmod +x $(DEFAULT_REF)
	@echo "Done. Review and commit bin/bootstrap.default.sh"

clean:  ## Remove build artifacts and caches
	rm -f $(BUILD_OUTPUT)
	rm -rf .ruff_cache

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

## Setup
setup:  ## Install Python dev dependencies via uv
	uv sync --dev

setup-bats:  ## Install BATS test framework
	scripts/setup-bats.sh

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

## Install
build-dist:  ## Build sdist and wheel (output in dist/)
	uv build

install-test:  ## Test clean install in isolated venv
	@echo "Testing clean install..."
	@rm -rf /tmp/plsec-install-test
	@uv venv /tmp/plsec-install-test
	@VIRTUAL_ENV=/tmp/plsec-install-test uv pip install dist/plsec-$(VERSION)-*.whl
	@/tmp/plsec-install-test/bin/plsec --version
	@/tmp/plsec-install-test/bin/plsec --help > /dev/null
	@echo "Clean install test passed."
	@rm -rf /tmp/plsec-install-test

install-global:  ## Deploy global configs to ~/.peerlabs/plsec (via plsec install)
	uv run plsec install --check

deploy:  ## Force redeploy global configs to ~/.peerlabs/plsec
	uv run plsec install --force --check

reset:  ## Factory reset global state (non-interactive)
	uv run plsec reset --yes

clean-install: reset install-global  ## Reset + install + verify from clean slate

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

## Test
test: test-python test-unit test-integration  ## Run all tests (pytest + BATS)

test-python:  ## pytest (426 tests)
	uv run pytest tests/ --ignore=tests/bats

test-unit:  ## BATS unit tests only
	bats tests/bats/unit/

test-integration: build  ## BATS integration tests
	bats tests/bats/integration/

test-container: build  ## Run BATS tests in container
	tests/bats/run-in-container.sh tests/bats/integration/

test-assembler:
	bash scripts/test-assembler-escaping.sh

# ---------------------------------------------------------------------------
# Quality
# ---------------------------------------------------------------------------

## Quality
lint: lint-python lint-templates lint-skeleton lint-bootstrap  ## All linting (Python + templates + bootstrap)

lint-python:  ## ruff check + format --check
	uv run ruff check .
	uv run ruff format . --check

check:  ## Type check Python with ty
	uv run ty check src/

format:  ## Format Python with ruff (mutating)
	uv run ruff format .

scan:  ## Run plsec scan against own codebase (dogfood)
	uv run plsec scan .

lint-templates:
	@echo "Checking JSON templates..."
	@for f in $(TEMPLATE_DIR)/*.json; do \
		uv run python -m json.tool "$$f" > /dev/null || exit 1; \
		echo "  OK: $$f"; \
	done
	@echo "Checking YAML templates..."
	@for f in $(TEMPLATE_DIR)/*.yaml; do \
		uv run python -c "import yaml; yaml.safe_load(open('$$f'))" || exit 1; \
		echo "  OK: $$f"; \
	done
	@echo "Checking shell templates..."
	@for f in $(TEMPLATE_DIR)/*.sh; do \
		sed 's|@@PLSEC_DIR@@|/tmp/test|g' "$$f" | bash -n || exit 1; \
		echo "  OK: $$f"; \
	done
	@echo "All templates valid."

lint-skeleton:
	@echo "Checking skeleton syntax (markers will cause errors - checking structure only)..."
	@# The skeleton has markers so bash -n will fail; check for balanced braces instead
	@OPEN=$$(grep -c '{' $(SKELETON)); \
	 CLOSE=$$(grep -c '}' $(SKELETON)); \
	 if [ "$$OPEN" != "$$CLOSE" ]; then \
		echo "  WARNING: Unbalanced braces in skeleton (open=$$OPEN close=$$CLOSE)"; \
	 else \
		echo "  OK: Brace balance ($$OPEN pairs)"; \
	 fi

lint-bootstrap: $(BUILD_OUTPUT)
	@echo "Checking assembled bootstrap.sh..."
	@bash -n $(BUILD_OUTPUT) && echo "  OK: $(BUILD_OUTPUT)" || (echo "  FAIL: $(BUILD_OUTPUT)" && exit 1)

# ---------------------------------------------------------------------------
# Golden Files
# ---------------------------------------------------------------------------

## Golden Files
golden: build  ## Regenerate golden test fixtures
	@echo "Regenerating golden files..."
	@mkdir -p $(GOLDEN_DIR)
	@cp $(TEMPLATE_DIR)/claude-md-strict.md $(GOLDEN_DIR)/
	@cp $(TEMPLATE_DIR)/claude-md-balanced.md $(GOLDEN_DIR)/
	@cp $(TEMPLATE_DIR)/opencode-json-strict.json $(GOLDEN_DIR)/
	@cp $(TEMPLATE_DIR)/opencode-json-balanced.json $(GOLDEN_DIR)/
	@cp $(TEMPLATE_DIR)/trivy-secret.yaml $(GOLDEN_DIR)/
	@cp $(TEMPLATE_DIR)/trivy.yaml $(GOLDEN_DIR)/
	@echo "Golden files updated in $(GOLDEN_DIR)/"

golden-check:  ## Verify golden files match templates
	@echo "Checking golden files match templates..."
	@FAIL=0; \
	for f in claude-md-strict.md claude-md-balanced.md opencode-json-strict.json opencode-json-balanced.json trivy-secret.yaml trivy.yaml; do \
		if ! diff -q $(TEMPLATE_DIR)/$$f $(GOLDEN_DIR)/$$f > /dev/null 2>&1; then \
			echo "  DRIFT: $$f"; \
			FAIL=1; \
		else \
			echo "  OK: $$f"; \
		fi; \
	done; \
	if [ $$FAIL -eq 1 ]; then echo "Golden file drift detected. Run 'make golden' to update." && exit 1; fi
	@echo "All golden files match."

# ---------------------------------------------------------------------------
# Verify: ensure build artifact matches the promoted reference
# ---------------------------------------------------------------------------

verify: build  ## Ensure build matches promoted reference
	@echo "Verifying build matches promoted reference..."
	@if [ ! -f $(DEFAULT_REF) ]; then \
		echo "  No reference file yet ($(DEFAULT_REF)). Run 'make promote' first."; \
		exit 1; \
	fi
	@if diff -q $(BUILD_OUTPUT) $(DEFAULT_REF) > /dev/null 2>&1; then \
		echo "  OK: build/bootstrap.sh matches bin/bootstrap.default.sh"; \
	else \
		echo "  DRIFT: build/bootstrap.sh differs from bin/bootstrap.default.sh"; \
		echo "  Run 'make promote' after reviewing changes, or fix templates."; \
		exit 1; \
	fi

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

## Help
help:  ## Show this help
	@awk 'BEGIN {FS = ":.*##"} \
		/^## [A-Z]/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 4) } \
		/^[a-zA-Z0-9_-]+:.*##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' \
		$(MAKEFILE_LIST)
	@echo ""

.PHONY: all ci build promote clean \
        setup setup-bats build-dist install-test install-global deploy reset clean-install \
        test test-python test-unit test-integration test-container test-assembler \
        lint lint-python lint-templates lint-skeleton lint-bootstrap check format scan \
        golden golden-check verify \
        help
