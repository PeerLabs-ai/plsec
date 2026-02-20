# Makefile - plsec build and test targets
#
# Primary targets:
#   make all       - Lint, check, test, build, and verify everything
#   make ci        - Full CI pipeline
#   make setup     - Install Python dev dependencies via uv
#   make lint      - All linting (Python + templates)
#   make check     - Type check Python with ty
#   make format    - Format Python with ruff (mutating)
#   make test      - Run all tests (BATS + pytest)
#   make build     - Assemble build/bootstrap.sh from templates
#   make promote   - Copy build artifact to bin/bootstrap.default.sh
#   make clean     - Remove build artifacts and caches
#
# The build/ directory contains assembled output (checked in as curl target).
# The bin/bootstrap.default.sh is the promoted known-good reference.
# Uses uv for Python toolchain management throughout.

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
# Top-level targets
# ---------------------------------------------------------------------------

.PHONY: all ci

all: lint check test build verify

ci: lint check build test-assembler test verify golden-check
	@echo ""
	@echo "CI passed."

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

.PHONY: setup setup-bats

setup:
	uv sync --dev

setup-bats:
	scripts/setup-bats.sh

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

.PHONY: build clean

build: $(BUILD_OUTPUT)

$(BUILD_OUTPUT): $(SKELETON) $(TEMPLATES) $(ASSEMBLER) VERSION
	@bash $(ASSEMBLER) "$(VERSION)+bootstrap" "$(BUILD_OUTPUT)"

clean:
	rm -f $(BUILD_OUTPUT)
	rm -rf .venv.make .ruff_cache

# ---------------------------------------------------------------------------
# Promote: copy build artifact to known-good reference
# ---------------------------------------------------------------------------

.PHONY: promote

promote: $(BUILD_OUTPUT)
	@echo "Promoting build/bootstrap.sh -> bin/bootstrap.default.sh"
	@mkdir -p bin
	@cp $(BUILD_OUTPUT) $(DEFAULT_REF)
	@chmod +x $(DEFAULT_REF)
	@echo "Done. Review and commit bin/bootstrap.default.sh"

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

.PHONY: test test-unit test-integration test-container test-python test-assembler

test: test-python test-unit test-integration

test-unit:
	bats tests/bats/unit/

test-integration: build
	bats tests/bats/integration/

test-container: build
	tests/bats/run-in-container.sh tests/bats/integration/

test-python:
	uv run pytest tests/ --ignore=tests/bats

test-assembler:
	bash scripts/test-assembler-escaping.sh

# ---------------------------------------------------------------------------
# Python quality
# ---------------------------------------------------------------------------

.PHONY: lint-python check format

lint-python:
	uv run ruff check .
	uv run ruff format . --check

check:
	uv run ty check src/

format:
	uv run ruff format .

# ---------------------------------------------------------------------------
# Template and bootstrap linting
# ---------------------------------------------------------------------------

.PHONY: lint lint-templates lint-bootstrap lint-skeleton

lint: lint-python lint-templates lint-skeleton lint-bootstrap

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
# Golden files
# ---------------------------------------------------------------------------

.PHONY: golden golden-check

golden: build
	@echo "Regenerating golden files..."
	@mkdir -p $(GOLDEN_DIR)
	@cp $(TEMPLATE_DIR)/claude-md-strict.md $(GOLDEN_DIR)/
	@cp $(TEMPLATE_DIR)/claude-md-balanced.md $(GOLDEN_DIR)/
	@cp $(TEMPLATE_DIR)/opencode-json-strict.json $(GOLDEN_DIR)/
	@cp $(TEMPLATE_DIR)/opencode-json-balanced.json $(GOLDEN_DIR)/
	@cp $(TEMPLATE_DIR)/trivy-secret.yaml $(GOLDEN_DIR)/
	@cp $(TEMPLATE_DIR)/trivy.yaml $(GOLDEN_DIR)/
	@echo "Golden files updated in $(GOLDEN_DIR)/"

golden-check:
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

.PHONY: verify

verify: build
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
