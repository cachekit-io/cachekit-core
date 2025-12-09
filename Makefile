# cachekit-core - Development Makefile

.PHONY: help check test lint clippy audit deny vet fmt fmt-check fuzz-quick fuzz-deep sbom clean
.DEFAULT_GOAL := help

# Colors for output
BLUE := \033[36m
GREEN := \033[32m
YELLOW := \033[33m
RESET := \033[0m

# Helper function to check if a binary exists
define require_binary
	@command -v $(1) >/dev/null 2>&1 || { echo "$(YELLOW)❌ $(1) not found. $(2)$(RESET)"; exit 1; }
endef

help: ## Show available commands
	@echo "$(BLUE)cachekit-core - Development Commands$(RESET)"
	@echo ""
	@echo "$(GREEN)Common Workflows:$(RESET)"
	@echo "  $(YELLOW)make check$(RESET)       Run all fast checks (fmt-check, lint, test, audit, deny)"
	@echo "  $(YELLOW)make test$(RESET)        Run tests with all features"
	@echo "  $(YELLOW)make fmt$(RESET)         Format code"
	@echo ""
	@echo "$(GREEN)All Commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(YELLOW)%-20s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""

check: fmt-check lint test audit deny vet ## Run all fast checks (fmt, lint, test, audit, deny, vet)
	@echo ""
	@echo "$(GREEN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "$(GREEN)✓ All checks passed$(RESET)"
	@echo "$(GREEN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"

test: ## Run tests with all features
	@echo "$(BLUE)Running tests...$(RESET)"
	$(call require_binary,cargo,Install Rust: https://rustup.rs)
	@cargo test --all-features
	@echo "$(GREEN)✓ Tests passed$(RESET)"

lint: ## Run clippy with all features
	@echo "$(BLUE)Running clippy...$(RESET)"
	$(call require_binary,cargo,Install Rust: https://rustup.rs)
	@cargo clippy --all-features -- -D warnings
	@echo "$(GREEN)✓ Clippy passed$(RESET)"

clippy: lint ## Alias for lint (clippy)

audit: ## Run cargo audit for CVEs
	@echo "$(BLUE)Running cargo audit...$(RESET)"
	$(call require_binary,cargo-audit,Install: cargo install cargo-audit)
	@cargo audit
	@echo "$(GREEN)✓ No vulnerabilities found$(RESET)"

deny: ## Run cargo deny checks
	@echo "$(BLUE)Running cargo deny...$(RESET)"
	$(call require_binary,cargo-deny,Install: cargo install cargo-deny)
	@cargo deny check
	@echo "$(GREEN)✓ Deny checks passed$(RESET)"

vet: ## Run cargo vet (supply chain security)
	@echo "$(BLUE)Running cargo vet...$(RESET)"
	$(call require_binary,cargo-vet,Install: cargo install cargo-vet)
	@cargo vet
	@echo "$(GREEN)✓ Vet checks passed$(RESET)"

fmt: ## Format code
	@echo "$(BLUE)Formatting code...$(RESET)"
	$(call require_binary,cargo,Install Rust: https://rustup.rs)
	@cargo fmt
	@echo "$(GREEN)✓ Code formatted$(RESET)"

fmt-check: ## Check code formatting
	@echo "$(BLUE)Checking code formatting...$(RESET)"
	$(call require_binary,cargo,Install Rust: https://rustup.rs)
	@cargo fmt --check
	@echo "$(GREEN)✓ Code formatting OK$(RESET)"

fuzz-quick: ## Quick corpus-only fuzz run (2 min per target)
	@echo "$(BLUE)Running quick fuzzing (2 min per target)...$(RESET)"
	$(call require_binary,cargo-fuzz,Install: cargo install cargo-fuzz)
	@cd fuzz && for target in $$(cargo fuzz list 2>/dev/null); do \
		echo "$(YELLOW)Fuzzing $$target...$(RESET)"; \
		cargo fuzz run $$target -- -max_total_time=120 -runs=0 || true; \
	done
	@echo "$(GREEN)✓ Quick fuzzing completed$(RESET)"

fuzz-deep: ## Deep fuzzing (30 min per target)
	@echo "$(BLUE)Running deep fuzzing (30 min per target)...$(RESET)"
	$(call require_binary,cargo-fuzz,Install: cargo install cargo-fuzz)
	@cd fuzz && for target in $$(cargo fuzz list 2>/dev/null); do \
		echo "$(YELLOW)Fuzzing $$target...$(RESET)"; \
		cargo fuzz run $$target -- -max_total_time=1800 || true; \
	done
	@echo "$(GREEN)✓ Deep fuzzing completed$(RESET)"

sbom: ## Generate SBOM to dist/
	@echo "$(BLUE)Generating SBOM...$(RESET)"
	$(call require_binary,cargo-sbom,Install: cargo install cargo-sbom)
	@mkdir -p dist
	@cargo sbom --output-format cyclonedx_json_1_4 > dist/cachekit-core-sbom.json 2>/dev/null || \
		cargo sbom > dist/cachekit-core-sbom.json
	@echo "$(GREEN)✓ SBOM generated: dist/cachekit-core-sbom.json$(RESET)"

clean: ## Clean build artifacts
	@echo "$(BLUE)Cleaning build artifacts...$(RESET)"
	$(call require_binary,cargo,Install Rust: https://rustup.rs)
	@cargo clean
	@rm -rf dist/
	@echo "$(GREEN)✓ Cleaned$(RESET)"
