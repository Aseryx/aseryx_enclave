CARGO ?= cargo

# The engine module browsers run and the appraisal-core fixtures, from the sibling checkouts. The engine tests fail
# when either is missing.
export ENCLAVE_ENGINE_WASM ?= $(abspath ../aseryx_application/client/vendor/appraisal-core/appraisal_core_wasm_bg.wasm)
export ENCLAVE_TABULAR_FIXTURES ?= $(abspath ../aseryx_zk_server/tests/fixtures/tabular_v12)

.PHONY: help fmt fmt-check clippy test doc check

help: ## List the targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*## /\t/'

fmt: ## Format Rust sources
	$(CARGO) fmt --all

fmt-check: ## Verify formatting
	$(CARGO) fmt --all --check

clippy: ## Lint with clippy, warnings as errors
	$(CARGO) clippy --workspace --all-targets --all-features --locked -- -D warnings

test: ## Run the tests
	$(CARGO) test --workspace --all-features --locked

doc: ## Build the docs, warnings as errors
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --no-deps --workspace --locked

check: fmt-check clippy test doc ## Run every gate
