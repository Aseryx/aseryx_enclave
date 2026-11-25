CARGO ?= cargo

# The engine module browsers run (engine/) and the appraisal-core fixtures, from the sibling checkout. The engine tests
# fail when either is missing.
export ENCLAVE_ENGINE_WASM ?= $(abspath engine/appraisal_core_wasm_bg.wasm)
export ENCLAVE_CIRCUITS ?= $(abspath .cache/circuits)
export ENCLAVE_TABULAR_FIXTURES ?= $(abspath ../aseryx_zk_server/tests/fixtures/tabular_v12)

.PHONY: help fmt fmt-check clippy circuits test doc policy-tests check

help: ## List the targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*## /\t/'

fmt: ## Format Rust sources
	$(CARGO) fmt --all

fmt-check: ## Verify formatting
	$(CARGO) fmt --all --check

clippy: ## Lint with clippy, warnings as errors
	$(CARGO) clippy --workspace --all-targets --all-features --locked -- -D warnings

circuits: ## Download the pinned circuit artifacts
	./scripts/fetch-circuits.sh

test: circuits ## Run the tests
	$(CARGO) test --workspace --all-features --locked

doc: ## Build the docs, warnings as errors
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --no-deps --workspace --locked

policy-tests: ## Test the policy anchoring and the policy checker
	python3 -m unittest discover -s scripts -p 'test_*.py'
	python3 scripts/check-policy.py --self-test

check: fmt-check clippy test doc policy-tests ## Run every gate
