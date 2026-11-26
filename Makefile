CARGO ?= cargo

# The engine module browsers run (engine/) and the aseryx-engine goldens (harness/tests/tabular). The engine tests
# fail when either is missing.
export ENCLAVE_ENGINE_WASM ?= $(abspath engine/aseryx_engine_wasm_bg.wasm)
export ENCLAVE_CIRCUITS ?= $(abspath .cache/circuits)
export ENCLAVE_TABULAR_FIXTURES ?= $(abspath harness/tests/tabular)

.PHONY: help fmt fmt-check clippy circuits test doc policy-tests secrets check

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

secrets: ## Scan the working tree (tracked and untracked files that are not ignored) and the git history for secrets
	gitleaks git --no-banner --redact --config .gitleaks.toml .
	rm -rf target/secrets-scan && mkdir -p target/secrets-scan
	git ls-files --cached --others --exclude-standard -z | xargs -0 tar -cf - | tar -xf - -C target/secrets-scan
	cd target/secrets-scan && gitleaks dir --no-banner --redact --config ../../.gitleaks.toml .
	rm -rf target/secrets-scan

check: fmt-check clippy test doc policy-tests secrets ## Run every gate
