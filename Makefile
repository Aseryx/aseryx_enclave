CARGO ?= cargo

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
