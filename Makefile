SHELL := /bin/bash

.PHONY: all env check-rust install-rust check-ddbug install-ddbug

all: env

env: check-rust check-ddbug

check-rust:
	@if ! command -v rustc >/dev/null 2>&1; then \
		echo "Rust not found — installing via rustup..."; \
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh; \
		echo "After install, run 'source $$HOME/.cargo/env' or restart your shell to have cargo in PATH."; \
	else \
		echo "Rust is installed: $$(rustc --version)"; \
	fi

check-ddbug:
	@if ! command -v ddbug >/dev/null 2>&1; then \
		if ! command -v cargo >/dev/null 2>&1; then \
			echo "cargo not found; ensure Rust is installed and cargo is in PATH"; exit 1; \
		fi; \
		echo "ddbug not found — installing from git..."; \
		cargo install --git https://github.com/gimli-rs/ddbug || true; \
	else \
		echo "ddbug is installed: $$(ddbug --version 2>/dev/null || echo '(version unknown)')"; \
	fi