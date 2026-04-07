# vertrule-verifier local validation targets

# Build in release mode
build:
    cargo build --release

# Run all tests
test:
    cargo test

# Run tests with WASM feature
test-wasm:
    cargo test --features wasm

# Run clippy with deny warnings
clippy:
    cargo clippy --all-targets -- -D warnings

# Lint (alias for clippy)
lint: clippy

# Format check (does not modify files)
fmt-check:
    cargo fmt -- --check

# Auto-format
fmt:
    cargo fmt

# Full local check: build + test + clippy + format
check: build test clippy fmt-check

# Regenerate protocol test vectors
vectors:
    cargo run --example generate_test_vectors

# Run local CI gate and update badge
local-ci:
    #!/usr/bin/env bash
    set -euo pipefail
    if just verify-local; then
        tooling/gen-badge.sh passing artifacts/local-ci-badge.svg
        echo "Local CI: PASSING"
    else
        tooling/gen-badge.sh failing artifacts/local-ci-badge.svg
        echo "Local CI: FAILING" >&2
        exit 1
    fi

# Full release verification sequence
verify-local: check vectors test test-wasm
    @echo "Local verification complete."
