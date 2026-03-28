# vertrule-verifier local validation targets

# Build in release mode
build:
    cargo build --release

# Run all tests
test:
    cargo test

# Run clippy with deny warnings
clippy:
    cargo clippy --all-targets -- -D warnings

# Format check (does not modify files)
fmt-check:
    cargo fmt -- --check

# Full local check: build + test + clippy + format
check: build test clippy fmt-check

# Regenerate protocol test vectors
vectors:
    cargo run --example generate_test_vectors

# Full release verification sequence
verify-local: check vectors test
    @echo "Local verification complete."
