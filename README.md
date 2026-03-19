# `vr-verifier`

Standalone public verifier for VertRule receipt envelopes.

This crate verifies receipt structure, digest integrity, chain linkage, and
signatures without importing the private runtime crates that produce receipts.

## Scope

`vr-verifier` is for **verification only**. It does not mint receipts, sign
receipts, execute governed workloads, or require trust in `vertrule-runtime`.

## Verification Surface

The verifier checks:

- Envelope version compatibility
- Schema/profile conformance for the public envelope
- JCS canonicalization (RFC 8785)
- `event_hash` recomputation with BLAKE3
- Chain parent linkage through `parent_id`
- Monotonic `logical_time`
- Uniform `context_digest` across a chain
- Stable `policy_digest` across a chain
- Ed25519 signature verification (domain-separated)
- Deterministic result emission as canonical JSON

## CLI

```bash
# Verify a single receipt
vr-verify receipt examples/sample_receipt.json

# Verify a receipt chain
vr-verify chain examples/sample_chain.json

```

Exit codes: `0` = VALID, `1` = INVALID, `2` = ERROR.

Output: canonical JSON verification result to stdout, result digest to stderr.

## Build

```bash
cargo build --release
cargo test
cargo clippy -- -D warnings
```

## Examples

The `examples/` directory contains:

| File | Purpose |
|------|---------|
| `sample_receipt.json` | Valid single receipt envelope (governance type) |
| `sample_chain.json` | Valid 3-envelope chain with parent linkage |
| `tampered_receipt.json` | Receipt with flipped event_hash bit (should fail) |

Try it:

```bash
# Should exit 0 with status VALID
./target/release/vr-verify receipt examples/sample_receipt.json

# Should exit 1 with status INVALID
./target/release/vr-verify receipt examples/tampered_receipt.json
```

## Public Contract

The verifier operates on the `ReceiptEnvelope` shape defined by `vertrule-schemas`:

- `envelope_version`, `receipt_type`, `context_digest`, `schema_digest`
- `policy_digest`, `logical_time`, `event_hash`, `parent_id`
- `boundary_origin`, `payload`

Domain-specific governed receipts live inside `payload`.

## Dependency Policy

Production dependencies: `vertrule-schemas` (includes JCS canonicalization),
`base64`, `blake3`, `ed25519-dalek`, `hex`, `serde`, `serde_json`, `thiserror`.

The verifier must not depend on the private runtime execution stack.

## Trust Model

An external reviewer can verify a receipt bundle without needing access to
the private execution runtime. That is the core publication goal.

## License

Apache-2.0
