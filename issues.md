# vr-verifier: Code Review Issues

Identified 2026-03-19 via adversarial code review.

## Issue 1: `SignatureBundle` missing `deny_unknown_fields`

**Severity**: Medium
**Files**: `src/signature.rs`

`SignatureBundle` uses `#[derive(Deserialize)]` without `#[serde(deny_unknown_fields)]`.
The envelope gets dual-layer unknown field protection (schema profile + serde),
but the signature bundle does not. An attacker could inject extra fields into a
signature bundle JSON and the verifier would silently accept them. Inconsistent
with the fail-closed philosophy applied to envelopes.

**Fix**: Add `#[serde(deny_unknown_fields)]` to `SignatureBundle`.

## Issue 2: No `schema_digest` chain consistency check

**Severity**: Medium
**Files**: `src/chain.rs`, `src/error.rs`

Chain verification checks `context_digest` and `policy_digest` consistency but
not `schema_digest`. If the verifier enforces that all envelopes in a chain
share the same context and policy, the same argument applies to schema.

**Fix**: Add `schema_digest` uniformity check in `check_chain_detail`, add
`SchemaInconsistent` error variant, add corresponding test and test vector.

## Issue 3: Empty chain indistinguishable from single-receipt result

**Severity**: Low
**Files**: `src/verify.rs`

Empty chain `[]` returns a result without `chain_validation`, making it
indistinguishable from a single-receipt result. A consumer cannot tell from the
result whether they passed a chain or a single envelope.

**Fix**: Return `chain_validation: Some(ChainValidation { length: 0, ... })`
for empty chains in `verify_receipt_chain`.

---

## Architecture Decision: WASM Enablement (2026-03-20)

### Decision

**Option A: compile `vr-verifier` directly to WASM** with a `wasm` feature gate
for `wasm-bindgen` exports.

### Options evaluated

| Option | Description | Verdict |
|--------|-------------|---------|
| A | Compile library directly to `wasm32-unknown-unknown` | **Chosen** |
| B | Extract a WASM-safe core crate | Unnecessary — library is already IO-free |
| C | Create a separate `vertrule-verifier-wasm` wrapper crate | Adds indirection with no benefit |

### Rationale

The library code contains zero platform-sensitive imports. All filesystem,
environment, and process access is confined to `src/bin/vr_verify.rs` (the CLI
binary), which is excluded from `--lib` builds. All dependencies (`blake3`,
`ed25519-dalek`, `serde_json`, `hex`, `base64`, `thiserror`, `vertrule-schemas`)
compile for `wasm32-unknown-unknown` without modification.

No code extraction or restructuring was needed. The verification boundary
(`&[u8] -> VerificationResult`) was already WASM-safe.

### WASM API surface

Exported via `#[wasm_bindgen]` behind `feature = "wasm"`:

| Function | Signature | Purpose |
|----------|-----------|---------|
| `verify_receipt_json` | `(receipt_json: &str) -> String` | Verify single envelope |
| `verify_chain_json` | `(chain_json: &str) -> String` | Verify receipt chain |
| `verify_signed_receipt_json` | `(receipt_json: &str, sig_json: &str) -> String` | Verify signed envelope |
| `digest_hex` | `(input: &[u8]) -> String` | BLAKE3 digest as hex |
| `verifier_version` | `() -> String` | Schema profile version |

All verification functions return JCS-canonical JSON of `VerificationResult`.
They never throw — malformed input produces `{"status":"INVALID",...}`.

### Result taxonomy

The `VerificationResult` structure provides machine-readable failure
classification:

- `status`: `"VALID"` or `"INVALID"`
- `digest_validation.all_hashes_match`: false on digest mismatch
- `digest_validation.chain_integrity`: false on broken chain linkage
- `digest_validation.ordering_valid`: false on non-monotonic logical time
- `signature_validation.present`: false if no signature material
- `signature_validation.valid`: false on signature verification failure
- `context_consistency.uniform_context`: false on context drift
- `policy_consistency.stable_policy`: false on policy drift
- `schema_consistency.uniform_schema`: false on schema drift
- `errors[]`: structured error messages

All result types derive both `Serialize` and `Deserialize` for round-trip use.

### Build commands

```bash
# Check WASM compilation
cargo check --lib --features wasm --target wasm32-unknown-unknown

# Build .wasm binary
cargo build --lib --features wasm --target wasm32-unknown-unknown --release

# Run WASM module tests (native runner)
cargo test --features wasm

# Clippy (WASM target)
cargo clippy --lib --features wasm --target wasm32-unknown-unknown -- -D warnings

# Clippy (native, all targets)
cargo clippy --all-targets --features wasm -- -D warnings
```

Output: `target/wasm32-unknown-unknown/release/vr_verifier.wasm` (~446 KB)

For browser use, run `wasm-bindgen` or `wasm-pack` over this artifact to
generate JS/TS bindings.

### What remains native-only

- `src/bin/vr_verify.rs` (CLI binary) — uses `std::fs`, `std::env`, `std::process`
- Integration tests that read fixture files from disk

### Blockers: none

All dependencies compile for WASM. No code changes were required to the
verification logic. The `wasm` feature gate adds `wasm-bindgen` as an optional
dependency and conditionally compiles `src/wasm.rs`.

### Risk assessment

- **Semantic drift**: Zero risk. WASM exports call the same `verify_receipt`,
  `verify_receipt_chain`, `verify_signed_receipt` functions as the CLI.
- **Determinism**: Preserved. No environment-dependent code paths. Same inputs
  produce same outputs across native and WASM.
- **Binary size**: 446 KB release WASM. Acceptable for browser use.
- **Feature isolation**: The `wasm` feature only adds the thin export module.
  Default builds are unchanged.

### Next integration step for `vertrule-website`

1. Run `wasm-pack build --target web --features wasm` (or use `wasm-bindgen-cli`
   directly on the `.wasm` artifact)
2. Import the generated JS module in the website's `/verify/` page
3. Call `verify_receipt_json(inputString)` and parse the JSON result
4. Render the structured `VerificationResult` in the UI
