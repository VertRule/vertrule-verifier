# .vr/ — Repository State Root

Canonical repo-local state directory for the `vertrule-verifier` repository.

Governed by Repo State Standard v1.

## Canonical Layout

```
.vr/
  README.md
  governance/
    bindings/
    overlays/
    exemptions/
    manifest.toml
    known-nondeterminism.toml
  capabilities/
  receipts/
    governance/
    capabilities/
    local/
  state/
  public/
  tmp/
```

## Invariants

1. Exactly one canonical state root: `.vr/`
2. Governance definitions and receipts are strictly separated.
3. No mutable operational files at `.vr/` root level.
4. All path resolution uses `.vr/` prefix, never bare `governance/`.

## Governance Status

| Property | Value |
|----------|-------|
| Governance tier | Verification layer (Layer 4) |
| Determinism stage | 0 — canonical |
| Receipt chain | Genesis — no governance receipts produced |
| Authority set | Development — keys derived from plaintext hashing, not managed custody |

### Active Policy Bindings

| Policy | Mode | Overlay |
|--------|------|---------|
| `determinism@0.1` | bind+overlay | `overlays/determinism@0.1.toml` (strict: `src/**/*.rs`, no exceptions) |
| `repo-boundary@0.1` | bind | No overlay needed |
| `receipt-canonicalization@0.1` | bind | No overlay needed |
| `numeric-safety@0.1` | bind+overlay | `overlays/numeric-safety@0.1.toml` (finiteness exception for `mri_profile.rs`) |

### Binding Resolution

Policy and authority-set bindings reference external governance infrastructure
by BLAKE3 digest rather than by file path. This means:

- The **digest** field in each binding is the BLAKE3 hash of the canonical
  source file (policy.toml or authority-set YAML) in the VertRule shared
  governance infrastructure.
- The **overlay** (if any) is bundled in this repository under
  `.vr/governance/overlays/` and is fully inspectable from a fresh clone.
- The digest is an **anchor**, not a self-contained proof. To verify the
  binding against source material, you need access to the governance
  infrastructure. Without it, the digest serves as a tamper-evident seal:
  if the policy changes, the digest will no longer match.

### What can be verified from a fresh clone

- Code builds and all tests pass: `cargo test`
- Test vector validation passes: `cargo test --test test_vector_validation`
- Determinism tests pass: `cargo test --test determinism_tests`
- `vr-verify` binary builds and runs: `cargo build --release`
- Example receipts verify: `cargo run --bin vr-verify -- receipt examples/sample_receipt.json`
- Example chain verifies: `cargo run --bin vr-verify -- chain examples/sample_chain.json`
- Policy binding digests in `manifest.toml` can be compared against known policy hashes
- `governance-profile-v1.json` defines the complete v1 verification profile
- No nondeterminism sources: `known-nondeterminism.toml` is empty

### What cannot be verified from a fresh clone

- No governance receipts exist to verify for this repository
  (chain-manifest.json is in genesis state)
- The example receipts in `examples/` are test fixtures for other crates
  (vertrule-schemas, vr-jcs, vr-time), not governance evidence for this repository
- Authority set binding references external governance infrastructure
  (the digest is committed but the source material is not bundled)
- No signature-backed governance evidence has been produced for this repository
- `GovernanceReceipt.schema.json` defines the target receipt shape but no conforming
  receipts exist in this repository
