# vertrule-verifier Public Surface (v0.2)

Standalone public verifier for VertRule receipt envelopes.
Judgment over public artifacts — no receipt production, no signing,
no runtime execution.

## Supported Envelope Version

- **V1**: `event_hash` = `BLAKE3(JCS(envelope \ {event_hash}))` — full-envelope commitment

## Stable Root Exports

### Verification entry points

```rust
pub fn verify_receipt(raw_bytes: &[u8]) -> VerificationResult;
pub fn verify_receipt_with_limits(raw_bytes: &[u8], limits: &VerifierLimits) -> VerificationResult;
pub fn verify_receipt_chain(raw_bytes: &[u8]) -> VerificationResult;
pub fn verify_receipt_chain_with_limits(raw_bytes: &[u8], limits: &VerifierLimits) -> VerificationResult;
pub fn verify_signed_receipt(raw_bytes: &[u8], sig_bytes: &[u8]) -> VerificationResult;
pub fn verify_signed_receipt_with_trust(
    raw_bytes: &[u8], sig_bytes: &[u8],
    authority_set: &AuthoritySet, trust_policy: &TrustPolicy,
) -> VerificationResult;
pub fn verify_chain(envelopes: &[ReceiptEnvelope]) -> ChainDetail;
```

### Envelope integrity (re-homed from vertrule-schemas)

```rust
pub fn validate_receipt_envelope_integrity(
    envelope: &ReceiptEnvelope,
) -> Result<(), VerifyError>;
```

### MRI payload validation

```rust
pub fn validate_mri_batch_payload(payload: &MriBatchPayload) -> Result<(), VerifyError>;
pub fn validate_gradient_coupling_payload(payload: &GradientCouplingPayload) -> Result<(), VerifyError>;
```

### Error types

```rust
pub enum VerifyError { .. }
pub enum LimitViolation { .. }
```

### Limits

```rust
pub struct VerifierLimits { .. }
```

### Trust types

```rust
pub struct AuthorityKey { .. }
pub struct AuthoritySet { .. }
pub struct Revocation { .. }
pub struct TrustPolicy { .. }
pub struct TrustValidation { .. }
pub enum TrustStatus { .. }
```

### Re-exports from vertrule-schemas

```rust
pub use vertrule_schemas::{DigestBytes, SchemaVersion};
pub use envelope::ReceiptEnvelope;
```

### CLI

```
vr-verify receipt <file>
vr-verify chain <file>
vr-verify signed <receipt-file> <signature-file>
```

## Types available via submodule path (not root-exported)

```rust
vr_verifier::result::VerificationResult
vr_verifier::result::VerificationStatus
vr_verifier::result::DigestValidation
vr_verifier::result::ChainValidation
vr_verifier::result::ContextConsistency
vr_verifier::result::PolicyConsistency
vr_verifier::result::SchemaConsistency
vr_verifier::result::SignatureValidation
```

## Semantic Contracts

- `signature_validation.present`: whether a signature bundle was
  supplied, regardless of parse success. Malformed bundles count as
  present. Validity is separate from presence.
- Exit codes: `0` = VALID, `1` = INVALID, `2` = usage error.
- Output: JCS-canonical JSON to stdout, result digest to stderr.

## Dependencies

- `vertrule-schemas` for constitutional nouns
- `vr-jcs` for canonicalization (direct dependency)
- `blake3`, `ed25519-dalek` for cryptographic verification
