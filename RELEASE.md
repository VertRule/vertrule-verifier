# vertrule-verifier v0.1.0 Release Notes

Standalone public verifier for VertRule receipt envelopes. Zero runtime
dependencies — does not import the private execution stack.

## What ships

- Single-receipt verification: `verify_receipt`, `verify_receipt_with_limits`
- Chain verification: `verify_receipt_chain`, `verify_receipt_chain_with_limits`
- Signed verification: `verify_signed_receipt`, `verify_signed_receipt_with_trust`
- Envelope integrity: `validate_receipt_envelope_integrity` (re-homed
  from `vertrule-schemas`)
- MRI payload validation: `validate_mri_batch_payload`,
  `validate_gradient_coupling_payload`
- Authority-set trust evaluation
- CLI: `vr-verify receipt|chain|signed`
- JCS-canonical deterministic result output with BLAKE3 result digest

## Key decisions

- **V1 only**: full-envelope commitment
  (`BLAKE3(JCS(envelope \ {event_hash}))`) covering all trust-bearing fields.
- **Direct `vr-jcs` dependency**: canonicalization imported from `vr-jcs`
  directly, not through `vertrule-schemas`.
- **`signature_validation.present` semantics**: indicates whether a
  signature bundle was supplied, regardless of parse success. Malformed
  bundles count as present; validity is separate from presence.
- **`validate_receipt_envelope_integrity` re-homed**: integrity judgment
  moved from `ReceiptEnvelope::validate_integrity` (schemas) to a free
  function in the verifier, enforcing the nouns/procedures boundary.

## Dependencies

| Crate | Purpose |
|-------|---------|
| `vertrule-schemas` | Canonical types (constitutional nouns) |
| `vr-jcs` | JCS canonicalization (RFC 8785) |
| `blake3` | Cryptographic hashing |
| `ed25519-dalek` | Ed25519 signature verification |
