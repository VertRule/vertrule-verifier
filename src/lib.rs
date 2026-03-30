//! # `vertrule-verifier` -- Public `VertRule` Receipt Verifier
//!
//! This crate is the standalone, auditable verifier for `VertRule` receipt
//! envelopes. It supports envelope versions V1 (payload-only commitment) and
//! V2 (full-envelope commitment), both using BLAKE3 + JCS. It intentionally
//! carries **zero** runtime imports: it does not depend on `vertrule-core`,
//! `vertrule-app`, `vertrule-adapters`, or any other runtime crate.
//!
//! ## Dependencies
//!
//! Only minimal, well-audited crates:
//!
//! | Crate | Purpose |
//! |-------|---------|
//! | `vertrule-schemas` | Canonical types (constitutional nouns) |
//! | `vr-jcs` | JCS canonicalization (RFC 8785) |
//! | `blake3` | Cryptographic hashing |
//! | `serde` / `serde_json` | Deserialization |
//! | `hex` | Hex encoding |
//! | `ed25519-dalek` | Ed25519 signature verification |
//! | `base64` | Base64 encoding/decoding |
//! | `thiserror` | Error derivation |
//!
//! ## Verification
//!
//! Three levels of verification are provided:
//!
//! 1. **Per-envelope** -- [`verify_receipt`] checks schema profile, canonical
//!    form, envelope version, and `event_hash` integrity.
//! 2. **Chain** -- [`verify_receipt_chain`] additionally checks parent-id
//!    linkage, logical-time monotonicity, context/policy consistency, and
//!    duplicate detection.
//! 3. **Signed** -- [`verify_signed_receipt`] additionally verifies an Ed25519
//!    signature over the domain-separated receipt digest.

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(missing_docs)]

pub mod chain;
pub mod envelope;
pub mod error;
pub mod ingestion;
pub mod limits;
pub mod mri_profile;
pub mod result;
pub mod schema_profile;
pub mod signature;
pub mod trust;
pub mod verify;

#[cfg(feature = "wasm")]
pub mod wasm;

pub use chain::verify_chain;
pub use envelope::{validate_receipt_envelope_integrity, ReceiptEnvelope};
pub use error::VerifyError;
pub use limits::{LimitViolation, VerifierLimits};
pub use mri_profile::{validate_gradient_coupling_payload, validate_mri_batch_payload};
pub use trust::{
    AuthorityKey, AuthoritySet, Revocation, TrustPolicy, TrustStatus, TrustValidation,
};
pub use verify::{
    verify_receipt, verify_receipt_chain, verify_receipt_chain_with_limits,
    verify_receipt_with_limits, verify_signed_receipt, verify_signed_receipt_with_trust,
};

// Re-export types from vertrule-schemas for public API compatibility.
pub use vertrule_schemas::{DigestBytes, SchemaVersion};

#[cfg(test)]
mod test_support;

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
