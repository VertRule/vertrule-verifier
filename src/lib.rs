//! # `vr-verifier` -- Public `VertRule` Receipt Verifier
//!
//! This crate is the standalone, auditable verifier for `VertRule` governance
//! receipt envelopes. It intentionally carries **zero** runtime imports:
//! it does not depend on `vertrule-core`, `vertrule-app`, `vertrule-adapters`,
//! or any other runtime crate.
//!
//! ## Dependencies
//!
//! Only minimal, well-audited crates:
//!
//! | Crate | Purpose |
//! |-------|---------|
//! | `vertrule-schemas` | Canonical types (`DigestBytes`, etc.) |
//! | `vr-jcs` | RFC 8785 JSON Canonicalization |
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
pub mod result;
pub mod schema_profile;
pub mod signature;
pub mod verify;

pub use chain::verify_chain;
pub use envelope::ReceiptEnvelope;
pub use error::VerifyError;
pub use verify::{verify_receipt, verify_receipt_chain, verify_signed_receipt};

// Re-export types from vertrule-schemas for public API compatibility.
pub use vertrule_schemas::{DigestBytes, SchemaVersion};

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
