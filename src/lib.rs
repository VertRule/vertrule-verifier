//! # `vertrule-verifier` -- Public `VertRule` Receipt Verifier
//!
//! This crate is the standalone, auditable verifier for `VertRule` receipt
//! envelopes. It verifies full-envelope commitment (BLAKE3 + JCS). It intentionally
//! carries **zero** runtime imports: it does not depend on `vertrule-core`,
//! `vertrule-app`, `vertrule-adapters`, or any other runtime crate.
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

pub mod bundle;
pub(crate) mod canon;
pub(crate) mod canonical_identity;
pub mod chain;
pub mod closure_bundle;
pub mod decision_pack;
pub mod envelope;
pub mod error;
pub mod identity;
pub mod ingestion;
pub mod layered_pack;
pub mod limits;
pub mod mri_profile;
pub mod rbh;
pub mod result;
pub mod schema_profile;
pub mod signature;
pub mod trust;
pub mod verify;

#[cfg(feature = "wasm")]
pub mod wasm;

pub use bundle::{verify_bundle, BundleVerificationResult, SidecarDigestCheck};
pub use chain::verify_chain;
pub use closure_bundle::{verify_closure_bundle, ClosureBundleVerificationResult};
pub use decision_pack::{
    verify_decision_pack, DecisionPackVerificationResult, MemberStatus, SupportMemberCheck,
};
pub use envelope::{validate_receipt_envelope_integrity, ReceiptEnvelope};
pub use error::VerifyError;
pub use layered_pack::{verify_layered_pack, EdgeCheck, EdgeStatus, LayeredPackVerificationResult};
pub use limits::{LimitViolation, VerifierLimits};
pub use mri_profile::{validate_gradient_coupling_payload, validate_mri_batch_payload};
pub use rbh::{verify_external_receipt, ReceiptVerifyError, VerifiedReceiptMetadata};
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
