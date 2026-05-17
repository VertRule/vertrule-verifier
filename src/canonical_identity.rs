//! Sealed canonical-identity plumbing for `vertrule-verifier`.
//!
//! `pub(crate)` only. Companion to [`crate::canon`]: where `canon`
//! returns raw canonical bytes / strings, this module returns
//! [`vr_jcs::CanonicalDigest`] values — i.e. canonical bytes already
//! hashed under a typed digest strategy, with algorithm-with-output
//! binding preserved (ADR-002).
//!
//! Two narrow conversion shapes:
//!
//! - [`digest_trusted_value`] — for `serde_json::Value` instances that
//!   came from typed verifier-side construction (e.g. serializing a
//!   `Bundle` to a Value before recomputing its identity).
//! - [`digest_untrusted_json`] — for raw bytes that arrived from
//!   outside the verifier crate. Routes through
//!   `vr_jcs::strict_parse::parse_json_value_no_duplicates` first so
//!   duplicate-key ambiguity is rejected before any digest computation.
//!
//! # Sealed-helper invariant (JCS Consumer Hardening Plan § Gate 2)
//!
//! - This crate MUST NOT expose generic `hash_json`-style public
//!   helpers. Public surfaces are domain-specific sealed digest
//!   newtypes.
//! - This crate SHOULD recompute schema-owned identities (receipt
//!   commitment, scope digest) through `vertrule-schemas` constructors
//!   rather than redefine them here.
//! - Verifier-specific identity (signature-input prefix digest,
//!   sidecar digest) is owned here behind sealed newtypes.

use vr_jcs::{to_canon_digest_with, CanonicalDigest, DigestStrategy};

use crate::error::VerifyError;

/// Digest a typed verifier-constructed `serde_json::Value`.
///
/// # Errors
///
/// Returns [`VerifyError::Canon`] on canonicalization or digest
/// failure.
#[allow(
    clippy::redundant_pub_crate,
    reason = "explicit pub(crate) documents the Gate 2 sealed-helper visibility intent"
)]
pub(crate) fn digest_trusted_value(
    value: &serde_json::Value,
    strategy: &DigestStrategy,
) -> Result<CanonicalDigest, VerifyError> {
    to_canon_digest_with(value, strategy).map_err(|e| VerifyError::Canon(format!("{e}")))
}

/// Digest raw JSON bytes that arrived from outside the verifier.
///
/// # Errors
///
/// Returns [`VerifyError::MalformedJson`] for parse failures (the
/// strict-admission path catches duplicate keys, I-JSON violations,
/// and depth-bound breaches). Returns [`VerifyError::Canon`] for
/// digest failures.
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    reason = "Plumbing scaffold for Gate 2; first call site lands as bypass migrations complete"
)]
pub(crate) fn digest_untrusted_json(
    json: &[u8],
    strategy: &DigestStrategy,
) -> Result<CanonicalDigest, VerifyError> {
    let value = vr_jcs::strict_parse::parse_json_value_no_duplicates(json).map_err(|e| {
        VerifyError::MalformedJson {
            reason: format!("{e}"),
        }
    })?;
    to_canon_digest_with(&value, strategy).map_err(|e| VerifyError::Canon(format!("{e}")))
}
