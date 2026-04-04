//! Centralized JCS canonicalization boundary.
//!
//! All JCS operations in the verifier route through this module,
//! enforcing a two-path model:
//!
//! 1. **Admission** ([`admit_canonical_bytes`]): raw untrusted bytes
//!    are validated against the strict `vr-jcs` raw-byte API
//!    (duplicate-key rejection, I-JSON string/number validation)
//!    and compared byte-for-byte against their canonical form.
//!
//! 2. **Typed** ([`typed_canon_bytes`], [`typed_canon_string`]):
//!    pre-validated `serde_json::Value` objects are serialized to
//!    canonical form for digest computation, routed through the
//!    same strict API via a serialize→re-canonicalize round-trip.

use crate::error::VerifyError;

/// Verify that raw untrusted bytes are in JCS canonical form.
///
/// This is the admission gate for all external JSON entering the
/// verifier.  Uses [`vr_jcs::to_canon_bytes_from_slice`] for
/// parse-time admission control, then byte-compares the result
/// against the input.
///
/// # Errors
///
/// Returns [`VerifyError::MalformedJson`] for parse failures,
/// [`VerifyError::NonCanonical`] for canonicalization mismatches
/// or I-JSON constraint violations.
pub(crate) fn admit_canonical_bytes(raw: &[u8]) -> Result<(), VerifyError> {
    let canonical =
        vr_jcs::to_canon_bytes_from_slice(raw).map_err(|e| jcs_admission_error(&e))?;
    if raw != canonical.as_slice() {
        return Err(VerifyError::NonCanonical {
            reason: "input is not in JCS canonical form".to_string(),
        });
    }
    Ok(())
}

/// Canonicalize a pre-validated [`serde_json::Value`] to bytes.
///
/// For digest computation on verifier-constructed values.
/// Serializes to JSON, then re-canonicalizes through the strict
/// raw-byte API.
///
/// # Errors
///
/// Returns [`VerifyError::Canon`] on serialization or
/// canonicalization failure.
pub(crate) fn typed_canon_bytes(value: &serde_json::Value) -> Result<Vec<u8>, VerifyError> {
    let json_bytes =
        serde_json::to_vec(value).map_err(|e| VerifyError::Canon(format!("{e}")))?;
    vr_jcs::to_canon_bytes_from_slice(&json_bytes)
        .map_err(|e| VerifyError::Canon(format!("{e}")))
}

/// Canonicalize a pre-validated [`serde_json::Value`] to a string.
///
/// Same semantics as [`typed_canon_bytes`] but returns a [`String`].
///
/// # Errors
///
/// Returns [`VerifyError::Canon`] on serialization or
/// canonicalization failure.
pub(crate) fn typed_canon_string(value: &serde_json::Value) -> Result<String, VerifyError> {
    let json =
        serde_json::to_string(value).map_err(|e| VerifyError::Canon(format!("{e}")))?;
    vr_jcs::to_canon_string_from_str(&json).map_err(|e| VerifyError::Canon(format!("{e}")))
}

/// Map a JCS error from the admission path to the appropriate
/// [`VerifyError`] variant.
fn jcs_admission_error(e: &vr_jcs::JcsError) -> VerifyError {
    if matches!(e, vr_jcs::JcsError::Json(_)) {
        VerifyError::MalformedJson {
            reason: format!("{e}"),
        }
    } else {
        VerifyError::NonCanonical {
            reason: format!("{e}"),
        }
    }
}
