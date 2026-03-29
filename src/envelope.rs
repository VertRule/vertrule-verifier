//! Schema-owned receipt envelope type plus verifier-owned checks.
//!
//! The public receipt envelope nouns live in `vertrule-schemas`.
//! This module keeps only the verifier behavior that operates on that type.

use crate::error::VerifyError;

pub use vertrule_schemas::ReceiptEnvelope;

/// Verify that `event_hash` matches the commitment for this envelope's
/// schema version.
///
/// - **V1**: `event_hash` = `BLAKE3(JCS(payload))`
/// - **V2**: `event_hash` = `BLAKE3(JCS(envelope \ {event_hash}))`
///
/// # Errors
///
/// Returns [`VerifyError::EventHashMismatch`] when the recomputed hash
/// does not equal the declared `event_hash`, or [`VerifyError::Canon`] if
/// canonicalization fails.
pub fn verify_event_hash(envelope: &ReceiptEnvelope) -> Result<(), VerifyError> {
    let computed_digest = vertrule_schemas::receipts::compute_event_hash(envelope)
        .map_err(|e| VerifyError::Canon(format!("{e}")))?;

    if computed_digest == envelope.event_hash {
        Ok(())
    } else {
        Err(VerifyError::EventHashMismatch {
            expected: envelope.event_hash,
            actual: computed_digest,
        })
    }
}

/// Verify that `envelope_version` is in the supported set.
///
/// # Errors
///
/// Returns [`VerifyError::UnsupportedVersion`] when the version is not
/// recognised.
pub fn verify_envelope_version(envelope: &ReceiptEnvelope) -> Result<(), VerifyError> {
    let v = envelope.envelope_version;
    if v == vertrule_schemas::SchemaVersion::V1 || v == vertrule_schemas::SchemaVersion::V2 {
        Ok(())
    } else {
        Err(VerifyError::UnsupportedVersion { version: v.get() })
    }
}

/// Validate the structural integrity of a receipt envelope.
///
/// Checks:
/// 1. Algorithm markers (if present) match the version's identity triple
/// 2. `event_hash` matches the recomputed commitment for this version
///
/// Re-homed from `ReceiptEnvelope::validate_integrity` in `vertrule-schemas`
/// to enforce the nouns/procedures boundary: schemas owns the data shape,
/// the verifier owns judgment.
///
/// # Errors
///
/// Returns [`VerifyError::DigestAlgorithmMismatch`] or
/// [`VerifyError::CanonicalizationMismatch`] if markers conflict, or
/// [`VerifyError::EventHashMismatch`] if `event_hash` does not match.
pub fn validate_receipt_envelope_integrity(envelope: &ReceiptEnvelope) -> Result<(), VerifyError> {
    verify_algorithms(envelope)?;
    verify_event_hash(envelope)?;
    Ok(())
}

/// Verify that declared algorithms (if present) match the spec version's
/// identity triple.
///
/// For v1 envelopes, absent fields imply `"BLAKE3"` and `"JCS"`.
/// If present, they must match exactly.
///
/// # Errors
///
/// Returns [`VerifyError::DigestAlgorithmMismatch`] or
/// [`VerifyError::CanonicalizationMismatch`] on mismatch.
pub fn verify_algorithms(envelope: &ReceiptEnvelope) -> Result<(), VerifyError> {
    let expected_algo = envelope.envelope_version.digest_algorithm();
    let expected_canon = envelope.envelope_version.canonicalization();

    if let Some(ref declared) = envelope.digest_algorithm {
        if declared != expected_algo {
            return Err(VerifyError::DigestAlgorithmMismatch {
                declared: declared.clone(),
                expected: expected_algo.to_string(),
            });
        }
    }
    if let Some(ref declared) = envelope.canonicalization {
        if declared != expected_canon {
            return Err(VerifyError::CanonicalizationMismatch {
                declared: declared.clone(),
                expected: expected_canon.to_string(),
            });
        }
    }
    Ok(())
}
