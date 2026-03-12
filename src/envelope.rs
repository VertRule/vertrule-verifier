//! Schema-owned receipt envelope type plus verifier-owned checks.
//!
//! The public receipt envelope nouns live in `vertrule-schemas`.
//! This module keeps only the verifier behavior that operates on that type.

use vertrule_schemas::common::algorithms::{CANONICALIZATION, DIGEST_ALGORITHM};

use crate::error::VerifyError;

pub use vertrule_schemas::ReceiptEnvelope;

/// Verify that `event_hash` matches the BLAKE3 digest of the JCS-canonical
/// payload.
///
/// # Errors
///
/// Returns [`VerifyError::EventHashMismatch`] when the recomputed hash
/// does not equal the declared `event_hash`, or [`VerifyError::Canon`] if
/// canonicalization fails.
pub fn verify_event_hash(envelope: &ReceiptEnvelope) -> Result<(), VerifyError> {
    let canon_bytes = vr_jcs::to_canon_bytes(&envelope.payload)
        .map_err(|e| VerifyError::Canon(format!("{e}")))?;

    let computed = blake3::hash(&canon_bytes);
    let computed_digest = vertrule_schemas::DigestBytes::from_array(*computed.as_bytes());

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
    if envelope.envelope_version == vertrule_schemas::SchemaVersion::V1 {
        Ok(())
    } else {
        Err(VerifyError::UnsupportedVersion {
            version: envelope.envelope_version.get(),
        })
    }
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
    if let Some(ref declared) = envelope.digest_algorithm {
        if declared != DIGEST_ALGORITHM {
            return Err(VerifyError::DigestAlgorithmMismatch {
                declared: declared.clone(),
                expected: DIGEST_ALGORITHM.to_string(),
            });
        }
    }
    if let Some(ref declared) = envelope.canonicalization {
        if declared != CANONICALIZATION {
            return Err(VerifyError::CanonicalizationMismatch {
                declared: declared.clone(),
                expected: CANONICALIZATION.to_string(),
            });
        }
    }
    Ok(())
}
