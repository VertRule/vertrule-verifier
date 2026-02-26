//! Standalone receipt envelope type and per-envelope verification.
//!
//! [`ReceiptEnvelope`] mirrors the runtime's `UnifiedReceiptEnvelope` but is
//! owned entirely by this crate, keeping the verifier free of runtime imports.
//! Digest fields use [`DigestBytes`] from `vr-definitions`.

use serde::Deserialize;

use vr_definitions::DigestBytes;

use crate::error::VerifyError;

/// The only currently supported envelope version.
const SUPPORTED_VERSION: u32 = 1;

/// A self-contained receipt envelope for verification.
///
/// All digest fields are validated [`DigestBytes`] values: exactly 32 bytes
/// representing a BLAKE3 hash (serialized as 64 lowercase hex characters).
#[derive(Debug, Clone, Deserialize)]
pub struct ReceiptEnvelope {
    /// Envelope schema version. Currently only `1` is accepted.
    pub envelope_version: u32,

    /// Free-form receipt type tag (e.g. `"governance"`).
    pub receipt_type: String,

    /// BLAKE3 digest of the governance context.
    pub context_digest: DigestBytes,

    /// BLAKE3 digest of the schema used.
    pub schema_digest: DigestBytes,

    /// BLAKE3 digest of the policy in effect.
    pub policy_digest: DigestBytes,

    /// Monotonically increasing logical clock value.
    pub logical_time: u64,

    /// BLAKE3 hash of the canonicalized payload.
    pub event_hash: DigestBytes,

    /// Hash of the previous envelope in the chain, or `None` for the first.
    pub parent_id: Option<DigestBytes>,

    /// Optional boundary origin tag.
    pub boundary_origin: Option<String>,

    /// Arbitrary domain payload whose canonical form produces `event_hash`.
    pub payload: serde_json::Value,
}

impl ReceiptEnvelope {
    /// Verify that `event_hash` matches the BLAKE3 digest of the JCS-canonical
    /// payload.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::EventHashMismatch`] when the recomputed hash
    /// does not equal the declared `event_hash`, or [`VerifyError::Canon`] if
    /// canonicalization fails.
    pub fn verify_event_hash(&self) -> Result<(), VerifyError> {
        let canon_bytes = vr_jcs::to_canon_bytes(&self.payload)
            .map_err(|e| VerifyError::Canon(format!("{e}")))?;

        let computed = blake3::hash(&canon_bytes);
        let computed_digest = DigestBytes::from_array(*computed.as_bytes());

        if computed_digest == self.event_hash {
            Ok(())
        } else {
            Err(VerifyError::EventHashMismatch {
                expected: self.event_hash,
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
    pub const fn verify_envelope_version(&self) -> Result<(), VerifyError> {
        if self.envelope_version == SUPPORTED_VERSION {
            Ok(())
        } else {
            Err(VerifyError::UnsupportedVersion {
                version: self.envelope_version,
            })
        }
    }
}
