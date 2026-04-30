//! Receipt verification for RBH evidence.
//!
//! Structural verification at the host boundary before policy evaluation.
//! Pure, deterministic — no network, no wall-clock, no key discovery.
//! Trust anchors (authority sets, key epochs) are validated by policy
//! against values already sealed in Ĉ.
//!
//! Lifted from `vertrule-app::policy_substrate::rbh_verify`
//! (`CG-SP: RBH-VERIFY-LIFT-V1`, 2026-04-30) so that the post-mint public
//! trust surface is owned by the verifier crate. Pre-mint authorization
//! (`vr_app::validate_authorization_request`) remains in the policy
//! substrate.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use vertrule_schemas::{DigestBytes, ReceiptEnvelope, SchemaVersion};

/// Metadata extracted from a structurally verified external receipt.
///
/// Produced exclusively by [`verify_external_receipt`]. Fields are private
/// to prevent construction outside the causal verification pipeline.
/// Use accessor methods to read individual fields.
///
/// In tests, construct canonical receipt bytes and pass them through
/// [`verify_external_receipt`] — the same path production code takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedReceiptMetadata {
    context_digest: String,
    policy_digest: String,
    schema_digest: String,
    event_hash: String,
    receipt_type: String,
    logical_time: u64,
    boundary_origin: Option<String>,
    payload: serde_json::Value,
}

impl VerifiedReceiptMetadata {
    /// BLAKE3 digest of the originating execution context.
    #[must_use]
    pub fn context_digest(&self) -> &str {
        &self.context_digest
    }

    /// BLAKE3 digest of the policy pack active at evidence time.
    #[must_use]
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    /// BLAKE3 digest of the schema used.
    #[must_use]
    pub fn schema_digest(&self) -> &str {
        &self.schema_digest
    }

    /// BLAKE3 hash of the canonical payload.
    #[must_use]
    pub fn event_hash(&self) -> &str {
        &self.event_hash
    }

    /// Receipt type discriminator (e.g., "Governance").
    #[must_use]
    pub fn receipt_type(&self) -> &str {
        &self.receipt_type
    }

    /// Monotonic logical timestamp from the originating context.
    #[must_use]
    pub const fn logical_time(&self) -> u64 {
        self.logical_time
    }

    /// Boundary origin tag, if present.
    #[must_use]
    pub fn boundary_origin(&self) -> Option<&str> {
        self.boundary_origin.as_deref()
    }

    /// The receipt payload as structured JSON.
    #[must_use]
    pub const fn payload(&self) -> &serde_json::Value {
        &self.payload
    }
}

/// Errors from structural receipt verification.
#[derive(Debug, Error)]
pub enum ReceiptVerifyError {
    /// Failed to parse receipt bytes as JSON.
    #[error("receipt parse error: {0}")]
    ParseError(String),

    /// Envelope version is not supported.
    #[error("unsupported envelope version: {0}")]
    UnsupportedVersion(u32),

    /// Event hash does not match canonical payload.
    #[error("event hash mismatch: expected {expected}, actual {actual}")]
    EventHashMismatch {
        /// Declared event hash.
        expected: String,
        /// Recomputed event hash.
        actual: String,
    },
}

/// Verify the supported receipt-envelope version.
fn verify_envelope_version(envelope: &ReceiptEnvelope) -> Result<(), ReceiptVerifyError> {
    if envelope.envelope_version == SchemaVersion::V1 {
        Ok(())
    } else {
        Err(ReceiptVerifyError::UnsupportedVersion(
            envelope.envelope_version.get(),
        ))
    }
}

/// Verify the payload digest declared in the receipt envelope.
fn verify_event_hash(envelope: &ReceiptEnvelope) -> Result<(), ReceiptVerifyError> {
    let json_bytes = serde_json::to_vec(&envelope.payload)
        .map_err(|e| ReceiptVerifyError::ParseError(e.to_string()))?;
    let canon_bytes = vr_jcs::to_canon_bytes_from_slice(&json_bytes)
        .map_err(|e| ReceiptVerifyError::ParseError(e.to_string()))?;
    let computed = blake3::hash(&canon_bytes);
    let actual = DigestBytes::from_array(*computed.as_bytes());

    if actual == envelope.event_hash {
        Ok(())
    } else {
        Err(ReceiptVerifyError::EventHashMismatch {
            expected: envelope.event_hash.to_hex(),
            actual: actual.to_hex(),
        })
    }
}

/// Structurally verify an external receipt and extract metadata.
///
/// Called at host boundary before policy evaluation.
/// No network calls. No time-based checks. No key discovery.
/// Trust anchors (authority sets, key epochs) are validated by
/// policy against values already sealed in Ĉ.
///
/// Performs:
/// 1. Parse receipt bytes → [`ReceiptEnvelope`]
/// 2. Verify the supported envelope version
/// 3. Verify `BLAKE3(JCS(payload))` against the declared `event_hash`
/// 4. Extract all metadata fields
///
/// [`ReceiptEnvelope`]: vertrule_schemas::ReceiptEnvelope
///
/// # Errors
///
/// Returns [`ReceiptVerifyError`] on parse failure, version mismatch,
/// or event hash mismatch.
pub fn verify_external_receipt(
    receipt_bytes: &[u8],
) -> Result<VerifiedReceiptMetadata, ReceiptVerifyError> {
    let envelope: ReceiptEnvelope = serde_json::from_slice(receipt_bytes)
        .map_err(|e| ReceiptVerifyError::ParseError(e.to_string()))?;

    verify_envelope_version(&envelope)?;

    verify_event_hash(&envelope)?;

    Ok(VerifiedReceiptMetadata {
        context_digest: envelope.context_digest.to_hex(),
        policy_digest: envelope.policy_digest.to_hex(),
        schema_digest: envelope.schema_digest.to_hex(),
        event_hash: envelope.event_hash.to_hex(),
        receipt_type: format!("{:?}", envelope.receipt_type),
        logical_time: envelope.logical_time.into(),
        boundary_origin: envelope.boundary_origin.map(|bo| format!("{bo:?}")),
        payload: envelope.payload.into_value(),
    })
}

#[cfg(test)]
#[path = "rbh_tests.rs"]
mod tests;
