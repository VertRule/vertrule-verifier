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
use vr_receipt_identity::compute_event_hash;
use vertrule_schemas::{EventHashProfileId, ReceiptEnvelope, ReceiptType, SchemaVersion};

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

    /// Event hash does not match the recomputed digest for its profile.
    #[error("event hash mismatch: expected {expected}, actual {actual}")]
    EventHashMismatch {
        /// Declared event hash.
        expected: String,
        /// Recomputed event hash.
        actual: String,
    },

    /// A multi-law `receipt_type` carries no `event_hash_profile`
    /// discriminator; the digest law cannot be resolved and is never inferred.
    #[error(
        "event_hash law ambiguous: receipt_type {receipt_type} is multi-law \
         and declares no event_hash_profile"
    )]
    EventHashLawAmbiguous {
        /// The multi-law receipt type that lacked a discriminator.
        receipt_type: String,
    },

    /// The declared profile is not verifiable by envelope-only RBH (its
    /// identity binds an out-of-band input set, not the envelope bytes).
    #[error("event_hash profile {profile} is not verifiable by envelope-only RBH")]
    ProfileNotEnvelopeVerifiable {
        /// The profile requiring bound-input (out-of-band) verification.
        profile: String,
    },

    /// Envelope-commitment canonicalization failed.
    #[error("envelope commitment failed: {0}")]
    CommitmentError(String),
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

/// The verification law for an envelope's `event_hash`, resolved from its
/// profile (ADR-029 §3 / ADR-028R).
enum EventHashLaw {
    /// `constitutional_envelope_v1`: recompute `BLAKE3(JCS(envelope \ {event_hash}))`.
    EnvelopeMinus,
    /// `runtime_port_event_preimage_v1`: a typed-preimage identity that
    /// envelope-only RBH cannot recompute from the envelope bytes
    /// (ADR-016 / DEC-3 — the preimage binds the runtime-port input set).
    RuntimePortPreimage,
}

/// `event` is the only multi-law `receipt_type` today (ADR-029): its
/// `event_hash` may be either constitutional self-commitment or a `RuntimePort`
/// typed preimage, so it requires an explicit discriminator.
const fn is_multi_law(receipt_type: ReceiptType) -> bool {
    matches!(receipt_type, ReceiptType::Event)
}

/// Resolve the digest-law profile for an envelope's `event_hash`.
///
/// Field-driven, never inferred (ADR-029 §3): the `event_hash_profile`
/// discriminator selects the law. A multi-law `receipt_type` (`event`) with no
/// discriminator is a hard reject. A single-law `receipt_type` without a
/// discriminator resolves to the constitutional self-commitment law (the
/// canonical law `vertrule-schemas` emits); it is **never** payload-only.
fn resolve_profile(envelope: &ReceiptEnvelope) -> Result<EventHashLaw, ReceiptVerifyError> {
    match envelope.event_hash_profile {
        Some(EventHashProfileId::ConstitutionalEnvelopeV1) => Ok(EventHashLaw::EnvelopeMinus),
        Some(EventHashProfileId::RuntimePortEventPreimageV1) => {
            Ok(EventHashLaw::RuntimePortPreimage)
        }
        None if is_multi_law(envelope.receipt_type) => {
            Err(ReceiptVerifyError::EventHashLawAmbiguous {
                receipt_type: format!("{:?}", envelope.receipt_type),
            })
        }
        None => Ok(EventHashLaw::EnvelopeMinus),
    }
}

/// Verify the declared `event_hash` under its resolved digest-law profile.
///
/// - `constitutional_envelope_v1` → recompute
///   `BLAKE3(JCS(envelope \ {event_hash}))` via the canonical schemas
///   constructor [`compute_event_hash`] and compare.
/// - `runtime_port_event_preimage_v1` → not recomputable from the envelope
///   alone; envelope-only RBH refuses rather than recompute under the wrong
///   law. Payload-only recomputation is **never** used on a public surface.
fn verify_event_hash(envelope: &ReceiptEnvelope) -> Result<(), ReceiptVerifyError> {
    match resolve_profile(envelope)? {
        EventHashLaw::EnvelopeMinus => {
            let recomputed = compute_event_hash(envelope)
                .map_err(|e| ReceiptVerifyError::CommitmentError(e.to_string()))?;
            if recomputed == envelope.event_hash {
                Ok(())
            } else {
                Err(ReceiptVerifyError::EventHashMismatch {
                    expected: envelope.event_hash.to_hex(),
                    actual: recomputed.to_hex(),
                })
            }
        }
        EventHashLaw::RuntimePortPreimage => {
            Err(ReceiptVerifyError::ProfileNotEnvelopeVerifiable {
                profile: "runtime_port_event_preimage_v1".to_string(),
            })
        }
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
/// 3. Resolve the `event_hash` law profile (ADR-029) and verify the declared
///    `event_hash`: envelope-minus recompute for `constitutional_envelope_v1`;
///    refuse `runtime_port_event_preimage_v1` as not envelope-verifiable;
///    reject a multi-law `event` receipt that declares no profile.
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
        logical_time: envelope.logical_time,
        boundary_origin: envelope.boundary_origin.map(|bo| format!("{bo:?}")),
        payload: envelope.payload.into_value(),
    })
}

#[cfg(test)]
#[path = "rbh_tests.rs"]
mod tests;
