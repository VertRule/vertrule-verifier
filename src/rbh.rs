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

use serde_json::Value;
use thiserror::Error;
use vertrule_schemas::{EventHashProfileId, ReceiptEnvelope, ReceiptType, SchemaVersion};
use vr_receipt_identity::compute_event_hash;

/// The verified-receipt metadata carrier now lives in `vertrule-schemas`
/// (ADR-038 Phase 1), below both this crate and the policy substrate, so
/// the substrate can consume it without depending on the verifier. It is
/// re-exported here to preserve the `vertrule_verifier::VerifiedReceiptMetadata`
/// public path. Production construction still flows exclusively through
/// [`verify_external_receipt`].
pub use vertrule_schemas::VerifiedReceiptMetadata;

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

    /// A payload claims to be a decode-step receipt at a non-canonical schema
    /// version. Only `vr.operator_stream.decode_step@0.2` is a canonical decode
    /// claim (ADR-0006); `@0.1` is content-digest-only with no envelope identity.
    #[error("non-canonical decode-step schema: {schema} (only @0.2 is a canonical decode claim)")]
    NonCanonicalDecodeStep {
        /// The rejected decode-step schema string.
        schema: String,
    },

    /// A projection receipt omits a required source-binding field. A projection
    /// (H0–H3 / browser) must bind all five fields (ADR-0006); a missing one is
    /// not a valid canonical-decode citation.
    #[error("projection missing source binding: {field}")]
    ProjectionMissingSourceBinding {
        /// The absent binding field name.
        field: &'static str,
    },

    /// A projection's source-bound field disagrees with the cited canonical
    /// envelope. The projection cites a different receipt class, schema, or event
    /// than the envelope it claims to project (ADR-0006); fail closed.
    #[error("projection source mismatch on {field}: expected {expected}, actual {actual}")]
    ProjectionSourceMismatch {
        /// The binding field that disagreed.
        field: &'static str,
        /// The cited envelope's value.
        expected: String,
        /// The projection's declared value.
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

/// Canonical decode-step payload schema (ADR-0006).
const CANONICAL_DECODE_STEP_SCHEMA: &str = "vr.operator_stream.decode_step@0.2";
/// Prefix shared by all decode-step payload schema versions.
const DECODE_STEP_SCHEMA_PREFIX: &str = "vr.operator_stream.decode_step@";

/// Reject a payload that claims to be a decode-step receipt at any version other
/// than the canonical `@0.2` (ADR-0006).
///
/// `@0.1` is content-digest-only with no envelope identity and is therefore not a
/// canonical decode claim. Payloads that carry no decode-step schema tag pass through
/// unaffected — this guard only fires when a payload asserts the decode-step schema.
fn verify_decode_step_schema(envelope: &ReceiptEnvelope) -> Result<(), ReceiptVerifyError> {
    let Some(schema) = envelope
        .payload
        .as_value()
        .get("schema")
        .and_then(serde_json::Value::as_str)
    else {
        return Ok(());
    };
    if schema.starts_with(DECODE_STEP_SCHEMA_PREFIX) && schema != CANONICAL_DECODE_STEP_SCHEMA {
        return Err(ReceiptVerifyError::NonCanonicalDecodeStep {
            schema: schema.to_string(),
        });
    }
    Ok(())
}

/// The five fields a projection must bind to its cited canonical envelope
/// (ADR-0006 *Projection commits to source*). The first three are bound to the
/// envelope and compared against it; the last two are projection-declared and
/// only asserted present.
const PROJECTION_SOURCE_FIELDS: [&str; 5] = [
    "source_receipt_type",
    "source_schema_version",
    "source_event_hash",
    "projection_law_id",
    "omitted_evidence_classes",
];

/// Assert a projection's source-bound field equals the cited envelope value.
///
/// Comparison is on the envelope's own serialized JSON string (e.g. `receipt_type`
/// `"llm"`, the payload `schema`, the `event_hash` hex), so it is
/// representation-consistent with what the projection author cited.
fn assert_projection_bind(
    projection: &Value,
    field: &'static str,
    expected: Option<&Value>,
) -> Result<(), ReceiptVerifyError> {
    let expected = expected.and_then(Value::as_str).unwrap_or_default();
    let actual = projection
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default();
    if actual == expected {
        Ok(())
    } else {
        Err(ReceiptVerifyError::ProjectionSourceMismatch {
            field,
            expected: expected.to_string(),
            actual: actual.to_string(),
        })
    }
}

/// Verify a projection receipt against the canonical decode-step envelope it cites.
///
/// A projection (H0–H3 `InferenceReceipt`, `BrowserDecodeStepReceipt`) carries no
/// authoritative event identity of its own (ADR-0006); its transport digest is
/// non-authoritative for decode semantics. It must bind **five** fields to its
/// source. Three of them — `source_receipt_type`, `source_schema_version`,
/// `source_event_hash` — are bound to the cited canonical envelope and must agree
/// with it; the other two (`projection_law_id`, `omitted_evidence_classes`) are
/// projection-declared and asserted present. The canonical envelope is verified in
/// full first via [`verify_external_receipt`], so a projection is never trusted
/// above an unverified source.
///
/// # Errors
///
/// Returns [`ReceiptVerifyError`] if the cited envelope fails verification, either
/// document fails to parse, any of the five binding fields is absent, or a
/// source-bound field disagrees with the cited envelope (fail-closed).
pub fn verify_projection_source(
    projection_bytes: &[u8],
    canonical_envelope_bytes: &[u8],
) -> Result<VerifiedReceiptMetadata, ReceiptVerifyError> {
    // The cited source must itself verify (event_hash law + decode-step schema).
    let meta = verify_external_receipt(canonical_envelope_bytes)?;

    let envelope: Value = serde_json::from_slice(canonical_envelope_bytes)
        .map_err(|e| ReceiptVerifyError::ParseError(e.to_string()))?;
    let projection: Value = serde_json::from_slice(projection_bytes)
        .map_err(|e| ReceiptVerifyError::ParseError(e.to_string()))?;

    for field in PROJECTION_SOURCE_FIELDS {
        if projection.get(field).is_none() {
            return Err(ReceiptVerifyError::ProjectionMissingSourceBinding { field });
        }
    }

    assert_projection_bind(
        &projection,
        "source_receipt_type",
        envelope.get("receipt_type"),
    )?;
    assert_projection_bind(
        &projection,
        "source_schema_version",
        envelope.get("payload").and_then(|p| p.get("schema")),
    )?;
    assert_projection_bind(&projection, "source_event_hash", envelope.get("event_hash"))?;

    Ok(meta)
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

    verify_decode_step_schema(&envelope)?;

    Ok(VerifiedReceiptMetadata::new(
        envelope.context_digest.to_hex(),
        envelope.policy_digest.to_hex(),
        envelope.schema_digest.to_hex(),
        envelope.event_hash.to_hex(),
        format!("{:?}", envelope.receipt_type),
        envelope.logical_time,
        envelope.boundary_origin.map(|bo| format!("{bo:?}")),
        envelope.payload.into_value(),
    ))
}

#[cfg(test)]
#[path = "rbh_tests.rs"]
mod tests;
