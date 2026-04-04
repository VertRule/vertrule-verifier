//! Integration tests for the MRI batch-aware payload validation pipeline.
//!
//! Validates the two-step pattern:
//! 1. `verify_receipt` checks envelope integrity (opaque payload)
//! 2. Consumer parses `MriBatchPayload` and calls `validate_mri_batch_payload`

use serde_json::json;
use vertrule_schemas::{
    BatchReduction, BoundaryOrigin, CanonicalPayload, DigestBytes, IJsonUInt, MriBatchPayload,
    ReceiptEnvelope, ReceiptType, ReductionAxis, ReductionMode, ReductionProvenance, SchemaVersion,
    TokenReduction,
};
use vertrule_verifier::result::VerificationStatus;
use vertrule_verifier::{validate_mri_batch_payload, verify_receipt};

/// Typed canonicalization helper (non-deprecated round-trip).
fn canon_bytes(value: &impl serde::Serialize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let json = serde_json::to_vec(value)?;
    Ok(vr_jcs::to_canon_bytes_from_slice(&json)?)
}

fn sample_provenance() -> Result<ReductionProvenance, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(json!({
        "reduction_mode": ReductionMode::PerExampleThenMean,
        "reduced_axes": [
            ReductionAxis::Token,
            ReductionAxis::Hidden,
            ReductionAxis::Batch
        ],
        "token_reduction": TokenReduction::Mean,
        "batch_reduction": BatchReduction::Mean,
    }))?)
}

fn scalar_only() -> Result<MriBatchPayload, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(json!({
        "schema": "vr.mri.batch_invariant@0.1",
        "layer": 0,
        "q_scalar": 0x3F80_0000u32,
        "provenance": sample_provenance()?,
    }))?)
}

/// Build a valid `ReceiptEnvelope` from an `MriBatchPayload`.
fn envelope_from_batch_payload(
    payload: &MriBatchPayload,
) -> Result<ReceiptEnvelope, Box<dyn std::error::Error>> {
    let payload_value = serde_json::to_value(payload)?;
    let canonical = CanonicalPayload::new(payload_value)?;
    let zero = DigestBytes::from_array([0u8; 32]);
    let logical_time = IJsonUInt::new(1)?;

    let mut envelope: ReceiptEnvelope = serde_json::from_value(json!({
        "envelope_version": SchemaVersion::V1.get(),
        "receipt_type": ReceiptType::Mri,
        "context_digest": zero,
        "schema_digest": zero,
        "policy_digest": zero,
        "logical_time": logical_time.get(),
        "event_hash": zero,
        "boundary_origin": BoundaryOrigin::Engine,
        "payload": canonical,
    }))?;
    envelope.event_hash = vertrule_schemas::receipts::compute_event_hash(&envelope)?;
    Ok(envelope)
}

// ---------------------------------------------------------------------------
// Valid payloads
// ---------------------------------------------------------------------------

#[test]
fn valid_scalar_only_passes_full_pipeline() -> Result<(), Box<dyn std::error::Error>> {
    let batch = scalar_only()?;

    let envelope = envelope_from_batch_payload(&batch)?;
    let raw = canon_bytes(&envelope)?;

    let result = verify_receipt(&raw);
    assert_eq!(result.status, VerificationStatus::Valid);

    let recovered: MriBatchPayload = serde_json::from_value(envelope.payload.into_value())?;
    assert!(validate_mri_batch_payload(&recovered).is_ok());
    Ok(())
}

#[test]
fn valid_vector_payload_passes_full_pipeline() -> Result<(), Box<dyn std::error::Error>> {
    let mut batch = scalar_only()?;
    batch.layer = 5;
    batch.q_scalar = 0x4120_0000;
    batch.batch_len = Some(3);
    batch.q_per_example = Some(vec![0x3F80_0000, 0x4000_0000, 0x4040_0000]);

    let envelope = envelope_from_batch_payload(&batch)?;
    let raw = canon_bytes(&envelope)?;

    let result = verify_receipt(&raw);
    assert_eq!(result.status, VerificationStatus::Valid);

    let recovered: MriBatchPayload = serde_json::from_value(envelope.payload.into_value())?;
    assert!(validate_mri_batch_payload(&recovered).is_ok());
    Ok(())
}

// ---------------------------------------------------------------------------
// Invalid payloads (envelope valid, shape rejected)
// ---------------------------------------------------------------------------

#[test]
fn vector_without_batch_len_rejected_after_valid_envelope() -> Result<(), Box<dyn std::error::Error>>
{
    let mut batch = scalar_only()?;
    batch.q_per_example = Some(vec![0x3F80_0000]);

    let envelope = envelope_from_batch_payload(&batch)?;
    let raw = canon_bytes(&envelope)?;

    // Envelope is still valid (opaque payload)
    let result = verify_receipt(&raw);
    assert_eq!(result.status, VerificationStatus::Valid);

    // But shape validation catches the error
    let recovered: MriBatchPayload = serde_json::from_value(envelope.payload.into_value())?;
    assert!(validate_mri_batch_payload(&recovered).is_err());
    Ok(())
}

#[test]
fn vector_length_mismatch_rejected_after_valid_envelope() -> Result<(), Box<dyn std::error::Error>>
{
    let mut batch = scalar_only()?;
    batch.batch_len = Some(5);
    batch.q_per_example = Some(vec![0x3F80_0000, 0x4000_0000]); // 2 != 5

    let envelope = envelope_from_batch_payload(&batch)?;
    let raw = canon_bytes(&envelope)?;

    let result = verify_receipt(&raw);
    assert_eq!(result.status, VerificationStatus::Valid);

    let recovered: MriBatchPayload = serde_json::from_value(envelope.payload.into_value())?;
    assert!(validate_mri_batch_payload(&recovered).is_err());
    Ok(())
}

// ---------------------------------------------------------------------------
// Reduction mode affects digest
// ---------------------------------------------------------------------------

#[test]
fn different_reduction_modes_produce_different_envelopes() -> Result<(), Box<dyn std::error::Error>>
{
    let mut p1 = scalar_only()?;
    p1.provenance.reduction_mode = ReductionMode::BatchCollapsed;

    let mut p2 = p1.clone();
    p2.provenance.reduction_mode = ReductionMode::PerExampleThenMean;

    let e1 = envelope_from_batch_payload(&p1)?;
    let e2 = envelope_from_batch_payload(&p2)?;

    assert_ne!(e1.event_hash, e2.event_hash);
    Ok(())
}

// ---------------------------------------------------------------------------
// Parse failure for unknown reduction mode (serde, not verifier)
// ---------------------------------------------------------------------------

#[test]
fn unknown_reduction_mode_fails_at_parse_not_validation() {
    // Construct a valid envelope with a hand-crafted payload containing
    // an unknown reduction_mode. The envelope itself is valid; the parse
    // step (serde) should reject the unknown variant.
    let raw_payload = serde_json::json!({
        "schema": "vr.mri.batch_invariant@0.1",
        "layer": 0,
        "q_scalar": 1_065_353_216,
        "provenance": {
            "reduction_mode": "invented_mode",
            "reduced_axes": ["token"],
            "token_reduction": "mean",
            "batch_reduction": "mean"
        }
    });

    let parse_result: Result<MriBatchPayload, _> = serde_json::from_value(raw_payload);
    assert!(
        parse_result.is_err(),
        "unknown reduction_mode must be a parse failure"
    );
}
