//! Full-envelope commitment tamper tests.
//!
//! Each test creates a valid envelope, tampers exactly one
//! trust-bearing field, and asserts verification fails.

use vertrule_schemas::receipts::compute_event_hash;
use vertrule_schemas::{
    BoundaryOrigin, CanonicalPayload, DigestBytes, IJsonUInt, ReceiptEnvelope, ReceiptType,
    SchemaVersion,
};

/// Typed canonicalization helper (non-deprecated round-trip).
fn canon_string(value: &impl serde::Serialize) -> Result<String, anyhow::Error> {
    let json = serde_json::to_string(value)?;
    Ok(vr_jcs::to_canon_string_from_str(&json)?)
}

const fn zero_digest() -> DigestBytes {
    DigestBytes::from_array([0u8; 32])
}

fn make_valid_envelope() -> Result<ReceiptEnvelope, anyhow::Error> {
    let payload = CanonicalPayload::new(serde_json::json!({
        "action": "test",
        "domain": "envelope.tamper.tests",
        "value": 42
    }))
    .map_err(|e| anyhow::anyhow!(e))?;

    let logical_time = IJsonUInt::new(1000)?;
    let mut envelope: ReceiptEnvelope = serde_json::from_value(serde_json::json!({
        "envelope_version": SchemaVersion::V1.get(),
        "receipt_type": ReceiptType::Governance,
        "context_digest": DigestBytes::from_array([0xaa; 32]),
        "schema_digest": DigestBytes::from_array([0xbb; 32]),
        "policy_digest": DigestBytes::from_array([0xcc; 32]),
        "logical_time": logical_time.get(),
        "event_hash": zero_digest(),
        "boundary_origin": BoundaryOrigin::Engine,
        "payload": payload,
    }))?;
    envelope.event_hash = compute_event_hash(&envelope)?;
    Ok(envelope)
}

fn verify_envelope(
    envelope: &ReceiptEnvelope,
) -> Result<vertrule_verifier::result::VerificationResult, anyhow::Error> {
    let json = canon_string(envelope)?;
    Ok(vertrule_verifier::verify_receipt(json.as_bytes()))
}

#[test]
fn envelope_valid_envelope_passes() -> Result<(), anyhow::Error> {
    let envelope = make_valid_envelope()?;
    let result = verify_envelope(&envelope)?;
    assert!(
        result.status == vertrule_verifier::result::VerificationStatus::Valid,
        "valid envelope should pass: {:?}",
        result.errors
    );
    Ok(())
}

#[test]
fn envelope_tamper_receipt_type_fails() -> Result<(), anyhow::Error> {
    let mut envelope = make_valid_envelope()?;
    envelope.receipt_type = ReceiptType::Mri;
    let result = verify_envelope(&envelope)?;
    assert!(result.status != vertrule_verifier::result::VerificationStatus::Valid);
    Ok(())
}

#[test]
fn envelope_tamper_context_digest_fails() -> Result<(), anyhow::Error> {
    let mut envelope = make_valid_envelope()?;
    envelope.context_digest = DigestBytes::from_array([0xff; 32]);
    let result = verify_envelope(&envelope)?;
    assert!(result.status != vertrule_verifier::result::VerificationStatus::Valid);
    Ok(())
}

#[test]
fn envelope_tamper_schema_digest_fails() -> Result<(), anyhow::Error> {
    let mut envelope = make_valid_envelope()?;
    envelope.schema_digest = DigestBytes::from_array([0xff; 32]);
    let result = verify_envelope(&envelope)?;
    assert!(result.status != vertrule_verifier::result::VerificationStatus::Valid);
    Ok(())
}

#[test]
fn envelope_tamper_policy_digest_fails() -> Result<(), anyhow::Error> {
    let mut envelope = make_valid_envelope()?;
    envelope.policy_digest = DigestBytes::from_array([0xff; 32]);
    let result = verify_envelope(&envelope)?;
    assert!(result.status != vertrule_verifier::result::VerificationStatus::Valid);
    Ok(())
}

#[test]
fn envelope_tamper_logical_time_fails() -> Result<(), anyhow::Error> {
    let mut envelope = make_valid_envelope()?;
    envelope.logical_time = IJsonUInt::new(9999)?;
    let result = verify_envelope(&envelope)?;
    assert!(result.status != vertrule_verifier::result::VerificationStatus::Valid);
    Ok(())
}

#[test]
fn envelope_tamper_parent_id_fails() -> Result<(), anyhow::Error> {
    let mut envelope = make_valid_envelope()?;
    envelope.parent_id = Some(DigestBytes::from_array([0xdd; 32]));
    let result = verify_envelope(&envelope)?;
    assert!(result.status != vertrule_verifier::result::VerificationStatus::Valid);
    Ok(())
}

#[test]
fn envelope_tamper_boundary_origin_fails() -> Result<(), anyhow::Error> {
    let mut envelope = make_valid_envelope()?;
    envelope.boundary_origin = Some(BoundaryOrigin::Adapter);
    let result = verify_envelope(&envelope)?;
    assert!(result.status != vertrule_verifier::result::VerificationStatus::Valid);
    Ok(())
}

#[test]
fn envelope_tamper_payload_fails() -> Result<(), anyhow::Error> {
    let mut envelope = make_valid_envelope()?;
    envelope.payload = CanonicalPayload::new(serde_json::json!({"tampered": true}))
        .map_err(|e| anyhow::anyhow!(e))?;
    let result = verify_envelope(&envelope)?;
    assert!(result.status != vertrule_verifier::result::VerificationStatus::Valid);
    Ok(())
}

#[test]
fn envelope_remove_boundary_origin_fails() -> Result<(), anyhow::Error> {
    let mut envelope = make_valid_envelope()?;
    envelope.boundary_origin = None;
    let result = verify_envelope(&envelope)?;
    assert!(result.status != vertrule_verifier::result::VerificationStatus::Valid);
    Ok(())
}
