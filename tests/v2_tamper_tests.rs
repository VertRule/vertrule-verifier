//! V2 full-envelope commitment tamper tests.
//!
//! Each test creates a valid V2 envelope, tampers exactly one
//! trust-bearing field, and asserts verification fails.

use vertrule_schemas::receipts::compute_event_hash;
use vertrule_schemas::{
    BoundaryOrigin, CanonicalPayload, DigestBytes, IJsonUInt, ReceiptEnvelope, ReceiptType,
    SchemaVersion,
};

const fn zero_digest() -> DigestBytes {
    DigestBytes::from_array([0u8; 32])
}

fn make_valid_v2_envelope() -> Result<ReceiptEnvelope, anyhow::Error> {
    let payload = CanonicalPayload::new(serde_json::json!({
        "action": "test",
        "domain": "v2.tamper.tests",
        "value": 42
    }))
    .map_err(|e| anyhow::anyhow!(e))?;

    let mut envelope = ReceiptEnvelope {
        envelope_version: SchemaVersion::V2,
        receipt_type: ReceiptType::Governance,
        context_digest: DigestBytes::from_array([0xaa; 32]),
        schema_digest: DigestBytes::from_array([0xbb; 32]),
        policy_digest: DigestBytes::from_array([0xcc; 32]),
        logical_time: IJsonUInt::new(1000)?,
        event_hash: zero_digest(),
        parent_id: None,
        boundary_origin: Some(BoundaryOrigin::Engine),
        digest_algorithm: None,
        canonicalization: None,
        payload,
    };
    envelope.event_hash = compute_event_hash(&envelope)?;
    Ok(envelope)
}

fn verify_envelope(
    envelope: &ReceiptEnvelope,
) -> Result<vertrule_verifier::result::VerificationResult, anyhow::Error> {
    let json = vr_jcs::to_canon_string(envelope)?;
    Ok(vertrule_verifier::verify_receipt(json.as_bytes()))
}

#[test]
fn v2_valid_envelope_passes() -> Result<(), anyhow::Error> {
    let envelope = make_valid_v2_envelope()?;
    let result = verify_envelope(&envelope)?;
    assert!(
        result.status == vertrule_verifier::result::VerificationStatus::Valid,
        "valid V2 envelope should pass: {:?}",
        result.errors
    );
    Ok(())
}

#[test]
fn v2_tamper_receipt_type_fails() -> Result<(), anyhow::Error> {
    let mut envelope = make_valid_v2_envelope()?;
    envelope.receipt_type = ReceiptType::Mri;
    let result = verify_envelope(&envelope)?;
    assert!(result.status != vertrule_verifier::result::VerificationStatus::Valid);
    Ok(())
}

#[test]
fn v2_tamper_context_digest_fails() -> Result<(), anyhow::Error> {
    let mut envelope = make_valid_v2_envelope()?;
    envelope.context_digest = DigestBytes::from_array([0xff; 32]);
    let result = verify_envelope(&envelope)?;
    assert!(result.status != vertrule_verifier::result::VerificationStatus::Valid);
    Ok(())
}

#[test]
fn v2_tamper_schema_digest_fails() -> Result<(), anyhow::Error> {
    let mut envelope = make_valid_v2_envelope()?;
    envelope.schema_digest = DigestBytes::from_array([0xff; 32]);
    let result = verify_envelope(&envelope)?;
    assert!(result.status != vertrule_verifier::result::VerificationStatus::Valid);
    Ok(())
}

#[test]
fn v2_tamper_policy_digest_fails() -> Result<(), anyhow::Error> {
    let mut envelope = make_valid_v2_envelope()?;
    envelope.policy_digest = DigestBytes::from_array([0xff; 32]);
    let result = verify_envelope(&envelope)?;
    assert!(result.status != vertrule_verifier::result::VerificationStatus::Valid);
    Ok(())
}

#[test]
fn v2_tamper_logical_time_fails() -> Result<(), anyhow::Error> {
    let mut envelope = make_valid_v2_envelope()?;
    envelope.logical_time = IJsonUInt::new(9999)?;
    let result = verify_envelope(&envelope)?;
    assert!(result.status != vertrule_verifier::result::VerificationStatus::Valid);
    Ok(())
}

#[test]
fn v2_tamper_parent_id_fails() -> Result<(), anyhow::Error> {
    let mut envelope = make_valid_v2_envelope()?;
    envelope.parent_id = Some(DigestBytes::from_array([0xdd; 32]));
    let result = verify_envelope(&envelope)?;
    assert!(result.status != vertrule_verifier::result::VerificationStatus::Valid);
    Ok(())
}

#[test]
fn v2_tamper_boundary_origin_fails() -> Result<(), anyhow::Error> {
    let mut envelope = make_valid_v2_envelope()?;
    envelope.boundary_origin = Some(BoundaryOrigin::Adapter);
    let result = verify_envelope(&envelope)?;
    assert!(result.status != vertrule_verifier::result::VerificationStatus::Valid);
    Ok(())
}

#[test]
fn v2_tamper_payload_fails() -> Result<(), anyhow::Error> {
    let mut envelope = make_valid_v2_envelope()?;
    envelope.payload = CanonicalPayload::new(serde_json::json!({"tampered": true}))
        .map_err(|e| anyhow::anyhow!(e))?;
    let result = verify_envelope(&envelope)?;
    assert!(result.status != vertrule_verifier::result::VerificationStatus::Valid);
    Ok(())
}

#[test]
fn v2_remove_boundary_origin_fails() -> Result<(), anyhow::Error> {
    let mut envelope = make_valid_v2_envelope()?;
    envelope.boundary_origin = None;
    let result = verify_envelope(&envelope)?;
    assert!(result.status != vertrule_verifier::result::VerificationStatus::Valid);
    Ok(())
}

#[test]
fn v1_same_payload_different_metadata_still_passes() -> Result<(), anyhow::Error> {
    let payload =
        CanonicalPayload::new(serde_json::json!({"v": 1})).map_err(|e| anyhow::anyhow!(e))?;
    let canon = vr_jcs::to_canon_bytes(payload.as_value())?;
    let event_hash = DigestBytes::from_array(*blake3::hash(&canon).as_bytes());

    let envelope = ReceiptEnvelope {
        envelope_version: SchemaVersion::V1,
        receipt_type: ReceiptType::Event,
        context_digest: zero_digest(),
        schema_digest: zero_digest(),
        policy_digest: zero_digest(),
        logical_time: IJsonUInt::new(1)?,
        event_hash,
        parent_id: None,
        boundary_origin: None,
        digest_algorithm: None,
        canonicalization: None,
        payload,
    };

    let mut tampered = envelope;
    tampered.context_digest = DigestBytes::from_array([0xff; 32]);
    let result = verify_envelope(&tampered)?;
    assert!(
        result.status == vertrule_verifier::result::VerificationStatus::Valid,
        "V1 does NOT protect metadata fields — this is the weakness V2 fixes"
    );
    Ok(())
}
