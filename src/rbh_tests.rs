use super::{verify_external_receipt, ReceiptVerifyError};
use serde_json::json;
use vertrule_schemas::DigestBytes;

/// Build envelope JSON bytes directly.
///
/// Emits raw JSON matching the constitutional envelope schema. Does NOT
/// round-trip through `ReceiptEnvelope` (which is `#[non_exhaustive]`
/// and would also pre-reject invalid values like version=99 at
/// deserialize time; this helper must be able to emit such values so
/// that the verifier's rejection paths can be exercised).
///
/// `ReceiptType` / `BoundaryOrigin` serialize as lowercase variant
/// names. `IJsonUInt` (used for `logical_time` here) is `#[serde(transparent)]`
/// over `u64`, so the value is emitted as a JSON integer.
fn envelope_bytes(
    event_hash: DigestBytes,
    envelope_version: u64,
    logical_time: u64,
    boundary_origin: Option<&str>,
    payload: serde_json::Value,
) -> Result<Vec<u8>, anyhow::Error> {
    let mut envelope_json = json!({
        "envelope_version": envelope_version,
        "receipt_type": "governance",
        "context_digest": DigestBytes::from_array([0xAA; 32]).to_hex(),
        "schema_digest": DigestBytes::from_array([0xBB; 32]).to_hex(),
        "policy_digest": DigestBytes::from_array([0xCC; 32]).to_hex(),
        "logical_time": logical_time,
        "event_hash": event_hash.to_hex(),
        "payload": payload,
    });
    if let Some(origin) = boundary_origin {
        envelope_json
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("envelope_json is not an object"))?
            .insert("boundary_origin".to_string(), json!(origin));
    }
    let bytes = serde_json::to_vec(&envelope_json)?;
    Ok(bytes)
}

/// Build a valid governance receipt envelope and serialize it.
fn make_valid_receipt_bytes() -> Result<Vec<u8>, anyhow::Error> {
    let payload = json!({
        "capability_type": "write",
        "scope": "engine.mutation"
    });

    let json_bytes = serde_json::to_vec(&payload)?;
    let payload_bytes = vr_jcs::to_canon_bytes_from_slice(&json_bytes)?;
    let event_hash = DigestBytes::from_array(*blake3::hash(&payload_bytes).as_bytes());

    envelope_bytes(event_hash, 1, 42, Some("governance"), payload)
}

#[test]
fn valid_receipt_accepted() -> Result<(), anyhow::Error> {
    let bytes = make_valid_receipt_bytes()?;
    let meta = verify_external_receipt(&bytes)?;

    assert_eq!(meta.receipt_type(), "Governance");
    assert_eq!(meta.logical_time(), 42);
    assert_eq!(meta.boundary_origin(), Some("Governance"));
    Ok(())
}

#[test]
fn tampered_event_hash_rejected() -> Result<(), anyhow::Error> {
    let payload = json!({"key": "value"});
    let wrong_hash = DigestBytes::from_array([0xFF; 32]);

    let bytes = envelope_bytes(wrong_hash, 1, 1, None, payload)?;
    let result = verify_external_receipt(&bytes);
    assert!(matches!(
        result,
        Err(ReceiptVerifyError::EventHashMismatch { .. })
    ));
    Ok(())
}

#[test]
fn unsupported_version_rejected() -> Result<(), anyhow::Error> {
    let payload = json!({"key": "value"});
    let json_bytes = serde_json::to_vec(&payload)?;
    let payload_bytes = vr_jcs::to_canon_bytes_from_slice(&json_bytes)?;
    let event_hash = DigestBytes::from_array(*blake3::hash(&payload_bytes).as_bytes());

    let bytes = envelope_bytes(event_hash, 99, 1, None, payload)?;
    let result = verify_external_receipt(&bytes);
    // `SchemaVersion::deserialize` rejects version 99 at parse time, so
    // the error surfaces as `ParseError` rather than reaching
    // `verify_envelope_version`. Either rejection is a valid refusal of
    // an unsupported envelope version.
    assert!(
        matches!(
            result,
            Err(ReceiptVerifyError::UnsupportedVersion(_)) | Err(ReceiptVerifyError::ParseError(_))
        ),
        "expected UnsupportedVersion or ParseError, got {result:?}"
    );
    Ok(())
}
