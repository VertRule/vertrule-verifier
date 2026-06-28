use super::{verify_external_receipt, verify_projection_source, ReceiptVerifyError};
use serde_json::{json, Value};
use vertrule_schemas::DigestBytes;

/// Build the envelope object **minus `event_hash`** (the commitment input).
///
/// Emits raw JSON matching the constitutional envelope schema so the verifier's
/// rejection paths can be exercised. `event_hash_profile`, when present, is part
/// of the commitment input (it is committed under `constitutional_envelope_v1`).
fn envelope_skeleton(
    envelope_version: u64,
    receipt_type: &str,
    logical_time: u64,
    boundary_origin: Option<&str>,
    event_hash_profile: Option<&str>,
    payload: &Value,
) -> Result<Value, anyhow::Error> {
    let mut obj = json!({
        "envelope_version": envelope_version,
        "receipt_type": receipt_type,
        "context_digest": DigestBytes::from_array([0xAA; 32]).to_hex(),
        "schema_digest": DigestBytes::from_array([0xBB; 32]).to_hex(),
        "policy_digest": DigestBytes::from_array([0xCC; 32]).to_hex(),
        "logical_time": logical_time.to_string(),
        "payload": payload,
    });
    let map = obj
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("skeleton is not a JSON object"))?;
    if let Some(origin) = boundary_origin {
        map.insert("boundary_origin".to_string(), json!(origin));
    }
    if let Some(profile) = event_hash_profile {
        map.insert("event_hash_profile".to_string(), json!(profile));
    }
    Ok(obj)
}

/// Envelope-minus-`event_hash` commitment: `BLAKE3(JCS(skeleton))`.
///
/// Mirrors `vertrule_schemas::ReceiptDigest::from_envelope_commitment`
/// (`blake3_untagged` over the JCS bytes of the envelope with `event_hash`
/// excluded), so a receipt built from this hash verifies under
/// `constitutional_envelope_v1`.
fn constitutional_event_hash(skeleton: &Value) -> Result<DigestBytes, anyhow::Error> {
    let bytes = serde_json::to_vec(skeleton)?;
    let canon = vr_jcs::to_canon_bytes_from_slice(&bytes)?;
    Ok(DigestBytes::from_array(*blake3::hash(&canon).as_bytes()))
}

/// Legacy payload-only digest (Law B — the defect): BLAKE3 over the JCS
/// canonical bytes of the payload alone.
fn payload_only_event_hash(payload: &Value) -> Result<DigestBytes, anyhow::Error> {
    let bytes = serde_json::to_vec(payload)?;
    let canon = vr_jcs::to_canon_bytes_from_slice(&bytes)?;
    Ok(DigestBytes::from_array(*blake3::hash(&canon).as_bytes()))
}

/// Insert a chosen `event_hash` into a skeleton and serialize to receipt bytes.
fn receipt_bytes(skeleton: &Value, event_hash: &DigestBytes) -> Result<Vec<u8>, anyhow::Error> {
    let mut obj = skeleton.clone();
    obj.as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("skeleton is not a JSON object"))?
        .insert("event_hash".to_string(), json!(event_hash.to_hex()));
    Ok(serde_json::to_vec(&obj)?)
}

/// A valid single-law (`governance`) receipt: constitutional envelope-minus
/// `event_hash`, no explicit profile.
fn make_valid_receipt_bytes() -> Result<Vec<u8>, anyhow::Error> {
    let payload = json!({"capability_type": "write", "scope": "engine.mutation"});
    let skeleton = envelope_skeleton(1, "governance", 42, Some("governance"), None, &payload)?;
    let event_hash = constitutional_event_hash(&skeleton)?;
    receipt_bytes(&skeleton, &event_hash)
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
    let skeleton = envelope_skeleton(1, "governance", 1, None, None, &payload)?;
    let wrong_hash = DigestBytes::from_array([0xFF; 32]);

    let bytes = receipt_bytes(&skeleton, &wrong_hash)?;
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
    let skeleton = envelope_skeleton(99, "governance", 1, None, None, &payload)?;
    let bytes = receipt_bytes(&skeleton, &DigestBytes::from_array([0x11; 32]))?;

    let result = verify_external_receipt(&bytes);
    // `SchemaVersion::deserialize` rejects version 99 at parse time, so the
    // error surfaces as `ParseError` rather than reaching
    // `verify_envelope_version`. Either rejection is a valid refusal.
    assert!(
        matches!(
            result,
            Err(ReceiptVerifyError::UnsupportedVersion(_) | ReceiptVerifyError::ParseError(_))
        ),
        "expected UnsupportedVersion or ParseError, got {result:?}"
    );
    Ok(())
}

#[test]
fn constitutional_profile_verifies_envelope_minus() -> Result<(), anyhow::Error> {
    // `event` (multi-law) WITH an explicit constitutional profile verifies via
    // envelope-minus recomputation.
    let payload = json!({"k": "v"});
    let skeleton = envelope_skeleton(
        1,
        "event",
        5,
        None,
        Some("constitutional_envelope_v1"),
        &payload,
    )?;
    let event_hash = constitutional_event_hash(&skeleton)?;
    let bytes = receipt_bytes(&skeleton, &event_hash)?;

    let meta = verify_external_receipt(&bytes)?;
    assert_eq!(meta.receipt_type(), "Event");
    Ok(())
}

#[test]
fn payload_only_event_hash_no_longer_passes() -> Result<(), anyhow::Error> {
    // A receipt whose event_hash is the legacy payload-only digest (Law B) must
    // no longer pass public verification: the envelope-minus recompute differs.
    let payload = json!({"k": "v"});
    let skeleton = envelope_skeleton(1, "governance", 1, None, None, &payload)?;
    let payload_only = payload_only_event_hash(&payload)?;

    let bytes = receipt_bytes(&skeleton, &payload_only)?;
    let result = verify_external_receipt(&bytes);
    assert!(
        matches!(result, Err(ReceiptVerifyError::EventHashMismatch { .. })),
        "payload-only event_hash must not pass public verification, got {result:?}"
    );
    Ok(())
}

#[test]
fn runtime_port_profile_not_misclassified_as_constitutional() -> Result<(), anyhow::Error> {
    // Even when event_hash EQUALS the constitutional (envelope-minus) commitment,
    // a runtime_port profile must NOT be verified as constitutional. The verifier
    // dispatches on the declared profile, not on whether bytes happen to match.
    let payload = json!({"command_id": "cmd-1"});
    let skeleton = envelope_skeleton(
        1,
        "event",
        7,
        None,
        Some("runtime_port_event_preimage_v1"),
        &payload,
    )?;
    let constitutional = constitutional_event_hash(&skeleton)?;
    let bytes = receipt_bytes(&skeleton, &constitutional)?;

    let result = verify_external_receipt(&bytes);
    assert!(
        matches!(
            result,
            Err(ReceiptVerifyError::ProfileNotEnvelopeVerifiable { .. })
        ),
        "runtime_port profile must not be verified by envelope-only RBH, got {result:?}"
    );
    Ok(())
}

#[test]
fn absent_profile_on_multi_law_event_rejects() -> Result<(), anyhow::Error> {
    // Multi-law `event` with no discriminator is a hard reject — even when the
    // event_hash is a valid constitutional commitment, the law is not inferred.
    let payload = json!({"k": "v"});
    let skeleton = envelope_skeleton(1, "event", 3, None, None, &payload)?;
    let event_hash = constitutional_event_hash(&skeleton)?;
    let bytes = receipt_bytes(&skeleton, &event_hash)?;

    let result = verify_external_receipt(&bytes);
    assert!(
        matches!(
            result,
            Err(ReceiptVerifyError::EventHashLawAmbiguous { .. })
        ),
        "multi-law `event` without a profile must reject, got {result:?}"
    );
    Ok(())
}

#[test]
fn unknown_profile_rejects_at_parse() -> Result<(), anyhow::Error> {
    // `event_hash_profile` is a closed enum: an inadmissible profile id fails to
    // deserialize (fail-closed at the type layer) and never reaches dispatch.
    let payload = json!({"k": "v"});
    let skeleton = envelope_skeleton(1, "event", 3, None, Some("sek_receipt_digest_v1"), &payload)?;
    let bytes = receipt_bytes(&skeleton, &DigestBytes::from_array([0x11; 32]))?;

    let result = verify_external_receipt(&bytes);
    assert!(
        matches!(result, Err(ReceiptVerifyError::ParseError(_))),
        "unknown event_hash_profile must reject at parse, got {result:?}"
    );
    Ok(())
}

#[test]
fn legacy_single_law_receipt_still_accepted() -> Result<(), anyhow::Error> {
    // A single-law non-`event` receipt without a profile still verifies (it is
    // not rejected for lacking a discriminator); its law is the constitutional
    // self-commitment, not payload-only.
    let payload = json!({"prompt": "hi"});
    let skeleton = envelope_skeleton(1, "llm", 9, None, None, &payload)?;
    let event_hash = constitutional_event_hash(&skeleton)?;
    let bytes = receipt_bytes(&skeleton, &event_hash)?;

    let meta = verify_external_receipt(&bytes)?;
    assert_eq!(meta.receipt_type(), "Llm");
    Ok(())
}

// ── Decode-step canonical-schema admission (ADR-0006) ────────────────────

fn decode_step_payload(schema: &str) -> Value {
    json!({
        "schema": schema,
        "step_index": 0,
        "step_output_digest": "abc",
    })
}

#[test]
fn decode_step_v02_constitutional_accepts() -> Result<(), anyhow::Error> {
    let payload = decode_step_payload("vr.operator_stream.decode_step@0.2");
    let skeleton = envelope_skeleton(1, "llm", 1, Some("engine"), None, &payload)?;
    let event_hash = constitutional_event_hash(&skeleton)?;
    let bytes = receipt_bytes(&skeleton, &event_hash)?;

    let meta = verify_external_receipt(&bytes)?;
    assert_eq!(meta.receipt_type(), "Llm");
    Ok(())
}

#[test]
fn decode_step_v01_rejected_as_non_canonical() -> Result<(), anyhow::Error> {
    // @0.1 carries a valid constitutional event_hash, so it passes the hash check;
    // it must still be rejected as a non-canonical decode claim.
    let payload = decode_step_payload("vr.operator_stream.decode_step@0.1");
    let skeleton = envelope_skeleton(1, "llm", 1, Some("engine"), None, &payload)?;
    let event_hash = constitutional_event_hash(&skeleton)?;
    let bytes = receipt_bytes(&skeleton, &event_hash)?;

    let result = verify_external_receipt(&bytes);
    assert!(
        matches!(
            result,
            Err(ReceiptVerifyError::NonCanonicalDecodeStep { .. })
        ),
        "decode_step@0.1 must be rejected as non-canonical, got {result:?}"
    );
    Ok(())
}

#[test]
fn decode_step_under_runtime_port_profile_rejected() -> Result<(), anyhow::Error> {
    // A decode-step envelope declaring the runtime-port profile must be refused
    // (decode_step is constitutional only); proves the fail-closed profile mapping.
    let payload = decode_step_payload("vr.operator_stream.decode_step@0.2");
    let skeleton = envelope_skeleton(
        1,
        "llm",
        1,
        None,
        Some("runtime_port_event_preimage_v1"),
        &payload,
    )?;
    let event_hash = constitutional_event_hash(&skeleton)?;
    let bytes = receipt_bytes(&skeleton, &event_hash)?;

    let result = verify_external_receipt(&bytes);
    assert!(
        matches!(
            result,
            Err(ReceiptVerifyError::ProfileNotEnvelopeVerifiable { .. })
        ),
        "decode_step@0.2 declaring runtime_port must be rejected, got {result:?}"
    );
    Ok(())
}

// ── Projection source binding (ADR-0006) ─────────────────────────────────

/// Build a valid canonical `decode_step@0.2` envelope; return its bytes and the
/// hex `event_hash` a projection must cite.
fn canonical_decode_step_envelope() -> Result<(Vec<u8>, String), anyhow::Error> {
    let payload = decode_step_payload("vr.operator_stream.decode_step@0.2");
    let skeleton = envelope_skeleton(1, "llm", 1, Some("engine"), None, &payload)?;
    let event_hash = constitutional_event_hash(&skeleton)?;
    let bytes = receipt_bytes(&skeleton, &event_hash)?;
    Ok((bytes, event_hash.to_hex()))
}

/// A projection that cites the canonical envelope, carrying all five binding
/// fields with the three source-bound ones agreeing with the envelope.
fn projection_citing(event_hash_hex: &str) -> Value {
    json!({
        "schema": "vr.browser.decode_step@0.2",
        "source_receipt_type": "llm",
        "source_schema_version": "vr.operator_stream.decode_step@0.2",
        "source_event_hash": event_hash_hex,
        "projection_law_id": "vr/browser/decode-step/v2",
        "omitted_evidence_classes": ["sampling", "trace"],
    })
}

#[test]
fn projection_with_matching_source_accepts() -> Result<(), anyhow::Error> {
    let (envelope_bytes, event_hash) = canonical_decode_step_envelope()?;
    let projection_bytes = serde_json::to_vec(&projection_citing(&event_hash))?;
    verify_projection_source(&projection_bytes, &envelope_bytes)?;
    Ok(())
}

#[test]
fn projection_source_event_hash_mismatch_rejected() -> Result<(), anyhow::Error> {
    // Citing the wrong canonical event_hash must fail closed — the projection
    // claims to project a step it does not.
    let (envelope_bytes, _event_hash) = canonical_decode_step_envelope()?;
    let wrong = DigestBytes::from_array([0x77; 32]).to_hex();
    let projection_bytes = serde_json::to_vec(&projection_citing(&wrong))?;

    let result = verify_projection_source(&projection_bytes, &envelope_bytes);
    assert!(
        matches!(
            result,
            Err(ReceiptVerifyError::ProjectionSourceMismatch {
                field: "source_event_hash",
                ..
            })
        ),
        "projection citing wrong source_event_hash must reject, got {result:?}"
    );
    Ok(())
}

#[test]
fn projection_source_type_mismatch_rejected() -> Result<(), anyhow::Error> {
    // `source_event_hash` alone is insufficient: citing the wrong receipt class
    // (here `governance` against an `llm` decode step) must also fail closed.
    let (envelope_bytes, event_hash) = canonical_decode_step_envelope()?;
    let mut projection = projection_citing(&event_hash);
    projection["source_receipt_type"] = json!("governance");
    let projection_bytes = serde_json::to_vec(&projection)?;

    let result = verify_projection_source(&projection_bytes, &envelope_bytes);
    assert!(
        matches!(
            result,
            Err(ReceiptVerifyError::ProjectionSourceMismatch {
                field: "source_receipt_type",
                ..
            })
        ),
        "projection citing wrong source_receipt_type must reject, got {result:?}"
    );
    Ok(())
}

#[test]
fn projection_missing_binding_rejected() -> Result<(), anyhow::Error> {
    // All five fields are required; dropping a projection-declared one fails closed.
    let (envelope_bytes, event_hash) = canonical_decode_step_envelope()?;
    let mut projection = projection_citing(&event_hash);
    projection
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("projection is not a JSON object"))?
        .remove("projection_law_id");
    let projection_bytes = serde_json::to_vec(&projection)?;

    let result = verify_projection_source(&projection_bytes, &envelope_bytes);
    assert!(
        matches!(
            result,
            Err(ReceiptVerifyError::ProjectionMissingSourceBinding {
                field: "projection_law_id"
            })
        ),
        "projection missing a binding field must reject, got {result:?}"
    );
    Ok(())
}
