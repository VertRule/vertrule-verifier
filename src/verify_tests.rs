//! Tests for the verification facade.

use crate::result::VerificationStatus;
use crate::test_support::vr_test;

/// Build a single envelope JSON value with correct `event_hash`.
/// Returns `(value, event_hash_hex)`.
fn build_envelope_value(
    logical_time: u64,
    parent_id: Option<&str>,
    payload: serde_json::Value,
) -> Result<(serde_json::Value, String), anyhow::Error> {
    // Build the envelope without event_hash first
    let mut obj = serde_json::Map::new();
    obj.insert(
        "context_digest".to_string(),
        serde_json::json!("a".repeat(64)),
    );
    obj.insert("envelope_version".to_string(), serde_json::json!(1));
    obj.insert("logical_time".to_string(), serde_json::json!(logical_time));
    if let Some(pid) = parent_id {
        obj.insert("parent_id".to_string(), serde_json::json!(pid));
    }
    obj.insert("payload".to_string(), payload);
    obj.insert(
        "policy_digest".to_string(),
        serde_json::json!("c".repeat(64)),
    );
    obj.insert("receipt_type".to_string(), serde_json::json!("governance"));
    obj.insert(
        "schema_digest".to_string(),
        serde_json::json!("b".repeat(64)),
    );

    // Compute full-envelope hash (all fields except event_hash)
    let canon_bytes = crate::canon::typed_canon_bytes(&serde_json::Value::Object(obj.clone()))
        .map_err(|e| anyhow::anyhow!("canonicalization: {e}"))?;
    let hash = blake3::hash(&canon_bytes);
    let event_hash = hex::encode(hash.as_bytes());

    obj.insert("event_hash".to_string(), serde_json::json!(&event_hash));

    Ok((serde_json::Value::Object(obj), event_hash))
}

/// Build canonical bytes for a single envelope.
fn build_single_bytes(
    logical_time: u64,
    payload: serde_json::Value,
) -> Result<Vec<u8>, anyhow::Error> {
    let (value, _hash) = build_envelope_value(logical_time, None, payload)?;
    crate::canon::typed_canon_bytes(&value).map_err(|e| anyhow::anyhow!("canonicalization: {e}"))
}

/// Build a valid chain of `count` envelopes as a JSON array byte vector.
fn build_valid_chain_bytes(count: usize) -> Result<Vec<u8>, anyhow::Error> {
    let mut elements = Vec::new();
    let mut prev_hash: Option<String> = None;

    for i in 0..count {
        let payload = serde_json::json!({"index": i});
        let (value, event_hash) =
            build_envelope_value(1000 + i as u64, prev_hash.as_deref(), payload)?;
        prev_hash = Some(event_hash);
        elements.push(value);
    }

    let array = serde_json::Value::Array(elements);
    crate::canon::typed_canon_bytes(&array).map_err(|e| anyhow::anyhow!("canonicalization: {e}"))
}

vr_test!(
    fn test_verify_valid_single() {
        let bytes = build_single_bytes(1000, serde_json::json!({"key": "value"}))?;
        let result = super::verify_receipt(&bytes);
        assert_eq!(result.status, VerificationStatus::Valid);
        assert!(result.digest_validation.all_hashes_match);
        assert!(result.errors.is_empty());
    }
);

vr_test!(
    fn test_verify_malformed_json() {
        let result = super::verify_receipt(b"not json");
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert!(!result.errors.is_empty());
    }
);

vr_test!(
    fn test_verify_event_hash_mismatch() {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "context_digest".to_string(),
            serde_json::json!("a".repeat(64)),
        );
        obj.insert("envelope_version".to_string(), serde_json::json!(1));
        // Wrong event_hash
        obj.insert("event_hash".to_string(), serde_json::json!("f".repeat(64)));
        obj.insert("logical_time".to_string(), serde_json::json!(1000));
        obj.insert("payload".to_string(), serde_json::json!({"key": "value"}));
        obj.insert(
            "policy_digest".to_string(),
            serde_json::json!("c".repeat(64)),
        );
        obj.insert("receipt_type".to_string(), serde_json::json!("governance"));
        obj.insert(
            "schema_digest".to_string(),
            serde_json::json!("b".repeat(64)),
        );
        let value = serde_json::Value::Object(obj);
        let bytes = crate::canon::typed_canon_bytes(&value)
            .map_err(|e| anyhow::anyhow!("canonicalization: {e}"))?;

        let result = super::verify_receipt(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert!(!result.digest_validation.all_hashes_match);
    }
);

vr_test!(
    fn test_verify_valid_chain() {
        let bytes = build_valid_chain_bytes(3)?;
        let result = super::verify_receipt_chain(&bytes);
        assert_eq!(result.status, VerificationStatus::Valid);
        assert!(result.digest_validation.all_hashes_match);
        assert!(result.digest_validation.chain_integrity);
        assert!(result.digest_validation.ordering_valid);

        let chain = result
            .chain_validation
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing chain_validation"))?;
        assert_eq!(chain.length, 3);
        assert_eq!(chain.first_logical_time, 1000);
        assert_eq!(chain.last_logical_time, 1002);

        let ctx = result
            .context_consistency
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing context_consistency"))?;
        assert!(ctx.uniform_context);

        let pol = result
            .policy_consistency
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing policy_consistency"))?;
        assert!(pol.stable_policy);
        assert!(!pol.transitions_detected);
    }
);

vr_test!(
    fn test_verify_chain_broken_linkage() {
        let (env0, _hash0) = build_envelope_value(1000, None, serde_json::json!({"index": 0}))?;
        // Wrong parent_id (not the event_hash of env0)
        let (env1, _hash1) =
            build_envelope_value(1001, Some(&"f".repeat(64)), serde_json::json!({"index": 1}))?;

        let array = serde_json::Value::Array(vec![env0, env1]);
        let bytes = crate::canon::typed_canon_bytes(&array)
            .map_err(|e| anyhow::anyhow!("canonicalization: {e}"))?;

        let result = super::verify_receipt_chain(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert!(!result.digest_validation.chain_integrity);
    }
);

vr_test!(
    fn test_verify_chain_non_monotonic() {
        let (env0, hash0) = build_envelope_value(1000, None, serde_json::json!({"index": 0}))?;
        // Same logical_time as env0 — not monotonic
        let (env1, _hash1) =
            build_envelope_value(1000, Some(&hash0), serde_json::json!({"index": 1}))?;

        let array = serde_json::Value::Array(vec![env0, env1]);
        let bytes = crate::canon::typed_canon_bytes(&array)
            .map_err(|e| anyhow::anyhow!("canonicalization: {e}"))?;

        let result = super::verify_receipt_chain(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert!(!result.digest_validation.ordering_valid);
    }
);

vr_test!(
    fn test_verify_empty_chain() {
        let result = super::verify_receipt_chain(b"[]");
        assert_eq!(result.status, VerificationStatus::Valid);

        let chain = result
            .chain_validation
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("empty chain should have chain_validation"))?;
        assert_eq!(chain.length, 0);
    }
);

vr_test!(
    fn test_verify_chain_schema_inconsistent() {
        let (env0, hash0) = build_envelope_value(1000, None, serde_json::json!({"index": 0}))?;
        let (mut env1_val, _hash1) =
            build_envelope_value(1001, Some(&hash0), serde_json::json!({"index": 1}))?;

        // Tamper schema_digest in second envelope
        env1_val["schema_digest"] = serde_json::json!("f".repeat(64));

        let array = serde_json::Value::Array(vec![env0, env1_val]);
        let bytes = crate::canon::typed_canon_bytes(&array)
            .map_err(|e| anyhow::anyhow!("canonicalization: {e}"))?;

        let result = super::verify_receipt_chain(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);

        let sc = result
            .schema_consistency
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing schema_consistency"))?;
        assert!(!sc.uniform_schema);
    }
);

vr_test!(
    fn test_verify_result_deterministic() {
        let bytes = build_single_bytes(1000, serde_json::json!({"key": "value"}))?;
        let r1 = super::verify_receipt(&bytes);
        let r2 = super::verify_receipt(&bytes);
        let d1 = r1.digest()?;
        let d2 = r2.digest()?;
        assert_eq!(d1, d2);
    }
);

// ── signature_validation.present regression tests ─────────────────

vr_test!(
    /// Malformed JSON supplied as signature bundle → present: true, valid: false.
    fn test_malformed_sig_bundle_is_present_but_invalid() {
        let receipt_bytes = build_single_bytes(1000, serde_json::json!({"key": "value"}))?;
        let malformed_sig = b"this is not json";

        let result = super::verify_signed_receipt(&receipt_bytes, malformed_sig);
        let sig = result
            .signature_validation
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing signature_validation"))?;

        assert!(sig.present, "bundle was supplied, present must be true");
        assert!(!sig.valid, "malformed bundle cannot be valid");
    }
);

vr_test!(
    /// Correct `key_id`/`public_key` pair but bad signature → `key_id_consistent`: true, valid: false.
    fn test_correct_key_id_with_bad_signature() {
        let receipt_bytes = build_single_bytes(1000, serde_json::json!({"key": "value"}))?;

        // Generate a real keypair for a consistent key_id/public_key pair
        let seed = [99u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key();
        let pk_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk.as_bytes());
        let hash = blake3::hash(pk.as_bytes());
        let key_id = hex::encode(&hash.as_bytes()[..12]);

        // All-zeros signature: structurally valid length, cryptographically invalid
        let sig_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 64]);

        let bundle = serde_json::json!({
            "alg": "Ed25519",
            "key_id": key_id,
            "public_key_b64": pk_b64,
            "signature_b64": sig_b64,
            "schema_version": "0.2",
            "digest_basis": "BLAKE3+JCS",
            "timestamp": "2026-01-01T00:00:00Z"
        });
        let sig_bytes =
            serde_json::to_vec(&bundle).map_err(|e| anyhow::anyhow!("serialize: {e}"))?;

        let result = super::verify_signed_receipt(&receipt_bytes, &sig_bytes);
        let sig = result
            .signature_validation
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing signature_validation"))?;

        assert!(sig.present, "bundle was supplied, present must be true");
        assert!(!sig.valid, "bad signature must not be valid");
        assert!(
            sig.key_id_consistent,
            "key_id matches public_key — key_id_consistent must be true even when signature is invalid"
        );
    }
);

vr_test!(
    /// Valid JSON but wrong schema as signature bundle → present: true, valid: false.
    fn test_wrong_schema_sig_bundle_is_present_but_invalid() {
        let receipt_bytes = build_single_bytes(1000, serde_json::json!({"key": "value"}))?;
        let wrong_schema_sig = br#"{"not_a": "signature_bundle"}"#;

        let result = super::verify_signed_receipt(&receipt_bytes, wrong_schema_sig);
        let sig = result
            .signature_validation
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing signature_validation"))?;

        assert!(sig.present, "bundle was supplied, present must be true");
        assert!(!sig.valid, "wrong-schema bundle cannot be valid");
    }
);
