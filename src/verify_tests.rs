//! Tests for the verification facade.

use crate::test_support::vr_test;
use crate::result::VerificationStatus;

/// Build a single envelope JSON value with correct `event_hash`.
/// Returns `(value, event_hash_hex)`.
fn build_envelope_value(
    logical_time: u64,
    parent_id: Option<&str>,
    payload: serde_json::Value,
) -> Result<(serde_json::Value, String), anyhow::Error> {
    let payload_canon = vertrule_schemas::jcs::to_canon_bytes(&payload)
        .map_err(|e| anyhow::anyhow!("payload canonicalization: {e}"))?;
    let hash = blake3::hash(&payload_canon);
    let event_hash = hex::encode(hash.as_bytes());

    let mut obj = serde_json::Map::new();
    obj.insert(
        "context_digest".to_string(),
        serde_json::json!("a".repeat(64)),
    );
    obj.insert("envelope_version".to_string(), serde_json::json!(1));
    obj.insert("event_hash".to_string(), serde_json::json!(&event_hash));
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

    Ok((serde_json::Value::Object(obj), event_hash))
}

/// Build canonical bytes for a single envelope.
fn build_single_bytes(
    logical_time: u64,
    payload: serde_json::Value,
) -> Result<Vec<u8>, anyhow::Error> {
    let (value, _hash) = build_envelope_value(logical_time, None, payload)?;
    vertrule_schemas::jcs::to_canon_bytes(&value).map_err(|e| anyhow::anyhow!("canonicalization: {e}"))
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
    vertrule_schemas::jcs::to_canon_bytes(&array).map_err(|e| anyhow::anyhow!("canonicalization: {e}"))
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
        let bytes =
            vertrule_schemas::jcs::to_canon_bytes(&value).map_err(|e| anyhow::anyhow!("canonicalization: {e}"))?;

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
        let bytes =
            vertrule_schemas::jcs::to_canon_bytes(&array).map_err(|e| anyhow::anyhow!("canonicalization: {e}"))?;

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
        let bytes =
            vertrule_schemas::jcs::to_canon_bytes(&array).map_err(|e| anyhow::anyhow!("canonicalization: {e}"))?;

        let result = super::verify_receipt_chain(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert!(!result.digest_validation.ordering_valid);
    }
);

vr_test!(
    fn test_verify_empty_chain() {
        let result = super::verify_receipt_chain(b"[]");
        assert_eq!(result.status, VerificationStatus::Valid);
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
