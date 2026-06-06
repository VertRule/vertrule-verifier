//! Tests for bundle verification.

use crate::result::VerificationStatus;
use crate::test_support::vr_test;

vr_test!(
    fn malformed_json_rejected() {
        let result = super::verify_bundle(b"not json");
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert!(!result.errors.is_empty());
    }
);

vr_test!(
    fn wrong_format_rejected() {
        let bundle = serde_json::json!({
            "_format": "unknown/v9",
            "envelope_canonical": "{}",
            "sidecars": {}
        });
        let bytes = serde_json::to_vec(&bundle).map_err(|e| anyhow::anyhow!("{e}"))?;
        let result = super::verify_bundle(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("unsupported bundle format")));
    }
);

vr_test!(
    fn valid_envelope_no_sidecars() {
        // Build a valid envelope
        let payload = serde_json::json!({"key": "value"});
        let mut obj = serde_json::Map::new();
        obj.insert(
            "context_digest".to_string(),
            serde_json::json!("a".repeat(64)),
        );
        obj.insert("envelope_version".to_string(), serde_json::json!(1));
        obj.insert("logical_time".to_string(), serde_json::json!("1000"));
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

        let canon_bytes = crate::canon::typed_canon_bytes(&serde_json::Value::Object(obj.clone()))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let hash = blake3::hash(&canon_bytes);
        obj.insert(
            "event_hash".to_string(),
            serde_json::json!(hex::encode(hash.as_bytes())),
        );
        let envelope_canonical = crate::canon::typed_canon_string(&serde_json::Value::Object(obj))
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        let bundle = serde_json::json!({
            "_format": "vr-execution-bundle/v1",
            "envelope_canonical": envelope_canonical,
            "sidecars": {}
        });
        let bytes = serde_json::to_vec(&bundle).map_err(|e| anyhow::anyhow!("{e}"))?;

        let result = super::verify_bundle(&bytes);
        assert_eq!(result.status, VerificationStatus::Valid);
        assert!(result.errors.is_empty());
        assert!(result.sidecar_checks.is_empty());
    }
);

vr_test!(
    fn sidecar_digest_match() {
        // Create a sidecar and compute its digest
        let trace = serde_json::json!({"schema": "vr.layer-trace.v1", "steps": []});
        let trace_json = serde_json::to_string(&trace).map_err(|e| anyhow::anyhow!("{e}"))?;
        let trace_canonical =
            vr_jcs::to_canon_string_from_str(&trace_json).map_err(|e| anyhow::anyhow!("{e}"))?;
        let trace_digest = blake3::hash(trace_canonical.as_bytes())
            .to_hex()
            .to_string();

        // Build envelope with that digest in the payload
        let payload = serde_json::json!({"layer_trace_digest": trace_digest});
        let mut obj = serde_json::Map::new();
        obj.insert(
            "context_digest".to_string(),
            serde_json::json!("a".repeat(64)),
        );
        obj.insert("envelope_version".to_string(), serde_json::json!(1));
        obj.insert("logical_time".to_string(), serde_json::json!("1000"));
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

        let canon_bytes = crate::canon::typed_canon_bytes(&serde_json::Value::Object(obj.clone()))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let hash = blake3::hash(&canon_bytes);
        obj.insert(
            "event_hash".to_string(),
            serde_json::json!(hex::encode(hash.as_bytes())),
        );
        let envelope_canonical = crate::canon::typed_canon_string(&serde_json::Value::Object(obj))
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        let bundle = serde_json::json!({
            "_format": "vr-execution-bundle/v1",
            "envelope_canonical": envelope_canonical,
            "sidecars": {
                "layer_trace": trace
            }
        });
        let bytes = serde_json::to_vec(&bundle).map_err(|e| anyhow::anyhow!("{e}"))?;

        let result = super::verify_bundle(&bytes);
        assert_eq!(result.status, VerificationStatus::Valid);
        assert_eq!(result.sidecar_checks.len(), 1);
        assert!(result.sidecar_checks[0].matches);
    }
);

vr_test!(
    fn sidecar_digest_mismatch_detected() {
        // Create a sidecar but put a wrong digest in the payload
        let trace = serde_json::json!({"schema": "vr.layer-trace.v1", "steps": []});
        let wrong_digest = "f".repeat(64);

        let payload = serde_json::json!({"layer_trace_digest": wrong_digest});
        let mut obj = serde_json::Map::new();
        obj.insert(
            "context_digest".to_string(),
            serde_json::json!("a".repeat(64)),
        );
        obj.insert("envelope_version".to_string(), serde_json::json!(1));
        obj.insert("logical_time".to_string(), serde_json::json!("1000"));
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

        let canon_bytes = crate::canon::typed_canon_bytes(&serde_json::Value::Object(obj.clone()))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let hash = blake3::hash(&canon_bytes);
        obj.insert(
            "event_hash".to_string(),
            serde_json::json!(hex::encode(hash.as_bytes())),
        );
        let envelope_canonical = crate::canon::typed_canon_string(&serde_json::Value::Object(obj))
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        let bundle = serde_json::json!({
            "_format": "vr-execution-bundle/v1",
            "envelope_canonical": envelope_canonical,
            "sidecars": {
                "layer_trace": trace
            }
        });
        let bytes = serde_json::to_vec(&bundle).map_err(|e| anyhow::anyhow!("{e}"))?;

        let result = super::verify_bundle(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert_eq!(result.sidecar_checks.len(), 1);
        assert!(!result.sidecar_checks[0].matches);
        assert!(result.errors.iter().any(|e| e.contains("digest mismatch")));
    }
);
