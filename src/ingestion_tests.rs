//! Tests for fail-closed ingestion.

use crate::test_support::vr_test;
use vertrule_schemas::SchemaVersion;

use crate::error::VerifyError;

/// Build a valid canonical envelope as raw bytes.
fn valid_canonical_envelope_bytes() -> Result<Vec<u8>, anyhow::Error> {
    let value = serde_json::json!({
        "envelope_version": 1,
        "receipt_type": "governance",
        "context_digest": "a".repeat(64),
        "schema_digest": "b".repeat(64),
        "policy_digest": "c".repeat(64),
        "logical_time": 1000,
        "event_hash": "d".repeat(64),
        "payload": {"key": "value"}
    });
    // Canonicalize for the canonical form check
    vertrule_schemas::jcs::to_canon_bytes(&value)
        .map_err(|e| anyhow::anyhow!("canonicalization: {e}"))
}

vr_test!(
    fn test_valid_canonical_envelope_ingests() {
        let bytes = valid_canonical_envelope_bytes()?;
        let envelope = super::ingest_envelope(&bytes)?;
        assert_eq!(envelope.envelope_version, SchemaVersion::V1);
    }
);

vr_test!(
    fn test_malformed_json_rejected() {
        let bytes = b"not json at all";
        let Err(err) = super::ingest_envelope(bytes) else {
            anyhow::bail!("expected error, got Ok")
        };
        match err {
            VerifyError::MalformedJson { .. } => {}
            other => anyhow::bail!("expected MalformedJson, got: {other}"),
        }
    }
);

vr_test!(
    fn test_non_canonical_rejected() {
        // Pretty-printed JSON is not canonical
        let value = serde_json::json!({
            "envelope_version": 1,
            "receipt_type": "governance",
            "context_digest": "a".repeat(64),
            "schema_digest": "b".repeat(64),
            "policy_digest": "c".repeat(64),
            "logical_time": 1000,
            "event_hash": "d".repeat(64),
            "payload": {"key": "value"}
        });
        let pretty = serde_json::to_vec_pretty(&value)
            .map_err(|e| anyhow::anyhow!("serialize failed: {e}"))?;
        let Err(err) = super::ingest_envelope(&pretty) else {
            anyhow::bail!("expected error, got Ok")
        };
        match err {
            VerifyError::NonCanonical { .. } => {}
            other => anyhow::bail!("expected NonCanonical, got: {other}"),
        }
    }
);

vr_test!(
    fn test_unknown_field_rejected_through_ingestion() {
        let value = serde_json::json!({
            "envelope_version": 1,
            "receipt_type": "governance",
            "context_digest": "a".repeat(64),
            "schema_digest": "b".repeat(64),
            "policy_digest": "c".repeat(64),
            "logical_time": 1000,
            "event_hash": "d".repeat(64),
            "payload": {"key": "value"},
            "bogus": 42
        });
        let bytes = vertrule_schemas::jcs::to_canon_bytes(&value)
            .map_err(|e| anyhow::anyhow!("canon failed: {e}"))?;
        let Err(err) = super::ingest_envelope(&bytes) else {
            anyhow::bail!("expected error, got Ok")
        };
        match err {
            VerifyError::UnknownField { .. } => {}
            other => anyhow::bail!("expected UnknownField, got: {other}"),
        }
    }
);

vr_test!(
    fn test_non_canonical_chain_rejected() {
        // Build a valid envelope value
        let envelope = serde_json::json!({
            "context_digest": "a".repeat(64),
            "envelope_version": 1,
            "event_hash": "d".repeat(64),
            "logical_time": 1000,
            "payload": {"key": "value"},
            "policy_digest": "c".repeat(64),
            "receipt_type": "governance",
            "schema_digest": "b".repeat(64)
        });
        let array = serde_json::Value::Array(vec![envelope]);
        // Pretty-print to make it non-canonical
        let pretty = serde_json::to_vec_pretty(&array)
            .map_err(|e| anyhow::anyhow!("serialize failed: {e}"))?;
        let Err(err) = super::ingest_chain(&pretty) else {
            anyhow::bail!("expected error, got Ok")
        };
        match err {
            VerifyError::NonCanonical { .. } => {}
            other => anyhow::bail!("expected NonCanonical, got: {other}"),
        }
    }
);
