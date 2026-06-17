//! Tests for layered-pack verification (ADR-040 typed-edge composition law).
//!
//! Canonical valid graph: one provider receipt (`provider.v0`) → one model
//! receipt (`model.v0`) via a single typed `maker` edge. The mutation
//! corpus around it is the falsifier the ADR's first slice requires.

use crate::result::VerificationStatus;
use crate::test_support::vr_test;

use super::EdgeStatus;

/// Build a valid canonical envelope with the given payload, returning
/// `(canonical_json, event_hash_hex)`.
fn build_envelope(payload: serde_json::Value) -> anyhow::Result<(String, String)> {
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
    obj.insert("receipt_type".to_string(), serde_json::json!("event"));
    obj.insert(
        "schema_digest".to_string(),
        serde_json::json!("b".repeat(64)),
    );

    let canon_bytes = crate::canon::typed_canon_bytes(&serde_json::Value::Object(obj.clone()))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let hash_hex = crate::identity::GenericByteDigest::from_bytes(&canon_bytes).to_hex_string();
    obj.insert("event_hash".to_string(), serde_json::json!(hash_hex));
    let canonical = crate::canon::typed_canon_string(&serde_json::Value::Object(obj))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok((canonical, hash_hex))
}

/// A provider receipt carrying one evidence member.
fn build_provider() -> anyhow::Result<(String, String)> {
    build_envelope(serde_json::json!({
        "payload_kind": "provider.v0",
        "provider_id": "anthropic",
        "support_set": [
            {"member_kind": "evidence_digest", "id": "soc2", "digest": "f".repeat(64)}
        ]
    }))
}

/// A model receipt depending on `provider_hash` via a typed edge with the
/// given `role` and `target_schema`.
fn build_model(
    provider_hash: &str,
    role: &str,
    target_schema: &str,
) -> anyhow::Result<(String, String)> {
    build_envelope(serde_json::json!({
        "payload_kind": "model.v0",
        "model_id": "claude-opus-4-8",
        "support_set": [
            {
                "member_kind": "typed_receipt_dependency",
                "event_hash": provider_hash,
                "relation": "depends_on",
                "role": role,
                "target_schema": target_schema
            }
        ]
    }))
}

/// Assemble a `vr-layered-pack/v1` byte string.
fn build_pack(root: &str, receipts: &[&str]) -> anyhow::Result<Vec<u8>> {
    let pack = serde_json::json!({
        "_format": "vr-layered-pack/v1",
        "root_canonical": root,
        "receipts": receipts,
    });
    serde_json::to_vec(&pack).map_err(|e| anyhow::anyhow!("{e}"))
}

vr_test!(
    fn valid_provider_model_graph_accepts() {
        let (provider, provider_hash) = build_provider()?;
        let (model, _) = build_model(&provider_hash, "maker", "provider.v0")?;
        let bytes = build_pack(&model, &[&provider])?;
        let result = super::verify_layered_pack(&bytes);
        assert_eq!(
            result.status,
            VerificationStatus::Valid,
            "{:?}",
            result.errors
        );
        assert_eq!(result.root_kind.as_deref(), Some("model.v0"));
        assert_eq!(result.edge_checks.len(), 1);
        assert_eq!(result.edge_checks[0].status, EdgeStatus::Resolved);
        assert_eq!(result.edge_checks[0].role.as_deref(), Some("maker"));
    }
);

vr_test!(
    fn role_swap_changes_model_event_hash() {
        let (_, provider_hash) = build_provider()?;
        let (_, maker_hash) = build_model(&provider_hash, "maker", "provider.v0")?;
        let (_, host_hash) = build_model(&provider_hash, "host", "provider.v0")?;
        assert_ne!(
            maker_hash, host_hash,
            "swapping the typed edge role must change the model event_hash"
        );
    }
);

vr_test!(
    fn untyped_edge_in_layered_receipt_rejected() {
        let (provider, provider_hash) = build_provider()?;
        let (model, _) = build_envelope(serde_json::json!({
            "payload_kind": "model.v0",
            "model_id": "claude-opus-4-8",
            "support_set": [
                {"member_kind": "depended_on_receipt", "event_hash": provider_hash}
            ]
        }))?;
        let bytes = build_pack(&model, &[&provider])?;
        let result = super::verify_layered_pack(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert_eq!(result.edge_checks.len(), 1);
        assert_eq!(result.edge_checks[0].status, EdgeStatus::UntypedEdge);
    }
);

vr_test!(
    fn wrong_target_schema_rejected() {
        let (provider, provider_hash) = build_provider()?;
        // Edge claims the target is a model, but the supplied receipt is a provider.
        let (model, _) = build_model(&provider_hash, "maker", "model.v0")?;
        let bytes = build_pack(&model, &[&provider])?;
        let result = super::verify_layered_pack(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert_eq!(result.edge_checks[0].status, EdgeStatus::SchemaMismatch);
    }
);

vr_test!(
    fn missing_provider_node_rejected() {
        let (_, provider_hash) = build_provider()?;
        let (model, _) = build_model(&provider_hash, "maker", "provider.v0")?;
        let bytes = build_pack(&model, &[])?;
        let result = super::verify_layered_pack(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert_eq!(result.edge_checks[0].status, EdgeStatus::Missing);
    }
);

vr_test!(
    fn non_layered_root_rejected() {
        let (decision, _) = build_envelope(serde_json::json!({
            "payload_kind": "decision.v0",
            "verdict": {"kind": "allow"},
            "support_set": []
        }))?;
        let bytes = build_pack(&decision, &[])?;
        let result = super::verify_layered_pack(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("not a layered-family receipt")));
    }
);

vr_test!(
    fn wrong_format_rejected() {
        let pack = serde_json::json!({
            "_format": "unknown/v9",
            "root_canonical": "{}",
            "receipts": []
        });
        let bytes = serde_json::to_vec(&pack).map_err(|e| anyhow::anyhow!("{e}"))?;
        let result = super::verify_layered_pack(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("unsupported pack format")));
    }
);
