//! Tests for closure-committed bundle verification (ADR-040 transitive law).
//!
//! Canonical valid graph: pack (`pack.v0`) → model (`model.v0`) → provider
//! (`provider.v0`), with a [`ClosureManifest`] committing the dependency
//! closure `{model, provider}` and the root pack committing the manifest
//! digest. The mutation corpus is the falsifier the ADR's closure slice
//! requires.

use std::collections::{BTreeMap, BTreeSet};

use crate::result::VerificationStatus;
use crate::test_support::vr_test;

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
    let hash_hex = blake3::hash(&canon_bytes).to_hex().to_string();
    obj.insert("event_hash".to_string(), serde_json::json!(hash_hex));
    let canonical = crate::canon::typed_canon_string(&serde_json::Value::Object(obj))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok((canonical, hash_hex))
}

fn build_provider() -> anyhow::Result<(String, String)> {
    build_envelope(serde_json::json!({
        "payload_kind": "provider.v0",
        "provider_id": "anthropic",
        "support_set": [
            {"member_kind": "evidence_digest", "id": "soc2", "digest": "f".repeat(64)}
        ]
    }))
}

fn build_model(provider_hash: &str) -> anyhow::Result<(String, String)> {
    build_envelope(serde_json::json!({
        "payload_kind": "model.v0",
        "model_id": "claude-opus-4-8",
        "support_set": [{
            "member_kind": "typed_receipt_dependency",
            "event_hash": provider_hash,
            "relation": "depends_on",
            "role": "maker",
            "target_schema": "provider.v0"
        }]
    }))
}

/// Build a closure manifest over `deps`, returning `(manifest_value,
/// manifest_digest_hex)`. `deps` are sorted into the canonical list.
fn build_manifest(deps: &[&str]) -> anyhow::Result<(serde_json::Value, String)> {
    let mut sorted: Vec<String> = deps.iter().map(|s| (*s).to_string()).collect();
    sorted.sort();
    let body = serde_json::json!({
        "schema": "vr.closure_manifest.v0",
        "receipt_closure": sorted,
        "dependency_count": sorted.len(),
    });
    let canon = crate::canon::typed_canon_bytes(&body).map_err(|e| anyhow::anyhow!("{e}"))?;
    let digest = blake3::hash(&canon).to_hex().to_string();
    let mut manifest = body;
    manifest["manifest_digest"] = serde_json::json!(digest);
    Ok((manifest, digest))
}

fn build_pack(manifest_digest: &str, model_hash: &str) -> anyhow::Result<(String, String)> {
    build_envelope(serde_json::json!({
        "payload_kind": "pack.v0",
        "pack_id": "acme-deploy",
        "closure_manifest_digest": manifest_digest,
        "support_set": [{
            "member_kind": "typed_receipt_dependency",
            "event_hash": model_hash,
            "relation": "depends_on",
            "role": "host",
            "target_schema": "model.v0"
        }]
    }))
}

/// Assemble the canonical valid bundle and return its bytes.
fn build_valid_bundle() -> anyhow::Result<Vec<u8>> {
    let (provider, provider_hash) = build_provider()?;
    let (model, model_hash) = build_model(&provider_hash)?;
    let (manifest, manifest_digest) = build_manifest(&[&model_hash, &provider_hash])?;
    let (pack, _) = build_pack(&manifest_digest, &model_hash)?;
    let bundle = serde_json::json!({
        "_format": "vr-layered-bundle/v1",
        "root_canonical": pack,
        "manifest": manifest,
        "receipts": [model, provider],
    });
    serde_json::to_vec(&bundle).map_err(|e| anyhow::anyhow!("{e}"))
}

vr_test!(
    fn valid_closure_bundle_accepts() {
        let bytes = build_valid_bundle()?;
        let result = super::verify_closure_bundle(&bytes);
        assert_eq!(
            result.status,
            VerificationStatus::Valid,
            "{:?}",
            result.errors
        );
        assert!(result.manifest_digest_ok);
        assert!(result.closure_complete);
        assert!(!result.cycle_detected);
        assert_eq!(result.closure_size, 2);
    }
);

vr_test!(
    fn tampered_manifest_digest_rejected() {
        let (provider, provider_hash) = build_provider()?;
        let (model, model_hash) = build_model(&provider_hash)?;
        let (mut manifest, manifest_digest) = build_manifest(&[&model_hash, &provider_hash])?;
        // Flip the manifest's self-digest; the root still commits the real one.
        manifest["manifest_digest"] = serde_json::json!("0".repeat(64));
        let (pack, _) = build_pack(&manifest_digest, &model_hash)?;
        let bundle = serde_json::json!({
            "_format": "vr-layered-bundle/v1",
            "root_canonical": pack,
            "manifest": manifest,
            "receipts": [model, provider],
        });
        let bytes = serde_json::to_vec(&bundle).map_err(|e| anyhow::anyhow!("{e}"))?;
        let result = super::verify_closure_bundle(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert!(!result.manifest_digest_ok);
    }
);

vr_test!(
    fn closure_missing_reachable_rejected() {
        // Manifest omits the provider, which is still reachable model→provider.
        let (provider, provider_hash) = build_provider()?;
        let (model, model_hash) = build_model(&provider_hash)?;
        let (manifest, manifest_digest) = build_manifest(&[&model_hash])?;
        let (pack, _) = build_pack(&manifest_digest, &model_hash)?;
        let bundle = serde_json::json!({
            "_format": "vr-layered-bundle/v1",
            "root_canonical": pack,
            "manifest": manifest,
            "receipts": [model, provider],
        });
        let bytes = serde_json::to_vec(&bundle).map_err(|e| anyhow::anyhow!("{e}"))?;
        let result = super::verify_closure_bundle(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert!(!result.closure_complete);
    }
);

vr_test!(
    fn closure_extra_unreachable_rejected() {
        // Manifest lists a node that is not reachable from the root.
        let (provider, provider_hash) = build_provider()?;
        let (model, model_hash) = build_model(&provider_hash)?;
        let bogus = "e".repeat(64);
        let (manifest, manifest_digest) = build_manifest(&[&model_hash, &provider_hash, &bogus])?;
        let (pack, _) = build_pack(&manifest_digest, &model_hash)?;
        let bundle = serde_json::json!({
            "_format": "vr-layered-bundle/v1",
            "root_canonical": pack,
            "manifest": manifest,
            "receipts": [model, provider],
        });
        let bytes = serde_json::to_vec(&bundle).map_err(|e| anyhow::anyhow!("{e}"))?;
        let result = super::verify_closure_bundle(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert!(!result.closure_complete);
    }
);

vr_test!(
    fn missing_dependency_node_rejected() {
        // The model is reachable but its provider is not supplied.
        let (_, provider_hash) = build_provider()?;
        let (model, model_hash) = build_model(&provider_hash)?;
        let (manifest, manifest_digest) = build_manifest(&[&model_hash, &provider_hash])?;
        let (pack, _) = build_pack(&manifest_digest, &model_hash)?;
        let bundle = serde_json::json!({
            "_format": "vr-layered-bundle/v1",
            "root_canonical": pack,
            "manifest": manifest,
            "receipts": [model], // provider omitted
        });
        let bytes = serde_json::to_vec(&bundle).map_err(|e| anyhow::anyhow!("{e}"))?;
        let result = super::verify_closure_bundle(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);
    }
);

vr_test!(
    fn reorder_receipts_is_byte_irrelevant() {
        // Transport order of supplied receipts must not change the verdict.
        let (provider, provider_hash) = build_provider()?;
        let (model, model_hash) = build_model(&provider_hash)?;
        let (manifest, manifest_digest) = build_manifest(&[&model_hash, &provider_hash])?;
        let (pack, _) = build_pack(&manifest_digest, &model_hash)?;
        let bundle = serde_json::json!({
            "_format": "vr-layered-bundle/v1",
            "root_canonical": pack,
            "manifest": manifest,
            "receipts": [provider, model], // reversed
        });
        let bytes = serde_json::to_vec(&bundle).map_err(|e| anyhow::anyhow!("{e}"))?;
        let result = super::verify_closure_bundle(&bytes);
        assert_eq!(
            result.status,
            VerificationStatus::Valid,
            "reorder: {:?}",
            result.errors
        );
    }
);

// Content-addressed receipts make a *real* dependency cycle unconstructable
// (each event_hash must be computed before it can be referenced). The cycle
// guard is therefore exercised directly against the private walk with a
// synthetic mutually-referential index.
vr_test!(
    fn cycle_over_depends_on_is_detected() {
        let a = "1".repeat(64);
        let b = "2".repeat(64);
        let edge = |target: &str| super::Node {
            payload_kind: "model.v0".to_string(),
            support_set: vec![vertrule_schemas::SupportMember::TypedReceiptDependency {
                event_hash: target.to_string(),
                relation: vertrule_schemas::DependencyRelation::DependsOn,
                role: vertrule_schemas::DependencyRole::Maker,
                target_schema: "model.v0".to_string(),
            }],
            verify_status: VerificationStatus::Valid,
            verify_detail: String::new(),
        };
        let mut index: BTreeMap<String, super::Node> = BTreeMap::new();
        index.insert(a.clone(), edge(&b));
        index.insert(b, edge(&a));

        let mut reachable: BTreeSet<String> = BTreeSet::new();
        let mut on_stack: BTreeSet<String> = BTreeSet::new();
        let mut edge_checks = Vec::new();
        let mut cycle = false;
        super::walk(
            &a,
            &index,
            &mut reachable,
            &mut on_stack,
            &mut edge_checks,
            &mut cycle,
        );
        assert!(
            cycle,
            "mutually-referential depends_on edges must trip the cycle guard"
        );
    }
);
