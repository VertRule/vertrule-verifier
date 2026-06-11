//! Tests for decision pack verification (the support-set walk).

use crate::result::VerificationStatus;
use crate::test_support::vr_test;

use super::MemberStatus;

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
    // Sealed constructor (byte-identical to raw BLAKE3 over the canonical
    // bytes) — keeps the raw-BLAKE3 taxonomy guard's zero-site invariant.
    let hash_hex = crate::identity::GenericByteDigest::from_bytes(&canon_bytes).to_hex_string();
    obj.insert("event_hash".to_string(), serde_json::json!(hash_hex));
    let canonical = crate::canon::typed_canon_string(&serde_json::Value::Object(obj))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok((canonical, hash_hex))
}

/// A depended-on receipt plus a decision committing to it and the three
/// committed-assumption member kinds.
fn build_pack() -> anyhow::Result<(serde_json::Value, String)> {
    let (depended, depended_hash) = build_envelope(serde_json::json!({"step": "prior"}))?;
    let decision_payload = serde_json::json!({
        "payload_kind": "decision.v0",
        "verdict": {"kind": "allow"},
        "support_set": [
            {"member_kind": "cited_link", "id": "site", "url": "https://example.org/x"},
            {"member_kind": "depended_on_receipt", "event_hash": depended_hash},
            {"member_kind": "evidence_digest", "id": "dpa", "digest": "f".repeat(64)},
            {"member_kind": "selector_value", "key": "content_length", "value": "10"}
        ]
    });
    let (decision, _) = build_envelope(decision_payload)?;
    let pack = serde_json::json!({
        "_format": "vr-decision-pack/v1",
        "decision_canonical": decision,
        "depended_on": [depended]
    });
    Ok((pack, depended_hash))
}

vr_test!(
    fn malformed_json_rejected() {
        let result = super::verify_decision_pack(b"not json");
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert!(!result.errors.is_empty());
    }
);

vr_test!(
    fn wrong_format_rejected() {
        let pack = serde_json::json!({
            "_format": "unknown/v9",
            "decision_canonical": "{}",
            "depended_on": []
        });
        let bytes = serde_json::to_vec(&pack).map_err(|e| anyhow::anyhow!("{e}"))?;
        let result = super::verify_decision_pack(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("unsupported pack format")));
    }
);

vr_test!(
    fn non_decision_payload_rejected() {
        let (envelope, _) = build_envelope(serde_json::json!({"key": "value"}))?;
        let pack = serde_json::json!({
            "_format": "vr-decision-pack/v1",
            "decision_canonical": envelope,
            "depended_on": []
        });
        let bytes = serde_json::to_vec(&pack).map_err(|e| anyhow::anyhow!("{e}"))?;
        let result = super::verify_decision_pack(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("not a decision payload")));
    }
);

vr_test!(
    fn full_pack_walks_valid() {
        let (pack, depended_hash) = build_pack()?;
        let bytes = serde_json::to_vec(&pack).map_err(|e| anyhow::anyhow!("{e}"))?;
        let result = super::verify_decision_pack(&bytes);
        assert_eq!(
            result.status,
            VerificationStatus::Valid,
            "{:?}",
            result.errors
        );
        assert_eq!(result.verdict_kind.as_deref(), Some("allow"));
        assert_eq!(result.member_checks.len(), 4);

        let receipt_check = result
            .member_checks
            .iter()
            .find(|c| c.member_kind == "depended_on_receipt")
            .ok_or_else(|| anyhow::anyhow!("missing receipt check"))?;
        assert_eq!(receipt_check.status, MemberStatus::Verified);
        assert_eq!(receipt_check.reference, depended_hash);

        let committed = result
            .member_checks
            .iter()
            .filter(|c| c.status == MemberStatus::Committed)
            .count();
        assert_eq!(committed, 3, "link, evidence, and selector are committed");
    }
);

vr_test!(
    fn missing_depended_on_receipt_is_out() {
        let (mut pack, _) = build_pack()?;
        pack["depended_on"] = serde_json::json!([]);
        let bytes = serde_json::to_vec(&pack).map_err(|e| anyhow::anyhow!("{e}"))?;
        let result = super::verify_decision_pack(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);
        let receipt_check = result
            .member_checks
            .iter()
            .find(|c| c.member_kind == "depended_on_receipt")
            .ok_or_else(|| anyhow::anyhow!("missing receipt check"))?;
        assert_eq!(receipt_check.status, MemberStatus::Missing);
        assert!(result.errors.iter().any(|e| e.contains("is OUT")));
    }
);

vr_test!(
    fn tampered_depended_on_receipt_is_out() {
        let (mut pack, _) = build_pack()?;
        let supplied = pack["depended_on"][0]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing supplied receipt"))?
            .to_string();
        // Tamper inside the supplied receipt's payload: event_hash no
        // longer recomputes, so the supplied receipt fails verification.
        let tampered = supplied.replace("prior", "priorX");
        pack["depended_on"] = serde_json::json!([tampered]);
        let bytes = serde_json::to_vec(&pack).map_err(|e| anyhow::anyhow!("{e}"))?;
        let result = super::verify_decision_pack(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);
        let receipt_check = result
            .member_checks
            .iter()
            .find(|c| c.member_kind == "depended_on_receipt")
            .ok_or_else(|| anyhow::anyhow!("missing receipt check"))?;
        assert_eq!(receipt_check.status, MemberStatus::Failed);
    }
);

vr_test!(
    fn malformed_evidence_digest_is_out() {
        let decision_payload = serde_json::json!({
            "payload_kind": "decision.v0",
            "verdict": {"kind": "allow"},
            "support_set": [
                {"member_kind": "evidence_digest", "id": "dpa", "digest": "NOT-HEX"}
            ]
        });
        let (decision, _) = build_envelope(decision_payload)?;
        let pack = serde_json::json!({
            "_format": "vr-decision-pack/v1",
            "decision_canonical": decision,
            "depended_on": []
        });
        let bytes = serde_json::to_vec(&pack).map_err(|e| anyhow::anyhow!("{e}"))?;
        let result = super::verify_decision_pack(&bytes);
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert_eq!(result.member_checks[0].status, MemberStatus::Failed);
    }
);

vr_test!(
    fn empty_support_set_holds_on_envelope_alone() {
        let decision_payload = serde_json::json!({
            "payload_kind": "decision.v0",
            "verdict": {"kind": "no_match"},
            "support_set": []
        });
        let (decision, _) = build_envelope(decision_payload)?;
        let pack = serde_json::json!({
            "_format": "vr-decision-pack/v1",
            "decision_canonical": decision,
            "depended_on": []
        });
        let bytes = serde_json::to_vec(&pack).map_err(|e| anyhow::anyhow!("{e}"))?;
        let result = super::verify_decision_pack(&bytes);
        assert_eq!(result.status, VerificationStatus::Valid);
        assert_eq!(result.verdict_kind.as_deref(), Some("no_match"));
        assert!(result.member_checks.is_empty());
    }
);

vr_test!(
    fn result_serializes_canonically() {
        let (pack, _) = build_pack()?;
        let bytes = serde_json::to_vec(&pack).map_err(|e| anyhow::anyhow!("{e}"))?;
        let result = super::verify_decision_pack(&bytes);
        let canon = result
            .to_canon_string()
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        assert!(canon.contains("\"status\":\"VALID\""));
        assert!(canon.contains("\"member_kind\":\"depended_on_receipt\""));
    }
);
