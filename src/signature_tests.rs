//! Tests for Ed25519 signature verification.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use crate::test_support::vr_test;

use super::*;
use vertrule_schemas::DigestBytes;

/// Create a deterministic test signing key (no RNG).
fn test_signing_key() -> SigningKey {
    let seed: [u8; 32] = [42u8; 32];
    SigningKey::from_bytes(&seed)
}

/// Compute `key_id` from a verifying key (mirrors `ed25519::key_id` in `vertrule-crypto`).
fn compute_key_id(key: &ed25519_dalek::VerifyingKey) -> String {
    let hash = blake3::hash(key.as_bytes());
    hex::encode(&hash.as_bytes()[..12])
}

/// Sign a payload and return a complete `SignatureBundle` JSON value.
fn sign_payload(
    payload: &serde_json::Value,
    timestamp: &str,
) -> Result<serde_json::Value, anyhow::Error> {
    let sk = test_signing_key();
    let pk = sk.verifying_key();

    // Compute domain-separated receipt digest
    let receipt_digest = compute_receipt_digest(payload)?;

    // Construct canonical message
    let canonical_message = construct_canonical_message(&receipt_digest, timestamp);

    // Sign
    let sig = sk.sign(&canonical_message);

    let bundle = serde_json::json!({
        "alg": "Ed25519",
        "key_id": compute_key_id(&pk),
        "public_key_b64": base64::engine::general_purpose::STANDARD.encode(pk.as_bytes()),
        "signature_b64": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        "schema_version": "0.2",
        "digest_basis": "BLAKE3+JCS",
        "timestamp": timestamp,
    });

    Ok(bundle)
}

vr_test!(
    fn test_valid_signature_verifies() {
        let payload = serde_json::json!({"action": "governance_change", "version": 1});
        let timestamp = "2026-02-23T12:00:00Z";
        let bundle_json = sign_payload(&payload, timestamp)?;
        let bundle: SignatureBundle = serde_json::from_value(bundle_json)
            .map_err(|e| anyhow::anyhow!("deserialize bundle: {e}"))?;

        verify_signature(&payload, &bundle)
            .map_err(|e| anyhow::anyhow!("verification should pass: {e}"))?;
    }
);

vr_test!(
    fn test_tampered_payload_fails() {
        let payload = serde_json::json!({"action": "governance_change", "version": 1});
        let timestamp = "2026-02-23T12:00:00Z";
        let bundle_json = sign_payload(&payload, timestamp)?;
        let bundle: SignatureBundle = serde_json::from_value(bundle_json)
            .map_err(|e| anyhow::anyhow!("deserialize bundle: {e}"))?;

        // Tamper with the payload
        let tampered = serde_json::json!({"action": "governance_change", "version": 2});
        let result = verify_signature(&tampered, &bundle);
        match result {
            Err(VerifyError::SignatureInvalid { .. }) => {}
            other => anyhow::bail!("expected SignatureInvalid, got: {other:?}"),
        }
    }
);

vr_test!(
    fn test_wrong_algorithm_rejected() {
        let bundle_json = serde_json::json!({
            "alg": "RSA",
            "key_id": "a".repeat(24),
            "public_key_b64": "AAAA",
            "signature_b64": "AAAA",
            "schema_version": "0.2",
            "digest_basis": "BLAKE3+JCS",
            "timestamp": "2026-02-23T12:00:00Z",
        });
        let bundle: SignatureBundle = serde_json::from_value(bundle_json)
            .map_err(|e| anyhow::anyhow!("deserialize bundle: {e}"))?;
        let payload = serde_json::json!({});
        let result = verify_signature(&payload, &bundle);
        match result {
            Err(VerifyError::SignatureDataMalformed { reason }) => {
                assert!(reason.contains("unsupported algorithm"));
            }
            other => anyhow::bail!("expected SignatureDataMalformed, got: {other:?}"),
        }
    }
);

vr_test!(
    fn test_wrong_key_id_rejected() {
        let payload = serde_json::json!({"action": "test"});
        let timestamp = "2026-02-23T12:00:00Z";
        let mut bundle_json = sign_payload(&payload, timestamp)?;

        // Replace key_id with a wrong value
        bundle_json["key_id"] = serde_json::json!("b".repeat(24));

        let bundle: SignatureBundle = serde_json::from_value(bundle_json)
            .map_err(|e| anyhow::anyhow!("deserialize bundle: {e}"))?;
        let result = verify_signature(&payload, &bundle);
        match result {
            Err(VerifyError::SignatureInvalid { reason }) => {
                assert!(reason.contains("key_id mismatch"));
            }
            other => {
                anyhow::bail!("expected SignatureInvalid with key_id mismatch, got: {other:?}")
            }
        }
    }
);

vr_test!(
    fn test_receipt_digest_has_domain_separation() {
        let payload = serde_json::json!({"key": "value"});

        // Compute domain-separated digest (with prefix)
        let receipt_digest = compute_receipt_digest(&payload)?;

        // Compute plain BLAKE3 (no prefix) — what event_hash uses
        let canon_bytes = vertrule_schemas::jcs::to_canon_bytes(&payload)
            .map_err(|e| anyhow::anyhow!("canonicalization: {e}"))?;
        let plain_hash = blake3::hash(&canon_bytes);
        let plain_digest = DigestBytes::from_array(*plain_hash.as_bytes());

        // They must differ (domain separation changes the hash)
        assert_ne!(receipt_digest, plain_digest);
    }
);

vr_test!(
    fn test_receipt_digest_is_deterministic() {
        let payload = serde_json::json!({"key": "value"});
        let d1 = compute_receipt_digest(&payload)?;
        let d2 = compute_receipt_digest(&payload)?;
        assert_eq!(d1, d2);
    }
);

vr_test!(
    fn test_malformed_base64_rejected() {
        let bundle_json = serde_json::json!({
            "alg": "Ed25519",
            "key_id": "a".repeat(24),
            "public_key_b64": "not-valid-base64!!!",
            "signature_b64": "AAAA",
            "schema_version": "0.2",
            "digest_basis": "BLAKE3+JCS",
            "timestamp": "2026-02-23T12:00:00Z",
        });
        let bundle: SignatureBundle = serde_json::from_value(bundle_json)
            .map_err(|e| anyhow::anyhow!("deserialize bundle: {e}"))?;
        let payload = serde_json::json!({});
        let result = verify_signature(&payload, &bundle);
        match result {
            Err(VerifyError::SignatureDataMalformed { .. }) => {}
            other => anyhow::bail!("expected SignatureDataMalformed, got: {other:?}"),
        }
    }
);
