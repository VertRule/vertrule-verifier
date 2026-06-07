//! Byte-stability tests for verifier-owned sealed identity newtypes.

use super::{PayloadEventDigest, SidecarDigest};
use crate::error::VerifyError;

#[test]
fn sidecar_digest_byte_stable_with_legacy_path() -> Result<(), VerifyError> {
    let value = serde_json::json!({"a": 1, "b": [2, 3]});

    // Sealed path.
    let sealed = SidecarDigest::recompute_from_value(&value)?;
    let sealed_hex = sealed.to_hex_string();

    // Legacy-equivalent path: what `bundle.rs::digest_canonical_value`
    // computed pre-Gate-2.
    // ALLOW-JCS-SPEC: byte-stability assertion against legacy bypass
    let legacy_json =
        serde_json::to_string(&value).map_err(|e| VerifyError::Canon(format!("{e}")))?;
    let legacy_canonical = vr_jcs::to_canon_string_from_str(&legacy_json)
        .map_err(|e| VerifyError::Canon(format!("{e}")))?;
    let legacy_hash = blake3::hash(legacy_canonical.as_bytes());
    let legacy_hex = legacy_hash.to_hex().to_string();

    assert_eq!(
        sealed_hex, legacy_hex,
        "SidecarDigest::recompute_from_value must byte-equal legacy BLAKE3(JCS(value))",
    );
    Ok(())
}

#[test]
fn sidecar_digest_algorithm_name_is_blake3_untagged() -> Result<(), VerifyError> {
    let value = serde_json::json!({"x": 1});
    let sealed = SidecarDigest::recompute_from_value(&value)?;
    assert_eq!(sealed.algorithm_name(), "blake3-untagged");
    Ok(())
}

#[test]
fn sidecar_digest_bytes_length_is_32() -> Result<(), VerifyError> {
    let value = serde_json::json!({"x": 1});
    let sealed = SidecarDigest::recompute_from_value(&value)?;
    assert_eq!(sealed.bytes().len(), 32);
    Ok(())
}

#[test]
fn sidecar_digest_to_hex_is_lowercase_64_chars() -> Result<(), VerifyError> {
    let value = serde_json::json!({"x": 1});
    let sealed = SidecarDigest::recompute_from_value(&value)?;
    let hex = sealed.to_hex_string();
    assert_eq!(hex.len(), 64);
    assert!(hex
        .chars()
        .all(|c: char| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    Ok(())
}

// ── PayloadEventDigest ────────────────────────────────────────────

#[test]
fn payload_event_digest_byte_stable_with_legacy_raw_byte_path() -> Result<(), VerifyError> {
    let payload = serde_json::json!({"hello": "world", "value": 42});

    // Sealed path: via typed Value.
    let sealed = PayloadEventDigest::recompute_from_payload_value(&payload)?;

    // Legacy-equivalent path: what `rbh.rs::verify_event_hash` did
    // pre-Gate-2 (serialize to vec, strict-parse + canonicalize via
    // `to_canon_bytes_from_slice`, then `blake3::hash`).
    // ALLOW-JCS-SPEC: byte-stability assertion against legacy bypass
    let legacy_json_bytes =
        serde_json::to_vec(&payload).map_err(|e| VerifyError::Canon(format!("{e}")))?;
    let legacy_canon_bytes = vr_jcs::to_canon_bytes_from_slice(&legacy_json_bytes)
        .map_err(|e| VerifyError::Canon(format!("{e}")))?;
    let legacy_hash = blake3::hash(&legacy_canon_bytes);

    assert_eq!(
        sealed.bytes(),
        legacy_hash.as_bytes(),
        "PayloadEventDigest::recompute_from_payload_value must byte-equal \
         BLAKE3(JCS(payload)) computed via the legacy raw-byte path",
    );
    Ok(())
}

#[test]
fn payload_event_digest_algorithm_name_is_blake3_untagged() -> Result<(), VerifyError> {
    let payload = serde_json::json!({"x": 1});
    let sealed = PayloadEventDigest::recompute_from_payload_value(&payload)?;
    assert_eq!(sealed.algorithm_name(), "blake3-untagged");
    Ok(())
}

// ── Layer A G2: blake3_untagged helper cross-copy equivalence ──────────
//
// The verifier copy (SidecarDigest::recompute_from_value) must produce the
// committed golden digests, byte-equivalent to the schemas and crypto
// copies. Source of truth:
// docs/audits/junk-drawer-inventory/fixtures/receipt-identity/goldens.json
#[test]
fn g2_blake3_untagged_helper_equivalence() -> Result<(), VerifyError> {
    let cases: [(serde_json::Value, &str); 5] = [
        (
            serde_json::json!({"a": 1, "b": 2}),
            "8e80439b77ac62d4194499edd46684c479da3aa1ac80dd5511468efae049166e",
        ),
        (
            serde_json::json!({"b": 2, "a": 1}),
            "8e80439b77ac62d4194499edd46684c479da3aa1ac80dd5511468efae049166e",
        ),
        (
            serde_json::json!({"z": [3, 1, 2], "a": {"k": "v"}}),
            "5ef47de6cdb1c8586547526ee1fb7726321452f65ce50ba1abef1d3bf650a08c",
        ),
        (
            serde_json::json!({"n": 9_007_199_254_740_991_i64}),
            "6f3adc03614205e4ef7d378c51d584a691c60baa2abcdfea5325018261a28fb6",
        ),
        (
            serde_json::json!({"s": "café\n\"q\""}),
            "770f998755f9ac91974ea4dc2e23d34144f5cd0ad3238c3403a0a1e797c26a3a",
        ),
    ];

    for (value, expected) in &cases {
        let sealed = SidecarDigest::recompute_from_value(value)?;
        assert_eq!(
            sealed.to_hex_string(),
            *expected,
            "verifier SidecarDigest drifted from golden"
        );
    }
    Ok(())
}
