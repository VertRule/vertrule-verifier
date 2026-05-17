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
    let legacy_json = serde_json::to_string(&value).map_err(|e| VerifyError::Canon(format!("{e}")))?;
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
    assert!(hex.chars().all(|c: char| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
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
