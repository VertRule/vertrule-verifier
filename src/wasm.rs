//! WASM bindings for the `vertrule-verifier` public verification API.
//!
//! Thin wrappers over the canonical verification functions.
//! All verification semantics live in the core modules — this module
//! only handles the `String` ↔ `&[u8]` boundary for browser use.
//!
//! ## Exported functions
//!
//! | Function | Input | Output |
//! |----------|-------|--------|
//! | [`verify_receipt_json`] | Receipt envelope JSON (string) | `VerificationResult` as JCS-canonical JSON |
//! | [`verify_chain_json`] | Receipt chain JSON array (string) | `VerificationResult` as JCS-canonical JSON |
//! | [`verify_signed_receipt_json`] | Receipt JSON + signature bundle JSON | `VerificationResult` as JCS-canonical JSON |
//!
//! All functions return JCS-canonical JSON. They never panic — malformed input
//! produces an `INVALID` result with descriptive errors.

use wasm_bindgen::prelude::*;

use crate::result::VerificationResult;

/// Serialize a `VerificationResult` to JCS-canonical JSON.
///
/// Falls back to `serde_json::to_string` if canonicalization fails,
/// preserving fail-closed semantics (the result still reaches the caller).
fn result_to_json(result: &VerificationResult) -> String {
    match result.to_canon_string() {
        Ok(s) => s,
        Err(e) => error_json(&format!("canonicalization error: {e}")),
    }
}

/// Produce a minimal JCS-canonical error JSON when result serialization fails.
///
/// This is a last-resort fallback — it should never be reached in practice.
/// Serializes via `serde_json`, then canonicalizes via `vr_jcs`. If either
/// step fails, falls back to a static JCS-canonical string.
fn error_json(message: &str) -> String {
    #[derive(serde::Serialize)]
    struct FallbackError<'a> {
        errors: [&'a str; 1],
        status: &'a str,
    }
    // Static fallback is pre-verified JCS-canonical (keys in lex order, no whitespace).
    const STATIC_FALLBACK: &str = r#"{"errors":["internal verifier error"],"status":"INVALID"}"#;

    let payload = FallbackError {
        errors: [message],
        status: "INVALID",
    };
    let Ok(json_str) = serde_json::to_string(&payload) else {
        return STATIC_FALLBACK.to_string();
    };
    match vr_jcs::to_canon_string_from_str(&json_str) {
        Ok(s) => s,
        Err(_) => STATIC_FALLBACK.to_string(),
    }
}

/// Verify a single receipt envelope.
///
/// Accepts the receipt envelope as a JSON string.
/// Returns a `VerificationResult` serialized as JCS-canonical JSON.
///
/// This function never throws. Malformed input produces an `INVALID` result.
#[must_use]
#[wasm_bindgen]
pub fn verify_receipt_json(receipt_json: &str) -> String {
    let result = crate::verify_receipt(receipt_json.as_bytes());
    result_to_json(&result)
}

/// Verify a chain of receipt envelopes.
///
/// Accepts the chain as a JSON array string.
/// Returns a `VerificationResult` serialized as JCS-canonical JSON.
///
/// This function never throws. Malformed input produces an `INVALID` result.
#[must_use]
#[wasm_bindgen]
pub fn verify_chain_json(chain_json: &str) -> String {
    let result = crate::verify_receipt_chain(chain_json.as_bytes());
    result_to_json(&result)
}

/// Verify a signed receipt envelope.
///
/// Accepts the receipt envelope JSON and signature bundle JSON as separate strings.
/// Returns a `VerificationResult` serialized as JCS-canonical JSON.
///
/// This function never throws. Malformed input produces an `INVALID` result.
#[must_use]
#[wasm_bindgen]
pub fn verify_signed_receipt_json(receipt_json: &str, signature_json: &str) -> String {
    let result = crate::verify_signed_receipt(receipt_json.as_bytes(), signature_json.as_bytes());
    result_to_json(&result)
}

/// Compute the BLAKE3 digest of arbitrary bytes, returned as a 64-char hex string.
///
/// Useful for the website to compute digests client-side for display
/// without reimplementing BLAKE3 in JavaScript.
#[must_use]
#[wasm_bindgen]
pub fn digest_hex(input: &[u8]) -> String {
    let hash = blake3::hash(input);
    hex::encode(hash.as_bytes())
}

/// Return the verifier's schema profile version.
///
/// Allows the website to display which profile version the WASM verifier uses,
/// ensuring transparency about verification semantics.
#[must_use]
#[wasm_bindgen]
pub fn verifier_version() -> String {
    crate::schema_profile::PROFILE_VERSION.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_receipt_json_returns_valid_for_good_input() {
        // Build the envelope without event_hash first
        let payload = serde_json::json!({"key": "value"});

        let mut obj = serde_json::Map::new();
        obj.insert(
            "context_digest".to_string(),
            serde_json::json!("a".repeat(64)),
        );
        obj.insert("envelope_version".to_string(), serde_json::json!(1));
        obj.insert("logical_time".to_string(), serde_json::json!(1000));
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

        // event_hash = BLAKE3(JCS(envelope \ {event_hash}))
        let Some(canon_bytes) =
            crate::canon::typed_canon_bytes(&serde_json::Value::Object(obj.clone())).ok()
        else {
            return;
        };
        let hash = blake3::hash(&canon_bytes);
        let event_hash = hex::encode(hash.as_bytes());

        obj.insert("event_hash".to_string(), serde_json::json!(&event_hash));

        let value = serde_json::Value::Object(obj);
        let Ok(input) = crate::canon::typed_canon_string(&value) else {
            return;
        };

        let output = verify_receipt_json(&input);
        assert!(output.contains("\"status\":\"VALID\""), "got: {output}");
        assert!(
            output.contains("\"all_hashes_match\":true"),
            "got: {output}",
        );
    }

    #[test]
    fn verify_receipt_json_returns_invalid_for_malformed() {
        let output = verify_receipt_json("not valid json");
        assert!(output.contains("\"status\":\"INVALID\""), "got: {output}");
        assert!(output.contains("\"errors\""), "got: {output}");
    }

    #[test]
    fn verify_chain_json_returns_valid_for_empty() {
        let output = verify_chain_json("[]");
        assert!(output.contains("\"status\":\"VALID\""), "got: {output}");
    }

    #[test]
    fn verify_chain_json_returns_invalid_for_non_array() {
        let output = verify_chain_json("{}");
        assert!(output.contains("\"status\":\"INVALID\""), "got: {output}");
    }

    #[test]
    fn verify_signed_receipt_json_returns_invalid_for_bad_sig() {
        let output = verify_signed_receipt_json("{}", "{}");
        assert!(output.contains("\"status\":\"INVALID\""), "got: {output}");
    }

    #[test]
    fn verify_signed_receipt_json_key_id_consistent_independent_of_sig() {
        // Build a valid envelope
        let payload = serde_json::json!({"key": "value"});
        let mut obj = serde_json::Map::new();
        obj.insert("context_digest".to_string(), serde_json::json!("a".repeat(64)));
        obj.insert("envelope_version".to_string(), serde_json::json!(1));
        obj.insert("logical_time".to_string(), serde_json::json!(1000));
        obj.insert("payload".to_string(), payload);
        obj.insert("policy_digest".to_string(), serde_json::json!("c".repeat(64)));
        obj.insert("receipt_type".to_string(), serde_json::json!("governance"));
        obj.insert("schema_digest".to_string(), serde_json::json!("b".repeat(64)));

        let Some(canon_bytes) =
            crate::canon::typed_canon_bytes(&serde_json::Value::Object(obj.clone())).ok()
        else {
            return;
        };
        let hash = blake3::hash(&canon_bytes);
        obj.insert("event_hash".to_string(), serde_json::json!(hex::encode(hash.as_bytes())));
        let value = serde_json::Value::Object(obj);
        let Ok(receipt_json) = crate::canon::typed_canon_string(&value) else {
            return;
        };

        // Build a sig bundle with correct key_id/public_key but bad signature
        let seed = [77u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key();
        let pk_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            pk.as_bytes(),
        );
        let pk_hash = blake3::hash(pk.as_bytes());
        let key_id = hex::encode(&pk_hash.as_bytes()[..12]);
        let sig_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &[0u8; 64],
        );
        let bundle = serde_json::json!({
            "alg": "Ed25519",
            "key_id": key_id,
            "public_key_b64": pk_b64,
            "signature_b64": sig_b64,
            "schema_version": "0.2",
            "digest_basis": "BLAKE3+JCS",
            "timestamp": "2026-01-01T00:00:00Z"
        });
        let sig_json = serde_json::to_string(&bundle).ok();
        let Some(ref sig_str) = sig_json else {
            return;
        };

        let output = verify_signed_receipt_json(&receipt_json, sig_str);
        assert!(output.contains("\"key_id_consistent\":true"), "key_id matches public_key — got: {output}");
        assert!(output.contains("\"valid\":false"), "bad signature — got: {output}");
    }

    #[test]
    fn digest_hex_returns_64_char_hex() {
        let result = digest_hex(b"hello");
        assert_eq!(result.len(), 64);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn digest_hex_is_deterministic() {
        let a = digest_hex(b"test input");
        let b = digest_hex(b"test input");
        assert_eq!(a, b);
    }

    #[test]
    fn verifier_version_returns_nonempty() {
        let v = verifier_version();
        assert!(!v.is_empty());
    }

    #[test]
    fn error_json_produces_valid_json() {
        let json = error_json("test error");
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json);
        assert!(parsed.is_ok(), "error_json must produce valid JSON");
    }

    #[test]
    fn error_json_escapes_quotes() {
        let json = error_json("a \"quoted\" error");
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json);
        assert!(parsed.is_ok(), "error_json must escape quotes");
    }

    #[test]
    fn result_determinism_through_wasm_api() {
        let payload = serde_json::json!({"key": "value"});

        let mut obj = serde_json::Map::new();
        obj.insert(
            "context_digest".to_string(),
            serde_json::json!("a".repeat(64)),
        );
        obj.insert("envelope_version".to_string(), serde_json::json!(1));
        obj.insert("logical_time".to_string(), serde_json::json!(42));
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

        // event_hash = BLAKE3(JCS(envelope \ {event_hash}))
        let Some(canon_bytes) =
            crate::canon::typed_canon_bytes(&serde_json::Value::Object(obj.clone())).ok()
        else {
            return;
        };
        let hash = blake3::hash(&canon_bytes);
        let event_hash = hex::encode(hash.as_bytes());

        obj.insert("event_hash".to_string(), serde_json::json!(&event_hash));

        let value = serde_json::Value::Object(obj);
        let Ok(input) = crate::canon::typed_canon_string(&value) else {
            return;
        };

        let r1 = verify_receipt_json(&input);
        let r2 = verify_receipt_json(&input);
        assert_eq!(r1, r2, "WASM API must be deterministic");
    }
}
