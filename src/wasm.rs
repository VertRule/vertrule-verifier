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

/// Verify an execution bundle (envelope + sidecar digests).
///
/// Accepts the full bundle JSON string (`vr-execution-bundle/v1` format).
/// Returns a `BundleVerificationResult` serialized as JCS-canonical JSON.
///
/// This function never throws. Malformed input produces an `INVALID` result.
#[must_use]
#[wasm_bindgen]
pub fn verify_bundle_json(bundle_json: &str) -> String {
    let result = crate::verify_bundle(bundle_json.as_bytes());
    match result.to_canon_string() {
        Ok(s) => s,
        Err(e) => error_json(&format!("canonicalization error: {e}")),
    }
}

/// Verify a decision pack (decision receipt + depended-on receipts).
///
/// Accepts the full pack JSON string (`vr-decision-pack/v1` format).
/// Returns a `DecisionPackVerificationResult` serialized as JCS-canonical
/// JSON, including the per-member support-set walk.
///
/// This function never throws. Malformed input produces an `INVALID` result.
#[must_use]
#[wasm_bindgen]
pub fn verify_decision_pack_json(pack_json: &str) -> String {
    let result = crate::verify_decision_pack(pack_json.as_bytes());
    match result.to_canon_string() {
        Ok(s) => s,
        Err(e) => error_json(&format!("canonicalization error: {e}")),
    }
}

/// Verify a closure-committed layered bundle (ADR-040).
///
/// Accepts the full bundle JSON string (`vr-layered-bundle/v1` format): a
/// root `pack.v0` receipt, a closure manifest, and the transitive
/// dependency closure. Returns a `ClosureBundleVerificationResult`
/// serialized as JCS-canonical JSON, including the manifest-digest check,
/// closure completeness, cycle detection, and the per-edge walk.
///
/// This function never throws. Malformed input produces an `INVALID` result.
#[must_use]
#[wasm_bindgen]
pub fn verify_closure_bundle_json(bundle_json: &str) -> String {
    let result = crate::verify_closure_bundle(bundle_json.as_bytes());
    match result.to_canon_bytes() {
        Ok(bytes) => String::from_utf8(bytes)
            .unwrap_or_else(|_| error_json("closure bundle result was not valid UTF-8")),
        Err(e) => error_json(&format!("canonicalization error: {e}")),
    }
}

/// Compute the BLAKE3 digest of arbitrary bytes, returned as a 64-char hex string.
///
/// Useful for the website to compute digests client-side for display
/// without reimplementing BLAKE3 in JavaScript.
#[must_use]
#[wasm_bindgen]
pub fn digest_hex(input: &[u8]) -> String {
    // Opaque binary bytes, not canonical JSON — so the `vr-jcs` canonical
    // path does not apply. This function identifies nothing: it exports the
    // BLAKE3 primitive for client-side display, so the sealed primitive
    // carrier is the accurate expression rather than a placeholder. The
    // WASM-facing return shape (64-char lowercase hex) is unchanged.
    vertrule_crypto::identity::OpaqueBytesDigest::compute(input).to_hex_string()
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

        // event_hash = BLAKE3(JCS(envelope \ {event_hash})), computed via the
        // canonical law so it matches the verifier's own recompute.
        obj.insert("event_hash".to_string(), serde_json::json!("0".repeat(64)));
        let Ok(envelope) = serde_json::from_value::<vertrule_schemas::ReceiptEnvelope>(
            serde_json::Value::Object(obj.clone()),
        ) else {
            return;
        };
        let Ok(digest) = vr_receipt_identity::compute_event_hash(&envelope) else {
            return;
        };
        obj.insert("event_hash".to_string(), serde_json::json!(digest.to_hex()));

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

        // event_hash via the canonical law (matches verifier recompute).
        obj.insert("event_hash".to_string(), serde_json::json!("0".repeat(64)));
        let Ok(envelope) = serde_json::from_value::<vertrule_schemas::ReceiptEnvelope>(
            serde_json::Value::Object(obj.clone()),
        ) else {
            return;
        };
        let Ok(digest) = vr_receipt_identity::compute_event_hash(&envelope) else {
            return;
        };
        obj.insert("event_hash".to_string(), serde_json::json!(digest.to_hex()));
        let value = serde_json::Value::Object(obj);
        let Ok(receipt_json) = crate::canon::typed_canon_string(&value) else {
            return;
        };

        // Build a sig bundle with correct key_id/public_key but bad signature
        let seed = [77u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key();
        let pk_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk.as_bytes());
        // Key fingerprint through the ratified V1 law rather than
        // hand-reproducing `hex(BLAKE3(pk)[..12])`.
        let key_id = crate::signature::KeyId::from_public_key_v1(pk.as_bytes())
            .as_hex()
            .to_string();
        let sig_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[0u8; 64]);
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
        assert!(
            output.contains("\"key_id_consistent\":true"),
            "key_id matches public_key — got: {output}"
        );
        assert!(
            output.contains("\"valid\":false"),
            "bad signature — got: {output}"
        );
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

        // event_hash via the canonical law (matches verifier recompute).
        obj.insert("event_hash".to_string(), serde_json::json!("0".repeat(64)));
        let Ok(envelope) = serde_json::from_value::<vertrule_schemas::ReceiptEnvelope>(
            serde_json::Value::Object(obj.clone()),
        ) else {
            return;
        };
        let Ok(digest) = vr_receipt_identity::compute_event_hash(&envelope) else {
            return;
        };
        obj.insert("event_hash".to_string(), serde_json::json!(digest.to_hex()));

        let value = serde_json::Value::Object(obj);
        let Ok(input) = crate::canon::typed_canon_string(&value) else {
            return;
        };

        let r1 = verify_receipt_json(&input);
        let r2 = verify_receipt_json(&input);
        assert_eq!(r1, r2, "WASM API must be deterministic");
    }
}
