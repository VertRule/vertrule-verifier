//! Generate protocol test vectors for `vertrule-verifier`.
//!
//! Produces JSON fixtures in `test-vectors/` that any verifier implementation
//! can use to validate correctness. Each fixture computes BLAKE3 hashes over
//! JCS-canonicalized payloads so the hashes are authoritative.
//!
//! Run with:
//! ```bash
//! cargo run --example generate_test_vectors -p vertrule-verifier
//! ```

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::io::Write as _;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Typed canonicalization helper (non-deprecated round-trip).
fn canon_bytes(value: &serde_json::Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let json = serde_json::to_vec(value)?;
    Ok(vr_jcs::to_canon_bytes_from_slice(&json)?)
}

/// Compute the BLAKE3 hex digest of the JCS-canonical form of a JSON value.
fn canon_hash(value: &serde_json::Value) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = canon_bytes(value)?;
    Ok(hex::encode(blake3::hash(&bytes).as_bytes()))
}

/// Build a placeholder 64-char lowercase hex string from a seed byte.
fn placeholder_hex_64(seed: u8) -> serde_json::Value {
    let byte = format!("{seed:02x}");
    serde_json::Value::String(byte.repeat(32))
}

/// Build a single valid envelope JSON value from a payload.
fn build_envelope(
    payload: &serde_json::Value,
    logical_time: u64,
    parent_id: Option<&str>,
    receipt_type: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    build_envelope_with_digests(
        payload,
        logical_time,
        parent_id,
        receipt_type,
        &placeholder_hex_64(0xaa),
        &placeholder_hex_64(0xcc),
    )
}

/// Build an envelope with explicit context and policy digests.
///
/// Uses full-envelope commitment: `event_hash = BLAKE3(JCS(envelope \ {event_hash}))`.
fn build_envelope_with_digests(
    payload: &serde_json::Value,
    logical_time: u64,
    parent_id: Option<&str>,
    receipt_type: &str,
    context_digest: &serde_json::Value,
    policy_digest: &serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    // Build envelope without event_hash
    let mut envelope = json!({
        "envelope_version": 1,
        "receipt_type": receipt_type,
        "context_digest": context_digest,
        "schema_digest": placeholder_hex_64(0xbb),
        "policy_digest": policy_digest,
        // Canonical wire form is a decimal string (VR-CANONICAL-U64-STRING-POLICY-V1).
        "logical_time": logical_time.to_string(),
        "payload": payload,
    });

    if let Some(pid) = parent_id {
        envelope["parent_id"] = json!(pid);
    }

    // Compute full-envelope hash (all fields minus event_hash)
    let event_hash = canon_hash(&envelope)?;
    envelope["event_hash"] = json!(event_hash);

    Ok(envelope)
}

/// Write a test vector fixture (wrapper with metadata) to `dir/<name>.json`.
fn write_vector(
    dir: &std::path::Path,
    name: &str,
    vector: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = dir.join(format!("{name}.json"));
    let mut file = std::fs::File::create(&path)?;
    let formatted = serde_json::to_string_pretty(vector)?;
    file.write_all(formatted.as_bytes())?;
    file.write_all(b"\n")?;
    eprintln!("  wrote {}", path.display());
    Ok(())
}

/// Write raw JCS-canonical JSON bytes to `dir/raw/<name>.json`.
fn write_raw(
    dir: &std::path::Path,
    name: &str,
    value: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw_dir = dir.join("raw");
    std::fs::create_dir_all(&raw_dir)?;
    let path = raw_dir.join(format!("{name}.json"));
    let canon = canon_bytes(value)?;
    std::fs::write(&path, &canon)?;
    eprintln!("  wrote {}", path.display());
    Ok(())
}

/// Extract `event_hash` from an envelope value.
fn get_hash(env: &serde_json::Value) -> Result<String, Box<dyn std::error::Error>> {
    env["event_hash"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| "missing event_hash".into())
}

// ---------------------------------------------------------------------------
// Valid vectors
// ---------------------------------------------------------------------------

fn gen_valid_single_envelope(dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let payload = json!({
        "domain": "test.governance.v1",
        "action": "create",
        "value": 42
    });

    let envelope = build_envelope(&payload, 1000, None, "governance")?;

    let vector = json!({
        "description": "Single valid envelope with correct event_hash (full-envelope commitment).",
        "expected_result": "pass",
        "data": envelope
    });

    write_vector(dir, "valid_single_envelope", &vector)?;
    write_raw(dir, "valid_single_envelope", &envelope)
}

fn gen_valid_chain_3(dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let payload_0 = json!({
        "domain": "test.governance.v1",
        "action": "initialize",
        "epoch": 0
    });
    let env_0 = build_envelope(&payload_0, 100, None, "governance")?;
    let hash_0 = get_hash(&env_0)?;

    let payload_1 = json!({
        "domain": "test.governance.v1",
        "action": "update_policy",
        "policy_version": 2
    });
    let env_1 = build_envelope(&payload_1, 200, Some(&hash_0), "governance")?;
    let hash_1 = get_hash(&env_1)?;

    let payload_2 = json!({
        "domain": "test.governance.v1",
        "action": "seal_epoch",
        "epoch": 1
    });
    let env_2 = build_envelope(&payload_2, 300, Some(&hash_1), "governance")?;

    let chain = json!([env_0, env_1, env_2]);

    let vector = json!({
        "description": "Chain of 3 envelopes with correct parent_id linkage and monotonic logical_time.",
        "expected_result": "pass",
        "data": chain
    });

    write_vector(dir, "valid_chain_3", &vector)
}

fn gen_valid_signed(dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let seed: [u8; 32] = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key();

    let payload = json!({
        "domain": "test.governance.v1",
        "action": "signed_change",
        "version": 1
    });

    let envelope = build_envelope(&payload, 1000, None, "governance")?;

    // Domain-separated receipt digest (full-envelope minus event_hash)
    let mut commitment_value = envelope.clone();
    if let serde_json::Value::Object(ref mut map) = commitment_value {
        map.remove("event_hash");
    }
    let canon_bytes = canon_bytes(&commitment_value)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"VR-ReceiptDigest|v1|");
    hasher.update(&canon_bytes);
    let receipt_hex = hex::encode(hasher.finalize().as_bytes());

    // Canonical message
    let timestamp = "2026-02-23T12:00:00Z";
    let mut msg = Vec::new();
    msg.extend_from_slice(b"VR-ReceiptSig|v1|");
    msg.extend_from_slice(receipt_hex.as_bytes());
    msg.push(b'|');
    msg.extend_from_slice(timestamp.as_bytes());

    // Sign
    let sig = sk.sign(&msg);
    let kid = hex::encode(&blake3::hash(pk.as_bytes()).as_bytes()[..12]);

    let bundle = json!({
        "alg": "Ed25519",
        "key_id": kid,
        "public_key_b64": base64::engine::general_purpose::STANDARD.encode(pk.as_bytes()),
        "signature_b64": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        "schema_version": "0.2",
        "digest_basis": "BLAKE3+JCS",
        "timestamp": timestamp,
    });

    let vector = json!({
        "description": "Valid envelope with Ed25519 signature bundle.",
        "expected_result": "pass",
        "data": envelope
    });

    write_vector(dir, "valid_signed", &vector)?;
    write_vector(dir, "valid_sig", &bundle)?;
    write_raw(dir, "valid_signed", &envelope)?;

    // Write raw sig bundle
    let raw_dir = dir.join("raw");
    std::fs::create_dir_all(&raw_dir)?;
    let sig_path = raw_dir.join("valid_sig.json");
    let sig_formatted = serde_json::to_string_pretty(&bundle)?;
    std::fs::write(&sig_path, sig_formatted.as_bytes())?;
    eprintln!("  wrote {}", sig_path.display());

    Ok(())
}

fn gen_valid_with_algorithms(dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let payload = json!({
        "domain": "test.governance.v1",
        "action": "create_with_algorithms",
        "value": 99
    });

    // Build without event_hash, add algorithm fields, then compute hash
    let mut obj = json!({
        "envelope_version": 1,
        "receipt_type": "governance",
        "context_digest": placeholder_hex_64(0xaa),
        "schema_digest": placeholder_hex_64(0xbb),
        "policy_digest": placeholder_hex_64(0xcc),
        "logical_time": "2000",
        "digest_algorithm": "BLAKE3",
        "canonicalization": "JCS",
        "payload": payload,
    });
    let event_hash = canon_hash(&obj)?;
    obj["event_hash"] = json!(event_hash);
    let envelope = obj;

    let vector = json!({
        "description": "Valid envelope with explicit digest_algorithm and canonicalization fields matching v1 identity triple.",
        "expected_result": "pass",
        "data": envelope
    });

    write_vector(dir, "valid_with_algorithms", &vector)?;
    write_raw(dir, "valid_with_algorithms", &envelope)
}

// ---------------------------------------------------------------------------
// Invalid vectors
// ---------------------------------------------------------------------------

fn gen_invalid_event_hash(dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let payload = json!({
        "domain": "test.governance.v1",
        "action": "create",
        "value": 42
    });

    let mut envelope = build_envelope(&payload, 1000, None, "governance")?;

    let good_hash = get_hash(&envelope)?;
    let tampered = format!(
        "{}{}",
        &good_hash[..63],
        if good_hash.ends_with('0') { "1" } else { "0" }
    );
    envelope["event_hash"] = json!(tampered);

    let vector = json!({
        "description": "Envelope with tampered event_hash -- last hex digit flipped. Verifier must reject.",
        "expected_result": "fail",
        "expected_error": "EventHashMismatch",
        "data": envelope
    });

    write_vector(dir, "invalid_event_hash", &vector)
}

fn gen_invalid_chain_broken_link(dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let payload_0 = json!({ "step": 0 });
    let env_0 = build_envelope(&payload_0, 100, None, "event")?;

    let payload_1 = json!({ "step": 1 });
    let bogus_parent = "ff".repeat(32);
    let env_1 = build_envelope(&payload_1, 200, Some(&bogus_parent), "event")?;

    let vector = json!({
        "description": "Chain where envelope[1].parent_id does not match envelope[0].event_hash.",
        "expected_result": "fail",
        "expected_error": "ChainLinkageBroken",
        "data": [env_0, env_1]
    });

    write_vector(dir, "invalid_chain_broken_link", &vector)
}

fn gen_invalid_chain_time_regression(
    dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload_0 = json!({ "step": 0 });
    let env_0 = build_envelope(&payload_0, 500, None, "event")?;
    let hash_0 = get_hash(&env_0)?;

    let payload_1 = json!({ "step": 1 });
    let env_1 = build_envelope(&payload_1, 400, Some(&hash_0), "event")?;

    let vector = json!({
        "description": "Chain where logical_time goes backwards (500 -> 400). Verifier must reject.",
        "expected_result": "fail",
        "expected_error": "LogicalTimeNotMonotonic",
        "data": [env_0, env_1]
    });

    write_vector(dir, "invalid_chain_time_regression", &vector)
}

fn gen_invalid_version(dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let payload = json!({
        "domain": "test.governance.v1",
        "action": "create",
        "value": 1
    });

    let mut envelope = build_envelope(&payload, 1000, None, "governance")?;
    envelope["envelope_version"] = json!(99);

    let vector = json!({
        "description": "Envelope with unsupported version (99). Verifier must reject.",
        "expected_result": "fail",
        "expected_error": "UnsupportedVersion",
        "data": envelope
    });

    write_vector(dir, "invalid_version", &vector)?;
    write_raw(dir, "invalid_version", &envelope)
}

fn gen_invalid_unknown_field(dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let payload = json!({"action": "test"});
    let mut envelope = build_envelope(&payload, 1000, None, "governance")?;
    envelope["bogus_field"] = json!(42);

    let vector = json!({
        "description": "Envelope with unrecognized field 'bogus_field'. Verifier must reject.",
        "expected_result": "fail",
        "expected_error": "UnknownField",
        "data": envelope
    });

    write_vector(dir, "invalid_unknown_field", &vector)?;
    write_raw(dir, "invalid_unknown_field", &envelope)
}

fn gen_invalid_missing_required(dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    // Build valid then remove event_hash
    let payload = json!({"action": "test"});
    let mut envelope = build_envelope(&payload, 1000, None, "governance")?;
    let obj = envelope.as_object_mut().ok_or("not an object")?;
    obj.remove("event_hash");

    let vector = json!({
        "description": "Envelope missing required field 'event_hash'. Verifier must reject.",
        "expected_result": "fail",
        "expected_error": "MissingRequiredField",
        "data": envelope
    });

    write_vector(dir, "invalid_missing_required", &vector)?;
    write_raw(dir, "invalid_missing_required", &envelope)
}

fn gen_invalid_unknown_receipt_type(
    dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = json!({"action": "test"});
    let mut envelope = build_envelope(&payload, 1000, None, "governance")?;
    envelope["receipt_type"] = json!("Quantum");

    let vector = json!({
        "description": "Envelope with unknown receipt_type 'Quantum'. Verifier must reject.",
        "expected_result": "fail",
        "expected_error": "UnknownReceiptType",
        "data": envelope
    });

    write_vector(dir, "invalid_unknown_receipt_type", &vector)?;
    write_raw(dir, "invalid_unknown_receipt_type", &envelope)
}

fn gen_invalid_duplicate_hash(dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    // Build valid first envelope
    let payload = json!({"action": "duplicate"});
    let env_0 = build_envelope(&payload, 100, None, "event")?;
    let hash_0 = get_hash(&env_0)?;

    // Build second envelope with correct linkage but force its event_hash
    // to match env_0's — creating an intentional duplicate
    let mut env_1 = build_envelope(&payload, 200, Some(&hash_0), "event")?;
    env_1["event_hash"] = env_0["event_hash"].clone();

    let vector = json!({
        "description": "Chain with duplicate event_hash (forced). Verifier must reject.",
        "expected_result": "fail",
        "expected_error": "DuplicateEventHash",
        "data": [env_0, env_1]
    });

    write_vector(dir, "invalid_duplicate_hash", &vector)
}

fn gen_invalid_context_inconsistent(
    dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload_0 = json!({"step": 0});
    let env_0 = build_envelope(&payload_0, 100, None, "event")?;
    let hash_0 = get_hash(&env_0)?;

    let payload_1 = json!({"step": 1});
    // Different context_digest
    let env_1 = build_envelope_with_digests(
        &payload_1,
        200,
        Some(&hash_0),
        "event",
        &placeholder_hex_64(0xdd), // different from env_0's 0xaa
        &placeholder_hex_64(0xcc),
    )?;

    let vector = json!({
        "description": "Chain where context_digest differs between envelopes. Verifier must reject.",
        "expected_result": "fail",
        "expected_error": "ContextInconsistent",
        "data": [env_0, env_1]
    });

    write_vector(dir, "invalid_context_inconsistent", &vector)
}

fn gen_invalid_policy_inconsistent(
    dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload_0 = json!({"step": 0});
    let env_0 = build_envelope(&payload_0, 100, None, "event")?;
    let hash_0 = get_hash(&env_0)?;

    let payload_1 = json!({"step": 1});
    // Different policy_digest
    let env_1 = build_envelope_with_digests(
        &payload_1,
        200,
        Some(&hash_0),
        "event",
        &placeholder_hex_64(0xaa),
        &placeholder_hex_64(0xdd), // different from env_0's 0xcc
    )?;

    let vector = json!({
        "description": "Chain where policy_digest differs between envelopes. Verifier must reject.",
        "expected_result": "fail",
        "expected_error": "PolicyInconsistent",
        "data": [env_0, env_1]
    });

    write_vector(dir, "invalid_policy_inconsistent", &vector)
}

fn gen_invalid_bit_flip(dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let payload = json!({
        "domain": "test.governance.v1",
        "action": "create",
        "value": 42
    });

    let mut envelope = build_envelope(&payload, 1000, None, "governance")?;

    // Flip the low bit of the first hex nibble
    let good_hash = get_hash(&envelope)?;
    let mut hash_bytes = good_hash.into_bytes();
    hash_bytes[0] ^= 1; // toggles between adjacent hex pairs (0↔1, 2↔3, a↔b, etc.)
    let tampered = String::from_utf8(hash_bytes).map_err(|_| "non-utf8 after flip")?;
    envelope["event_hash"] = json!(tampered);

    let vector = json!({
        "description": "Envelope with single-bit flip in event_hash first nibble. Verifier must reject.",
        "expected_result": "fail",
        "expected_error": "EventHashMismatch",
        "data": envelope
    });

    write_vector(dir, "invalid_bit_flip", &vector)
}

fn gen_invalid_wrong_digest_algorithm(
    dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = json!({
        "domain": "test.governance.v1",
        "action": "create",
        "value": 1
    });

    let mut envelope = build_envelope(&payload, 1000, None, "governance")?;
    envelope["digest_algorithm"] = json!("SHA256");

    let vector = json!({
        "description": "Envelope declaring digest_algorithm 'SHA256' which does not match v1 identity triple. Verifier must reject.",
        "expected_result": "fail",
        "expected_error": "DigestAlgorithmMismatch",
        "data": envelope
    });

    write_vector(dir, "invalid_wrong_digest_algorithm", &vector)
}

fn gen_invalid_wrong_canonicalization(
    dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = json!({
        "domain": "test.governance.v1",
        "action": "create",
        "value": 1
    });

    let mut envelope = build_envelope(&payload, 1000, None, "governance")?;
    envelope["canonicalization"] = json!("CBOR");

    let vector = json!({
        "description": "Envelope declaring canonicalization 'CBOR' which does not match v1 identity triple. Verifier must reject.",
        "expected_result": "fail",
        "expected_error": "CanonicalizationMismatch",
        "data": envelope
    });

    write_vector(dir, "invalid_wrong_canonicalization", &vector)
}

fn gen_invalid_schema_inconsistent(
    dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload_0 = json!({"step": 0});
    let env_0 = build_envelope(&payload_0, 100, None, "event")?;
    let hash_0 = get_hash(&env_0)?;

    let payload_1 = json!({"step": 1});
    // Same context and policy, but different schema_digest
    let env_1 = build_envelope_with_digests(
        &payload_1,
        200,
        Some(&hash_0),
        "event",
        &placeholder_hex_64(0xaa),
        &placeholder_hex_64(0xcc),
    )?;
    // Tamper schema_digest after commitment (intentionally invalid)
    let mut env_1 = env_1;
    env_1["schema_digest"] = placeholder_hex_64(0xdd);

    let vector = json!({
        "description": "Chain where schema_digest differs between envelopes. Verifier must reject.",
        "expected_result": "fail",
        "expected_error": "SchemaInconsistent",
        "data": [env_0, env_1]
    });

    write_vector(dir, "invalid_schema_inconsistent", &vector)
}

fn gen_invalid_signature(dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let seed: [u8; 32] = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key();

    let payload = json!({"action": "signed_change", "version": 1});
    let envelope = build_envelope(&payload, 1000, None, "governance")?;

    // Domain-separated receipt digest (full-envelope minus event_hash)
    let mut commitment_value = envelope;
    if let serde_json::Value::Object(ref mut map) = &mut commitment_value {
        map.remove("event_hash");
    }
    let canon_bytes = canon_bytes(&commitment_value)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"VR-ReceiptDigest|v1|");
    hasher.update(&canon_bytes);
    let receipt_hex = hex::encode(hasher.finalize().as_bytes());

    let timestamp = "2026-02-23T12:00:00Z";
    let mut msg = Vec::new();
    msg.extend_from_slice(b"VR-ReceiptSig|v1|");
    msg.extend_from_slice(receipt_hex.as_bytes());
    msg.push(b'|');
    msg.extend_from_slice(timestamp.as_bytes());

    let sig = sk.sign(&msg);
    let kid = hex::encode(&blake3::hash(pk.as_bytes()).as_bytes()[..12]);

    // Corrupt the signature (flip first byte)
    let mut sig_bytes = sig.to_bytes();
    sig_bytes[0] ^= 0xFF;

    let bundle = json!({
        "alg": "Ed25519",
        "key_id": kid,
        "public_key_b64": base64::engine::general_purpose::STANDARD.encode(pk.as_bytes()),
        "signature_b64": base64::engine::general_purpose::STANDARD.encode(sig_bytes),
        "schema_version": "0.2",
        "digest_basis": "BLAKE3+JCS",
        "timestamp": timestamp,
    });

    let vector = json!({
        "description": "Signature bundle with corrupted signature bytes. Verifier must reject.",
        "expected_result": "fail",
        "expected_error": "SignatureInvalid",
    });

    write_vector(dir, "invalid_signature", &vector)?;

    // Write the bad sig bundle as a standalone file too
    let raw_dir = dir.join("raw");
    std::fs::create_dir_all(&raw_dir)?;
    let path = raw_dir.join("invalid_sig.json");
    let formatted = serde_json::to_string_pretty(&bundle)?;
    std::fs::write(&path, formatted.as_bytes())?;
    eprintln!("  wrote {}", path.display());

    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = manifest_dir.join("test-vectors");
    std::fs::create_dir_all(&dir)?;

    eprintln!("Generating test vectors in {}", dir.display());

    // Valid vectors
    gen_valid_single_envelope(&dir)?;
    gen_valid_chain_3(&dir)?;
    gen_valid_signed(&dir)?;
    gen_valid_with_algorithms(&dir)?;

    // Invalid vectors
    gen_invalid_event_hash(&dir)?;
    gen_invalid_chain_broken_link(&dir)?;
    gen_invalid_chain_time_regression(&dir)?;
    gen_invalid_version(&dir)?;
    gen_invalid_unknown_field(&dir)?;
    gen_invalid_missing_required(&dir)?;
    gen_invalid_unknown_receipt_type(&dir)?;
    gen_invalid_duplicate_hash(&dir)?;
    gen_invalid_context_inconsistent(&dir)?;
    gen_invalid_policy_inconsistent(&dir)?;
    gen_invalid_bit_flip(&dir)?;
    gen_invalid_signature(&dir)?;
    gen_invalid_wrong_digest_algorithm(&dir)?;
    gen_invalid_wrong_canonicalization(&dir)?;
    gen_invalid_schema_inconsistent(&dir)?;

    eprintln!("Done.");
    Ok(())
}
