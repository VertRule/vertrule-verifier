//! Determinism tests for the public verifier.
//!
//! Ensures that verification results are byte-identical across runs
//! and that key ordering in JSON does not affect digest computation.

use vr_kernel_testutils::{need, ok_when, vr_test};

use vr_verifier::result::VerificationStatus;

/// Load raw canonical bytes from `test-vectors/raw/<name>.json`.
fn load_raw(name: &str) -> anyhow::Result<Vec<u8>> {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = manifest
        .join("test-vectors")
        .join("raw")
        .join(format!("{name}.json"));
    std::fs::read(&path).map_err(Into::into)
}

vr_test!(
    fn three_runs_produce_identical_result_digests() {
        let raw = load_raw("valid_single_envelope")?;

        let r1 = vr_verifier::verify_receipt(&raw);
        let r2 = vr_verifier::verify_receipt(&raw);
        let r3 = vr_verifier::verify_receipt(&raw);

        let d1 = r1.digest()?;
        let d2 = r2.digest()?;
        let d3 = r3.digest()?;

        need(ok_when(d1 == d2), "run 1 and 2 must match")?;
        need(ok_when(d2 == d3), "run 2 and 3 must match")?;
    }
);

vr_test!(
    fn different_key_order_same_payload_same_event_hash() {
        // Two payloads with same keys but constructed in different insertion order.
        // JCS canonicalization sorts keys, so both must produce the same event_hash.
        let payload_a = serde_json::json!({"alpha": 1, "beta": 2, "gamma": 3});
        let payload_b = serde_json::json!({"gamma": 3, "alpha": 1, "beta": 2});

        let canon_a =
            vr_jcs::to_canon_bytes(&payload_a).map_err(|e| anyhow::anyhow!("canon a: {e}"))?;
        let canon_b =
            vr_jcs::to_canon_bytes(&payload_b).map_err(|e| anyhow::anyhow!("canon b: {e}"))?;

        let hash_a = hex::encode(blake3::hash(&canon_a).as_bytes());
        let hash_b = hex::encode(blake3::hash(&canon_b).as_bytes());

        need(
            ok_when(hash_a == hash_b),
            "same keys in different order must produce same BLAKE3 hash",
        )?;
    }
);

vr_test!(
    fn valid_and_invalid_produce_different_digests() {
        let raw = load_raw("valid_single_envelope")?;
        let valid_result = vr_verifier::verify_receipt(&raw);
        let invalid_result = vr_verifier::verify_receipt(b"not json");

        need(
            ok_when(valid_result.status == VerificationStatus::Valid),
            "valid should be valid",
        )?;
        need(
            ok_when(invalid_result.status == VerificationStatus::Invalid),
            "invalid should be invalid",
        )?;

        let d_valid = valid_result.digest()?;
        let d_invalid = invalid_result.digest()?;

        need(
            ok_when(d_valid != d_invalid),
            "valid and invalid must produce different digests",
        )?;
    }
);

vr_test!(
    fn signed_verification_result_is_deterministic() {
        let raw = load_raw("valid_signed")?;
        let sig = load_raw("valid_sig")?;

        let r1 = vr_verifier::verify_signed_receipt(&raw, &sig);
        let r2 = vr_verifier::verify_signed_receipt(&raw, &sig);

        let d1 = r1.digest()?;
        let d2 = r2.digest()?;

        need(ok_when(d1 == d2), "signed result must be deterministic")?;
    }
);
