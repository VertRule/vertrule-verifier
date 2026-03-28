//! Integration tests that validate the `vr-verifier` crate against the
//! generated protocol test vectors in `test-vectors/`.
//!
//! These tests load JSON fixtures produced by `examples/generate_test_vectors.rs`
//! and verify that the verifier accepts valid vectors and rejects invalid ones
//! with the correct error variant.

use vr_verifier::chain::verify_chain;
use vr_verifier::envelope::ReceiptEnvelope;
use vr_verifier::envelope::{verify_algorithms, verify_envelope_version, verify_event_hash};
use vr_verifier::error::VerifyError;
use vr_verifier::result::VerificationStatus;

macro_rules! vr_test {
    ( $(#[$meta:meta])* fn $name:ident() $body:block ) => {
        $(#[$meta])*
        #[test]
        fn $name() {
            #[allow(clippy::redundant_closure_call)]
            let res: anyhow::Result<()> = (|| {
                $body
                Ok(())
            })();
            if let Err(e) = res {
                panic!("{e}");
            }
        }
    };
}

fn need<T>(option: Option<T>, what: &'static str) -> anyhow::Result<T> {
    option.ok_or_else(|| anyhow::anyhow!(what))
}

const fn ok_when(condition: bool) -> Option<()> {
    if condition {
        Some(())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load a test vector file by name (without `.json` extension).
fn load_vector(name: &str) -> anyhow::Result<serde_json::Value> {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = manifest.join("test-vectors").join(format!("{name}.json"));
    let bytes = std::fs::read(&path)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    Ok(value)
}

/// Load raw canonical bytes from `test-vectors/raw/<name>.json`.
fn load_raw(name: &str) -> anyhow::Result<Vec<u8>> {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = manifest
        .join("test-vectors")
        .join("raw")
        .join(format!("{name}.json"));
    std::fs::read(&path).map_err(Into::into)
}

/// Parse the `data` field of a vector as a single `ReceiptEnvelope`.
fn parse_single(vector: &serde_json::Value) -> anyhow::Result<ReceiptEnvelope> {
    let env: ReceiptEnvelope = serde_json::from_value(vector["data"].clone())?;
    Ok(env)
}

/// Parse the `data` field of a vector as a chain of `ReceiptEnvelope`s.
fn parse_chain(vector: &serde_json::Value) -> anyhow::Result<Vec<ReceiptEnvelope>> {
    let chain: Vec<ReceiptEnvelope> = serde_json::from_value(vector["data"].clone())?;
    Ok(chain)
}

// ---------------------------------------------------------------------------
// Valid vectors (low-level API)
// ---------------------------------------------------------------------------

vr_test!(
    fn valid_single_envelope_event_hash_matches() {
        let vector = load_vector("valid_single_envelope")?;
        need(
            ok_when(vector["expected_result"].as_str() == Some("pass")),
            "fixture metadata should declare pass",
        )?;

        let env = parse_single(&vector)?;
        verify_event_hash(&env)?;
        verify_envelope_version(&env)?;
    }
);

vr_test!(
    fn valid_chain_3_passes_all_checks() {
        let vector = load_vector("valid_chain_3")?;
        need(
            ok_when(vector["expected_result"].as_str() == Some("pass")),
            "fixture metadata should declare pass",
        )?;

        let chain = parse_chain(&vector)?;

        for env in &chain {
            verify_event_hash(env)?;
            verify_envelope_version(env)?;
        }

        verify_chain(&chain)?;
    }
);

// ---------------------------------------------------------------------------
// Invalid vectors (low-level API)
// ---------------------------------------------------------------------------

vr_test!(
    fn invalid_event_hash_is_rejected() {
        let vector = load_vector("invalid_event_hash")?;
        let env = parse_single(&vector)?;
        let result = verify_event_hash(&env);
        need(ok_when(result.is_err()), "tampered hash should be rejected")?;
        let err = need(result.err(), "expected error variant")?;
        need(
            ok_when(matches!(err, VerifyError::EventHashMismatch { .. })),
            "error should be EventHashMismatch",
        )?;
    }
);

vr_test!(
    fn invalid_chain_broken_link_is_rejected() {
        let vector = load_vector("invalid_chain_broken_link")?;
        let chain = parse_chain(&vector)?;
        let result = verify_chain(&chain);
        need(ok_when(result.is_err()), "broken chain should be rejected")?;
        let err = need(result.err(), "expected error variant")?;
        need(
            ok_when(matches!(
                err,
                VerifyError::ChainLinkageBroken { index: 1, .. }
            )),
            "error should be ChainLinkageBroken at index 1",
        )?;
    }
);

vr_test!(
    fn invalid_chain_time_regression_is_rejected() {
        let vector = load_vector("invalid_chain_time_regression")?;
        let chain = parse_chain(&vector)?;
        let result = verify_chain(&chain);
        need(
            ok_when(result.is_err()),
            "time regression should be rejected",
        )?;
        let err = need(result.err(), "expected error variant")?;
        need(
            ok_when(matches!(
                err,
                VerifyError::LogicalTimeNotMonotonic {
                    index: 1,
                    previous: 500,
                    current: 400,
                }
            )),
            "error should be LogicalTimeNotMonotonic(500 -> 400)",
        )?;
    }
);

vr_test!(
    fn invalid_version_is_rejected() {
        // Version 99 is rejected at deserialization (SchemaVersion validates on
        // construction). The facade catches this and returns INVALID.
        let raw = load_raw("invalid_version")?;
        let result = vr_verifier::verify_receipt(&raw);
        need(
            ok_when(result.status == VerificationStatus::Invalid),
            "unsupported version should produce INVALID",
        )?;
        need(
            ok_when(
                result
                    .errors
                    .iter()
                    .any(|e| e.contains("unsupported") || e.contains("version")),
            ),
            "error should mention unsupported version",
        )?;
    }
);

vr_test!(
    fn invalid_duplicate_hash_is_rejected() {
        let vector = load_vector("invalid_duplicate_hash")?;
        let chain = parse_chain(&vector)?;
        let result = verify_chain(&chain);
        need(
            ok_when(result.is_err()),
            "duplicate event_hash should be rejected",
        )?;
        let err = need(result.err(), "expected error variant")?;
        need(
            ok_when(matches!(err, VerifyError::DuplicateEventHash { .. })),
            "error should be DuplicateEventHash",
        )?;
    }
);

vr_test!(
    fn invalid_context_inconsistent_is_rejected() {
        let vector = load_vector("invalid_context_inconsistent")?;
        let chain = parse_chain(&vector)?;
        let result = verify_chain(&chain);
        need(
            ok_when(result.is_err()),
            "inconsistent context should be rejected",
        )?;
        let err = need(result.err(), "expected error variant")?;
        need(
            ok_when(matches!(err, VerifyError::ContextInconsistent { .. })),
            "error should be ContextInconsistent",
        )?;
    }
);

vr_test!(
    fn invalid_policy_inconsistent_is_rejected() {
        let vector = load_vector("invalid_policy_inconsistent")?;
        let chain = parse_chain(&vector)?;
        let result = verify_chain(&chain);
        need(
            ok_when(result.is_err()),
            "inconsistent policy should be rejected",
        )?;
        let err = need(result.err(), "expected error variant")?;
        need(
            ok_when(matches!(err, VerifyError::PolicyInconsistent { .. })),
            "error should be PolicyInconsistent",
        )?;
    }
);

vr_test!(
    fn invalid_schema_inconsistent_is_rejected() {
        let vector = load_vector("invalid_schema_inconsistent")?;
        let chain = parse_chain(&vector)?;
        let result = verify_chain(&chain);
        need(
            ok_when(result.is_err()),
            "inconsistent schema should be rejected",
        )?;
        let err = need(result.err(), "expected error variant")?;
        need(
            ok_when(matches!(err, VerifyError::SchemaInconsistent { .. })),
            "error should be SchemaInconsistent",
        )?;
    }
);

vr_test!(
    fn invalid_bit_flip_is_rejected() {
        let vector = load_vector("invalid_bit_flip")?;
        let env = parse_single(&vector)?;
        let result = verify_event_hash(&env);
        need(
            ok_when(result.is_err()),
            "bit-flipped event_hash should be rejected",
        )?;
        let err = need(result.err(), "expected error variant")?;
        need(
            ok_when(matches!(err, VerifyError::EventHashMismatch { .. })),
            "error should be EventHashMismatch",
        )?;
    }
);

// ---------------------------------------------------------------------------
// Ingestion-path vectors (facade API -- tests schema profile rejection)
// ---------------------------------------------------------------------------

vr_test!(
    fn facade_unknown_field_rejected() {
        let raw = load_raw("invalid_unknown_field")?;
        let result = vr_verifier::verify_receipt(&raw);
        need(
            ok_when(result.status == VerificationStatus::Invalid),
            "unknown field should produce INVALID",
        )?;
        need(
            ok_when(result.errors.iter().any(|e| e.contains("unknown field"))),
            "error should mention unknown field",
        )?;
    }
);

vr_test!(
    fn facade_missing_required_field_rejected() {
        let raw = load_raw("invalid_missing_required")?;
        let result = vr_verifier::verify_receipt(&raw);
        need(
            ok_when(result.status == VerificationStatus::Invalid),
            "missing required field should produce INVALID",
        )?;
        need(
            ok_when(
                result
                    .errors
                    .iter()
                    .any(|e| e.contains("missing required field")),
            ),
            "error should mention missing required field",
        )?;
    }
);

vr_test!(
    fn facade_unknown_receipt_type_rejected() {
        let raw = load_raw("invalid_unknown_receipt_type")?;
        let result = vr_verifier::verify_receipt(&raw);
        need(
            ok_when(result.status == VerificationStatus::Invalid),
            "unknown receipt type should produce INVALID",
        )?;
        need(
            ok_when(
                result
                    .errors
                    .iter()
                    .any(|e| e.contains("unknown receipt type")),
            ),
            "error should mention unknown receipt type",
        )?;
    }
);

// ---------------------------------------------------------------------------
// Algorithm declaration vectors
// ---------------------------------------------------------------------------

vr_test!(
    fn valid_with_algorithms_accepted() {
        let raw = load_raw("valid_with_algorithms")?;
        let result = vr_verifier::verify_receipt(&raw);
        need(
            ok_when(result.status == VerificationStatus::Valid),
            "envelope with matching algorithm declarations should pass",
        )?;
        need(ok_when(result.errors.is_empty()), "no errors expected")?;
    }
);

vr_test!(
    fn invalid_wrong_digest_algorithm_rejected() {
        let vector = load_vector("invalid_wrong_digest_algorithm")?;
        let env = parse_single(&vector)?;
        let result = verify_algorithms(&env);
        need(
            ok_when(result.is_err()),
            "wrong digest algorithm should be rejected",
        )?;
        let err = need(result.err(), "expected error variant")?;
        need(
            ok_when(matches!(err, VerifyError::DigestAlgorithmMismatch { .. })),
            "error should be DigestAlgorithmMismatch",
        )?;
    }
);

vr_test!(
    fn invalid_wrong_canonicalization_rejected() {
        let vector = load_vector("invalid_wrong_canonicalization")?;
        let env = parse_single(&vector)?;
        let result = verify_algorithms(&env);
        need(
            ok_when(result.is_err()),
            "wrong canonicalization should be rejected",
        )?;
        let err = need(result.err(), "expected error variant")?;
        need(
            ok_when(matches!(err, VerifyError::CanonicalizationMismatch { .. })),
            "error should be CanonicalizationMismatch",
        )?;
    }
);

// ---------------------------------------------------------------------------
// Facade API tests (using raw canonical vectors)
// ---------------------------------------------------------------------------

vr_test!(
    fn facade_valid_single_receipt() {
        let raw = load_raw("valid_single_envelope")?;
        let result = vr_verifier::verify_receipt(&raw);
        need(
            ok_when(result.status == VerificationStatus::Valid),
            "valid raw envelope should produce VALID",
        )?;
        need(ok_when(result.errors.is_empty()), "no errors expected")?;
    }
);

vr_test!(
    fn facade_valid_signed_receipt() {
        let raw = load_raw("valid_signed")?;
        let sig = load_raw("valid_sig")?;
        let result = vr_verifier::verify_signed_receipt(&raw, &sig);
        need(
            ok_when(result.status == VerificationStatus::Valid),
            "validly signed receipt should produce VALID",
        )?;
        let sv = need(
            result.signature_validation.as_ref(),
            "signature_validation should be present",
        )?;
        need(ok_when(sv.valid), "signature should be valid")?;
        need(
            ok_when(sv.key_id_consistent),
            "key_id should be consistent with public key",
        )?;
    }
);

vr_test!(
    fn facade_invalid_signature_rejected() {
        let raw = load_raw("valid_signed")?;
        let sig = load_raw("invalid_sig")?;
        let result = vr_verifier::verify_signed_receipt(&raw, &sig);
        need(
            ok_when(result.status == VerificationStatus::Invalid),
            "corrupted signature should produce INVALID",
        )?;
        let sv = need(
            result.signature_validation.as_ref(),
            "signature_validation should be present",
        )?;
        need(ok_when(!sv.valid), "signature should be invalid")?;
    }
);

// ---------------------------------------------------------------------------
// Determinism: verify hashes are stable across runs
// ---------------------------------------------------------------------------

vr_test!(
    fn event_hash_is_deterministic_across_runs() {
        let payload = serde_json::json!({
            "domain": "test.governance.v1",
            "action": "create",
            "value": 42
        });
        let canon_bytes =
            vertrule_schemas::jcs::to_canon_bytes(&payload).map_err(|e| anyhow::anyhow!("{e}"))?;
        let computed = hex::encode(blake3::hash(&canon_bytes).as_bytes());

        let vector = load_vector("valid_single_envelope")?;
        let stored = need(
            vector["data"]["event_hash"].as_str(),
            "vector should contain event_hash",
        )?;

        need(
            ok_when(computed == stored),
            "BLAKE3 hash must be deterministic across runs",
        )?;
    }
);

vr_test!(
    fn chain_parent_ids_match_previous_event_hashes() {
        let vector = load_vector("valid_chain_3")?;
        let chain = parse_chain(&vector)?;

        need(
            ok_when(chain[0].parent_id.is_none()),
            "first envelope must have no parent",
        )?;
        need(
            ok_when(
                chain[1]
                    .parent_id
                    .as_ref()
                    .map(vertrule_schemas::DigestBytes::to_hex)
                    == Some(chain[0].event_hash.to_hex()),
            ),
            "chain[1].parent_id must equal chain[0].event_hash",
        )?;
        need(
            ok_when(
                chain[2]
                    .parent_id
                    .as_ref()
                    .map(vertrule_schemas::DigestBytes::to_hex)
                    == Some(chain[1].event_hash.to_hex()),
            ),
            "chain[2].parent_id must equal chain[1].event_hash",
        )?;
    }
);
