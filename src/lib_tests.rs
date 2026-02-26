//! Tests for `vr-verifier`.
//!
//! Uses `vr_test!` from `vr-kernel-testutils` (zero runtime deps).

use serde_json::json;
use vr_kernel_testutils::{need, ok_when, vr_test};

use crate::chain::verify_chain;
use crate::envelope::ReceiptEnvelope;
use crate::error::VerifyError;
use vr_definitions::DigestBytes;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute a BLAKE3 digest over the JCS-canonical form of a `serde_json::Value`.
fn canon_hash(value: &serde_json::Value) -> Result<DigestBytes, VerifyError> {
    let bytes = vr_jcs::to_canon_bytes(value).map_err(|e| VerifyError::Canon(format!("{e}")))?;
    let hash = blake3::hash(&bytes);
    Ok(DigestBytes::from_array(*hash.as_bytes()))
}

/// Build a minimal valid `ReceiptEnvelope`.
fn make_envelope(
    payload: serde_json::Value,
    logical_time: u64,
    parent_id: Option<DigestBytes>,
) -> Result<ReceiptEnvelope, VerifyError> {
    let event_hash = canon_hash(&payload)?;
    let filler = DigestBytes::from_array([0u8; 32]);
    Ok(ReceiptEnvelope {
        envelope_version: 1,
        receipt_type: "governance".to_string(),
        context_digest: filler,
        schema_digest: filler,
        policy_digest: filler,
        logical_time,
        event_hash,
        parent_id,
        boundary_origin: None,
        payload,
    })
}

// ---------------------------------------------------------------------------
// Per-envelope tests
// ---------------------------------------------------------------------------

vr_test!(
    fn valid_envelope_passes_event_hash_check() {
        let env = make_envelope(json!({"action": "create", "id": 1}), 1, None)?;
        env.verify_event_hash()?;
    }
);

vr_test!(
    fn tampered_payload_fails_event_hash_check() {
        let mut env = make_envelope(json!({"action": "create", "id": 1}), 1, None)?;
        env.payload = json!({"action": "delete", "id": 1});

        need(
            ok_when(matches!(
                env.verify_event_hash(),
                Err(VerifyError::EventHashMismatch { .. })
            )),
            "tampered payload should produce EventHashMismatch",
        )?;
    }
);

vr_test!(
    fn wrong_version_rejected() {
        let mut env = make_envelope(json!({"x": 1}), 1, None)?;
        env.envelope_version = 99;

        need(
            ok_when(matches!(
                env.verify_envelope_version(),
                Err(VerifyError::UnsupportedVersion { version: 99 })
            )),
            "version 99 should produce UnsupportedVersion",
        )?;
    }
);

vr_test!(
    fn supported_version_accepted() {
        let env = make_envelope(json!({"x": 1}), 1, None)?;
        env.verify_envelope_version()?;
    }
);

// ---------------------------------------------------------------------------
// Chain tests
// ---------------------------------------------------------------------------

vr_test!(
    fn empty_chain_passes() {
        verify_chain(&[])?;
    }
);

vr_test!(
    fn single_envelope_chain_passes() {
        let env = make_envelope(json!({"a": 1}), 1, None)?;
        verify_chain(&[env])?;
    }
);

vr_test!(
    fn valid_three_envelope_chain_passes() {
        let e0 = make_envelope(json!({"step": 0}), 1, None)?;
        let e1 = make_envelope(json!({"step": 1}), 2, Some(e0.event_hash))?;
        let e2 = make_envelope(json!({"step": 2}), 3, Some(e1.event_hash))?;
        verify_chain(&[e0, e1, e2])?;
    }
);

vr_test!(
    fn broken_linkage_detected() {
        let e0 = make_envelope(json!({"step": 0}), 1, None)?;
        let e1 = make_envelope(json!({"step": 1}), 2, None)?;

        need(
            ok_when(matches!(
                verify_chain(&[e0, e1]),
                Err(VerifyError::ChainLinkageBroken { index: 1, .. })
            )),
            "broken linkage should produce ChainLinkageBroken at index 1",
        )?;
    }
);

vr_test!(
    fn non_monotonic_logical_time_detected() {
        let e0 = make_envelope(json!({"step": 0}), 10, None)?;
        let e1 = make_envelope(json!({"step": 1}), 5, Some(e0.event_hash))?;

        need(
            ok_when(matches!(
                verify_chain(&[e0, e1]),
                Err(VerifyError::LogicalTimeNotMonotonic {
                    index: 1,
                    previous: 10,
                    current: 5,
                })
            )),
            "backwards logical time should produce LogicalTimeNotMonotonic",
        )?;
    }
);

vr_test!(
    fn equal_logical_time_is_not_monotonic() {
        let e0 = make_envelope(json!({"step": 0}), 5, None)?;
        let e1 = make_envelope(json!({"step": 1}), 5, Some(e0.event_hash))?;

        need(
            ok_when(matches!(
                verify_chain(&[e0, e1]),
                Err(VerifyError::LogicalTimeNotMonotonic {
                    index: 1,
                    previous: 5,
                    current: 5,
                })
            )),
            "equal logical times should produce LogicalTimeNotMonotonic",
        )?;
    }
);

vr_test!(
    fn first_envelope_with_parent_fails() {
        let fake_parent = DigestBytes::from_array([0u8; 32]);
        let e0 = make_envelope(json!({"step": 0}), 1, Some(fake_parent))?;

        need(
            ok_when(matches!(
                verify_chain(&[e0]),
                Err(VerifyError::ChainLinkageBroken { index: 0, .. })
            )),
            "first envelope with parent should produce ChainLinkageBroken at index 0",
        )?;
    }
);
