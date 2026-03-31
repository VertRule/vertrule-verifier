//! Tests for `vertrule-verifier`.
//!
//! Uses `vr_test!` from `vr-kernel-testutils` (zero runtime deps).

use serde_json::json;

use crate::chain::verify_chain;
use crate::envelope::{verify_envelope_version, verify_event_hash, ReceiptEnvelope};
use crate::error::VerifyError;
use crate::test_support::{need, ok_when, vr_test};
use vertrule_schemas::CanonicalPayload;
use vertrule_schemas::{DigestBytes, IJsonUInt, ReceiptType, SchemaVersion};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal valid `ReceiptEnvelope`.
fn make_envelope(
    payload: serde_json::Value,
    logical_time: u64,
    parent_id: Option<DigestBytes>,
) -> anyhow::Result<ReceiptEnvelope> {
    let filler = DigestBytes::from_array([0u8; 32]);
    let canonical = CanonicalPayload::new(payload).map_err(|e| anyhow::anyhow!(e))?;
    let lt = IJsonUInt::new(logical_time).map_err(|e| anyhow::anyhow!(e))?;
    let mut envelope = ReceiptEnvelope {
        envelope_version: SchemaVersion::V1,
        receipt_type: ReceiptType::Governance,
        context_digest: filler,
        schema_digest: filler,
        policy_digest: filler,
        logical_time: lt,
        event_hash: filler, // placeholder
        parent_id,
        boundary_origin: None,
        digest_algorithm: None,
        canonicalization: None,
        payload: canonical,
    };
    envelope.event_hash = vertrule_schemas::receipts::compute_event_hash(&envelope)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(envelope)
}

// ---------------------------------------------------------------------------
// Per-envelope tests
// ---------------------------------------------------------------------------

vr_test!(
    fn valid_envelope_passes_event_hash_check() {
        let env = make_envelope(json!({"action": "create", "id": 1}), 1, None)?;
        verify_event_hash(&env)?;
    }
);

vr_test!(
    fn tampered_payload_fails_event_hash_check() {
        let mut env = make_envelope(json!({"action": "create", "id": 1}), 1, None)?;
        env.payload = CanonicalPayload::new(json!({"action": "delete", "id": 1}))
            .map_err(|e| anyhow::anyhow!(e))?;

        need(
            ok_when(matches!(
                verify_event_hash(&env),
                Err(VerifyError::EventHashMismatch { .. })
            )),
            "tampered payload should produce EventHashMismatch",
        )?;
    }
);

vr_test!(
    fn wrong_version_rejected_at_construction() {
        // `SchemaVersion::new` rejects unsupported versions at the type level,
        // so invalid versions can never reach the verifier.
        need(
            ok_when(SchemaVersion::new(99).is_err()),
            "version 99 should be rejected at construction",
        )?;
    }
);

vr_test!(
    fn supported_version_accepted() {
        let env = make_envelope(json!({"x": 1}), 1, None)?;
        verify_envelope_version(&env)?;
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

vr_test!(
    fn schema_digest_inconsistency_detected() {
        let e0 = make_envelope(json!({"step": 0}), 1, None)?;
        let mut e1 = make_envelope(json!({"step": 1}), 2, Some(e0.event_hash))?;
        e1.schema_digest = DigestBytes::from_array([0xffu8; 32]);

        need(
            ok_when(matches!(
                verify_chain(&[e0, e1]),
                Err(VerifyError::SchemaInconsistent { index: 1, .. })
            )),
            "different schema_digest should produce SchemaInconsistent at index 1",
        )?;
    }
);
