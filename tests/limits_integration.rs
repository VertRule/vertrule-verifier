//! Integration tests for resource limits enforcement.

use vertrule_schemas::{
    BoundaryOrigin, CanonicalPayload, DigestBytes, IJsonUInt, ReceiptEnvelope, ReceiptType,
    SchemaVersion,
};
use vr_verifier::limits::VerifierLimits;
use vr_verifier::result::VerificationStatus;

const fn zero_digest() -> DigestBytes {
    DigestBytes::from_array([0u8; 32])
}

fn make_v1_envelope(
    logical_time: u64,
    parent_id: Option<DigestBytes>,
) -> Result<ReceiptEnvelope, anyhow::Error> {
    let payload = CanonicalPayload::new(serde_json::json!({"t": logical_time}))
        .map_err(|e| anyhow::anyhow!(e))?;
    let canon = vr_jcs::to_canon_bytes(payload.as_value())?;
    let event_hash = DigestBytes::from_array(*blake3::hash(&canon).as_bytes());

    Ok(ReceiptEnvelope {
        envelope_version: SchemaVersion::V1,
        receipt_type: ReceiptType::Event,
        context_digest: zero_digest(),
        schema_digest: zero_digest(),
        policy_digest: zero_digest(),
        logical_time: IJsonUInt::new(logical_time)?,
        event_hash,
        parent_id,
        boundary_origin: Some(BoundaryOrigin::Engine),
        digest_algorithm: None,
        canonicalization: None,
        payload,
    })
}

fn build_chain_json(length: usize) -> Result<Vec<u8>, anyhow::Error> {
    let mut envelopes = Vec::with_capacity(length);
    let mut parent: Option<DigestBytes> = None;
    for i in 0..length {
        let t = (i + 1) as u64;
        let envelope = make_v1_envelope(t, parent)?;
        parent = Some(envelope.event_hash);
        envelopes.push(envelope);
    }
    Ok(vr_jcs::to_canon_bytes(&envelopes)?)
}

// ── Byte limit ─────────────────────────────────────────────────────

#[test]
fn oversized_single_envelope_rejected() -> Result<(), anyhow::Error> {
    let limits = VerifierLimits {
        max_bytes: 50,
        ..VerifierLimits::default()
    };
    let envelope = make_v1_envelope(1, None)?;
    let json = vr_jcs::to_canon_string(&envelope)?;
    let result = vr_verifier::verify_receipt_with_limits(json.as_bytes(), &limits);
    assert_eq!(result.status, VerificationStatus::Invalid);
    assert!(result.errors[0].contains("input too large"));
    Ok(())
}

// ── Chain length limit ─────────────────────────────────────────────

#[test]
fn chain_within_limit_passes() -> Result<(), anyhow::Error> {
    let limits = VerifierLimits {
        max_chain_length: 5,
        ..VerifierLimits::default()
    };
    let chain_json = build_chain_json(5)?;
    let result = vr_verifier::verify_receipt_chain_with_limits(&chain_json, &limits);
    assert_eq!(
        result.status,
        VerificationStatus::Valid,
        "5-element chain should pass with limit 5: {:?}",
        result.errors,
    );
    Ok(())
}

#[test]
fn chain_exceeding_limit_rejected() -> Result<(), anyhow::Error> {
    let limits = VerifierLimits {
        max_chain_length: 3,
        ..VerifierLimits::default()
    };
    let chain_json = build_chain_json(4)?;
    let result = vr_verifier::verify_receipt_chain_with_limits(&chain_json, &limits);
    assert_eq!(result.status, VerificationStatus::Invalid);
    assert!(result.errors[0].contains("chain too long"));
    Ok(())
}

// ── Default limits accept normal chains ────────────────────────────

#[test]
fn default_limits_accept_100_chain() -> Result<(), anyhow::Error> {
    let chain_json = build_chain_json(100)?;
    let result = vr_verifier::verify_receipt_chain(&chain_json);
    assert_eq!(
        result.status,
        VerificationStatus::Valid,
        "100-element chain should pass with default limits: {:?}",
        result.errors,
    );
    Ok(())
}

// ── Large chain benchmark ──────────────────────────────────────────

#[test]
fn large_chain_benchmark_1000() -> Result<(), anyhow::Error> {
    let chain_json = build_chain_json(1_000)?;
    let start = std::time::Instant::now();
    let result = vr_verifier::verify_receipt_chain(&chain_json);
    let elapsed = start.elapsed();
    assert_eq!(
        result.status,
        VerificationStatus::Valid,
        "1000-element chain should pass: {:?}",
        result.errors,
    );
    eprintln!(
        "benchmark: 1000-element chain verified in {:.1}ms ({} bytes)",
        elapsed.as_secs_f64() * 1000.0,
        chain_json.len(),
    );
    Ok(())
}

// ── Stable error codes ─────────────────────────────────────────────

#[test]
fn limit_error_codes_stable_in_verification_result() -> Result<(), anyhow::Error> {
    let limits = VerifierLimits {
        max_bytes: 10,
        ..VerifierLimits::default()
    };
    let envelope = make_v1_envelope(1, None)?;
    let json = vr_jcs::to_canon_string(&envelope)?;
    let result = vr_verifier::verify_receipt_with_limits(json.as_bytes(), &limits);
    assert_eq!(result.status, VerificationStatus::Invalid);
    assert_eq!(result.errors.len(), 1);
    assert!(result.errors[0].starts_with("limit exceeded: input too large"));
    Ok(())
}
