//! Top-level verification facade.
//!
//! Provides entry points that compose ingestion, per-envelope checks,
//! and chain verification into a single [`VerificationResult`].
//!
//! Each function is fail-closed: malformed, non-canonical, or otherwise
//! invalid input produces an [`Invalid`](crate::result::VerificationStatus::Invalid)
//! result — never a panic.

use crate::chain::check_chain_detail;
use crate::envelope::{
    verify_algorithms, verify_envelope_version, verify_event_hash, ReceiptEnvelope,
};
use crate::ingestion::{
    ingest_chain, ingest_chain_with_limits, ingest_envelope, ingest_envelope_with_limits,
};
use crate::limits::VerifierLimits;
use crate::result::{
    ChainValidation, ContextConsistency, DigestValidation, PolicyConsistency, SchemaConsistency,
    SignatureValidation, VerificationResult,
};
use crate::signature::{verify_signature, SignatureBundle};

/// Verify a single receipt envelope from raw JSON bytes.
///
/// Performs fail-closed ingestion, envelope version check, and
/// event hash verification. Errors are collected into the result.
#[must_use]
pub fn verify_receipt(raw_bytes: &[u8]) -> VerificationResult {
    match ingest_envelope(raw_bytes) {
        Ok(envelope) => verify_single_envelope(&envelope),
        Err(e) => VerificationResult::invalid(e.to_string()),
    }
}

/// Verify a single receipt envelope with configurable limits.
///
/// Same checks as [`verify_receipt`] but applies `limits` during ingestion
/// to bound input size and JSON structure complexity.
///
/// # Errors
///
/// Limit violations, non-canonical input, version mismatches, and
/// digest failures are collected into the returned result.
#[must_use]
pub fn verify_receipt_with_limits(raw_bytes: &[u8], limits: &VerifierLimits) -> VerificationResult {
    match ingest_envelope_with_limits(raw_bytes, limits) {
        Ok(envelope) => verify_single_envelope(&envelope),
        Err(e) => VerificationResult::invalid(e.to_string()),
    }
}

/// Verify a chain of receipt envelopes from raw JSON bytes (JSON array).
///
/// Performs fail-closed ingestion of each element, per-envelope checks,
/// and chain-level verification (linkage, monotonicity, context/policy
/// consistency, duplicate detection). Errors are collected into the result.
#[must_use]
pub fn verify_receipt_chain(raw_bytes: &[u8]) -> VerificationResult {
    match ingest_chain(raw_bytes) {
        Ok(envelopes) => verify_chain_envelopes(&envelopes),
        Err(e) => VerificationResult::invalid(e.to_string()),
    }
}

/// Verify a chain of receipt envelopes with configurable limits.
///
/// Same checks as [`verify_receipt_chain`] but applies `limits` during
/// ingestion to bound input size, JSON structure complexity, and chain length.
///
/// # Errors
///
/// Limit violations, chain linkage breaks, time monotonicity violations,
/// and consistency failures are collected into the returned result.
#[must_use]
pub fn verify_receipt_chain_with_limits(
    raw_bytes: &[u8],
    limits: &VerifierLimits,
) -> VerificationResult {
    match ingest_chain_with_limits(raw_bytes, limits) {
        Ok(envelopes) => verify_chain_envelopes(&envelopes),
        Err(e) => VerificationResult::invalid(e.to_string()),
    }
}

/// Verify a single receipt envelope with an Ed25519 signature bundle.
///
/// Performs all checks from [`verify_receipt`], then additionally parses the
/// signature bundle and verifies the Ed25519 signature over the
/// domain-separated receipt digest. Errors are collected into the result.
#[must_use]
pub fn verify_signed_receipt(raw_bytes: &[u8], sig_bytes: &[u8]) -> VerificationResult {
    let envelope = match ingest_envelope(raw_bytes) {
        Ok(pair) => pair,
        Err(e) => return VerificationResult::invalid(e.to_string()),
    };

    let mut result = verify_single_envelope(&envelope);
    verify_signature_bundle(&envelope, sig_bytes, &mut result);
    result
}

/// Verify a signed receipt with authority-set trust validation.
///
/// Performs all checks from [`verify_signed_receipt`], then evaluates
/// the signing key against the provided authority set and trust policy.
/// The result includes a [`TrustValidation`](crate::trust::TrustValidation)
/// with machine-readable trust status.
#[must_use]
pub fn verify_signed_receipt_with_trust(
    raw_bytes: &[u8],
    sig_bytes: &[u8],
    authority_set: &crate::trust::AuthoritySet,
    trust_policy: &crate::trust::TrustPolicy,
) -> VerificationResult {
    let envelope = match ingest_envelope(raw_bytes) {
        Ok(pair) => pair,
        Err(e) => return VerificationResult::invalid(e.to_string()),
    };

    let mut result = verify_single_envelope(&envelope);
    let bundle = verify_signature_bundle(&envelope, sig_bytes, &mut result);

    // Trust evaluation requires a successfully parsed bundle.
    if let Some(bundle) = bundle {
        let trust = crate::trust::evaluate_trust(
            &bundle.key_id,
            authority_set,
            trust_policy,
            Some(&bundle.public_key_b64),
        );
        if trust.status != crate::trust::TrustStatus::Trusted {
            result.add_error(format!("trust: {}", trust.status));
        }
        result.trust_validation = Some(trust);
    }

    result
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Run version, algorithm, and event-hash checks on a single envelope.
fn verify_single_envelope(envelope: &ReceiptEnvelope) -> VerificationResult {
    let mut result = VerificationResult::valid_single();

    if let Err(e) = verify_envelope_version(envelope) {
        result.add_error(e.to_string());
    }

    if let Err(e) = verify_algorithms(envelope) {
        result.add_error(e.to_string());
    }

    if let Err(e) = verify_event_hash(envelope) {
        result.digest_validation.all_hashes_match = false;
        result.add_error(e.to_string());
    }

    result
}

/// Assemble a chain result from already-ingested envelopes.
fn verify_chain_envelopes(envelopes: &[ReceiptEnvelope]) -> VerificationResult {
    if envelopes.is_empty() {
        let mut result = VerificationResult::valid_single();
        result.chain_validation = Some(ChainValidation {
            length: 0,
            first_logical_time: 0,
            last_logical_time: 0,
        });
        return result;
    }

    let mut result = VerificationResult::valid_single();
    let all_hashes_match = check_per_envelope(envelopes, &mut result);

    let detail = check_chain_detail(envelopes);
    for e in &detail.errors {
        result.add_error(e.to_string());
    }

    let first = &envelopes[0];
    let last = &envelopes[envelopes.len() - 1];

    result.digest_validation = DigestValidation {
        all_hashes_match,
        chain_integrity: detail.linkage_ok,
        ordering_valid: detail.ordering_ok,
    };

    result.chain_validation = Some(ChainValidation {
        length: envelopes.len(),
        first_logical_time: first.logical_time.get(),
        last_logical_time: last.logical_time.get(),
    });

    result.context_consistency = Some(ContextConsistency {
        uniform_context: detail.context_uniform,
    });

    result.policy_consistency = Some(PolicyConsistency {
        stable_policy: detail.policy_stable,
        transitions_detected: !detail.policy_stable,
    });

    result.schema_consistency = Some(SchemaConsistency {
        uniform_schema: detail.schema_uniform,
    });

    result
}

/// Parse and verify a signature bundle, updating `result` in place.
///
/// Returns the parsed bundle on success (needed for trust evaluation).
fn verify_signature_bundle(
    envelope: &ReceiptEnvelope,
    sig_bytes: &[u8],
    result: &mut VerificationResult,
) -> Option<SignatureBundle> {
    // Present is true because bytes were supplied, regardless of parse success.
    let bundle: SignatureBundle = match serde_json::from_slice(sig_bytes) {
        Ok(b) => b,
        Err(e) => {
            result.add_error(format!("invalid signature bundle: {e}"));
            result.signature_validation = Some(SignatureValidation {
                present: true,
                valid: false,
                key_id_consistent: false,
            });
            return None;
        }
    };

    // Check key_id/public-key consistency independently of signature validity.
    let key_id_consistent =
        crate::signature::check_key_id_consistency(&bundle);

    match verify_signature(envelope, &bundle) {
        Ok(()) => {
            result.signature_validation = Some(SignatureValidation {
                present: true,
                valid: true,
                key_id_consistent,
            });
        }
        Err(e) => {
            result.add_error(e.to_string());
            result.signature_validation = Some(SignatureValidation {
                present: true,
                valid: false,
                key_id_consistent,
            });
            return None;
        }
    }

    Some(bundle)
}

/// Check version and `event_hash` for each envelope. Returns `all_hashes_match`.
fn check_per_envelope(envelopes: &[ReceiptEnvelope], result: &mut VerificationResult) -> bool {
    let mut all_match = true;
    for (i, env) in envelopes.iter().enumerate() {
        if let Err(e) = verify_envelope_version(env) {
            result.add_error(format!("envelope {i}: {e}"));
        }
        if let Err(e) = verify_algorithms(env) {
            result.add_error(format!("envelope {i}: {e}"));
        }
        if let Err(e) = verify_event_hash(env) {
            result.add_error(format!("envelope {i}: {e}"));
            all_match = false;
        }
    }
    all_match
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
