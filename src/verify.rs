//! Top-level verification facade.
//!
//! Provides entry points that compose ingestion, per-envelope checks,
//! and chain verification into a single [`VerificationResult`].
//!
//! Each function is fail-closed: malformed, non-canonical, or otherwise
//! invalid input produces an [`Invalid`](crate::result::VerificationStatus::Invalid)
//! result — never a panic.

use std::collections::BTreeSet;

use crate::envelope::ReceiptEnvelope;
use crate::ingestion::{ingest_chain, ingest_envelope};
use crate::result::{
    ChainValidation, ContextConsistency, DigestValidation, PolicyConsistency, SignatureValidation,
    VerificationResult,
};
use crate::signature::{verify_signature, SignatureBundle};

/// Verify a single receipt envelope from raw JSON bytes.
///
/// Performs fail-closed ingestion, envelope version check, and
/// event hash verification. Errors are collected into the result.
#[must_use]
pub fn verify_receipt(raw_bytes: &[u8]) -> VerificationResult {
    let (_value, envelope) = match ingest_envelope(raw_bytes) {
        Ok(pair) => pair,
        Err(e) => return VerificationResult::invalid(e.to_string()),
    };

    let mut result = VerificationResult::valid_single();

    if let Err(e) = envelope.verify_envelope_version() {
        result.add_error(e.to_string());
    }

    if let Err(e) = envelope.verify_event_hash() {
        result.digest_validation.all_hashes_match = false;
        result.add_error(e.to_string());
    }

    result
}

/// Verify a chain of receipt envelopes from raw JSON bytes (JSON array).
///
/// Performs fail-closed ingestion of each element, per-envelope checks,
/// and chain-level verification (linkage, monotonicity, context/policy
/// consistency, duplicate detection). Errors are collected into the result.
#[must_use]
pub fn verify_receipt_chain(raw_bytes: &[u8]) -> VerificationResult {
    let (_values, envelopes) = match ingest_chain(raw_bytes) {
        Ok(pair) => pair,
        Err(e) => return VerificationResult::invalid(e.to_string()),
    };

    if envelopes.is_empty() {
        return VerificationResult::valid_single();
    }

    let mut result = VerificationResult::valid_single();

    // Per-envelope checks
    let all_hashes_match = check_per_envelope(&envelopes, &mut result);

    // Chain-level checks (each computed independently)
    let chain_integrity = check_linkage_and_duplicates(&envelopes, &mut result);
    let ordering_valid = check_ordering(&envelopes, &mut result);
    let uniform_context = check_context_consistency(&envelopes, &mut result);
    let (stable_policy, transitions_detected) = check_policy_consistency(&envelopes, &mut result);

    // Assemble result fields
    let first = &envelopes[0];
    let last = &envelopes[envelopes.len() - 1];

    result.digest_validation = DigestValidation {
        all_hashes_match,
        chain_integrity,
        ordering_valid,
    };

    result.chain_validation = Some(ChainValidation {
        length: envelopes.len(),
        first_logical_time: first.logical_time,
        last_logical_time: last.logical_time,
    });

    result.context_consistency = Some(ContextConsistency { uniform_context });

    result.policy_consistency = Some(PolicyConsistency {
        stable_policy,
        transitions_detected,
    });

    result
}

/// Verify a single receipt envelope with an Ed25519 signature bundle.
///
/// Performs all checks from [`verify_receipt`], then additionally parses the
/// signature bundle and verifies the Ed25519 signature over the
/// domain-separated receipt digest. Errors are collected into the result.
#[must_use]
pub fn verify_signed_receipt(raw_bytes: &[u8], sig_bytes: &[u8]) -> VerificationResult {
    let (_value, envelope) = match ingest_envelope(raw_bytes) {
        Ok(pair) => pair,
        Err(e) => return VerificationResult::invalid(e.to_string()),
    };

    let mut result = VerificationResult::valid_single();

    if let Err(e) = envelope.verify_envelope_version() {
        result.add_error(e.to_string());
    }

    if let Err(e) = envelope.verify_event_hash() {
        result.digest_validation.all_hashes_match = false;
        result.add_error(e.to_string());
    }

    // Parse signature bundle
    let bundle: SignatureBundle = match serde_json::from_slice(sig_bytes) {
        Ok(b) => b,
        Err(e) => {
            result.add_error(format!("invalid signature bundle: {e}"));
            result.signature_validation = Some(SignatureValidation {
                present: false,
                valid: false,
                authority_verified: false,
            });
            return result;
        }
    };

    // Verify signature over the payload (not the whole envelope)
    match verify_signature(&envelope.payload, &bundle) {
        Ok(()) => {
            result.signature_validation = Some(SignatureValidation {
                present: true,
                valid: true,
                authority_verified: true,
            });
        }
        Err(e) => {
            result.add_error(e.to_string());
            let present = !matches!(e, crate::error::VerifyError::SignatureDataMalformed { .. });
            result.signature_validation = Some(SignatureValidation {
                present,
                valid: false,
                authority_verified: false,
            });
        }
    }

    result
}

/// Check version and `event_hash` for each envelope. Returns `all_hashes_match`.
fn check_per_envelope(envelopes: &[ReceiptEnvelope], result: &mut VerificationResult) -> bool {
    let mut all_match = true;
    for (i, env) in envelopes.iter().enumerate() {
        if let Err(e) = env.verify_envelope_version() {
            result.add_error(format!("envelope {i}: {e}"));
        }
        if let Err(e) = env.verify_event_hash() {
            result.add_error(format!("envelope {i}: {e}"));
            all_match = false;
        }
    }
    all_match
}

/// Check parent linkage and duplicate `event_hash`. Returns `chain_integrity`.
fn check_linkage_and_duplicates(
    envelopes: &[ReceiptEnvelope],
    result: &mut VerificationResult,
) -> bool {
    let mut ok = envelopes[0].parent_id.is_none();
    if !ok {
        result.add_error("first envelope must not have parent_id".to_string());
    }

    let mut seen = BTreeSet::new();
    seen.insert(envelopes[0].event_hash.to_hex());

    for i in 1..envelopes.len() {
        if !seen.insert(envelopes[i].event_hash.to_hex()) {
            result.add_error(format!(
                "duplicate event_hash at index {i}: {}",
                envelopes[i].event_hash
            ));
            ok = false;
        }
        let expected = Some(envelopes[i - 1].event_hash);
        if envelopes[i].parent_id != expected {
            result.add_error(format!(
                "chain linkage broken at index {i}: expected {expected:?}, actual {:?}",
                envelopes[i].parent_id
            ));
            ok = false;
        }
    }

    ok
}

/// Check logical time monotonicity. Returns `ordering_valid`.
fn check_ordering(envelopes: &[ReceiptEnvelope], result: &mut VerificationResult) -> bool {
    let mut ok = true;
    for (i, pair) in envelopes.windows(2).enumerate() {
        if pair[1].logical_time <= pair[0].logical_time {
            result.add_error(format!(
                "logical time not monotonic at index {}: {} <= {}",
                i + 1,
                pair[1].logical_time,
                pair[0].logical_time
            ));
            ok = false;
        }
    }
    ok
}

/// Check `context_digest` consistency. Returns `uniform_context`.
fn check_context_consistency(
    envelopes: &[ReceiptEnvelope],
    result: &mut VerificationResult,
) -> bool {
    let expected = &envelopes[0].context_digest;
    let mut uniform = true;
    for (i, env) in envelopes.iter().enumerate().skip(1) {
        if env.context_digest != *expected {
            result.add_error(format!(
                "context_digest inconsistency at index {i}: expected {expected}, found {}",
                env.context_digest
            ));
            uniform = false;
        }
    }
    uniform
}

/// Check `policy_digest` consistency. Returns `(stable_policy, transitions_detected)`.
fn check_policy_consistency(
    envelopes: &[ReceiptEnvelope],
    result: &mut VerificationResult,
) -> (bool, bool) {
    let expected = &envelopes[0].policy_digest;
    let mut stable = true;
    for (i, env) in envelopes.iter().enumerate().skip(1) {
        if env.policy_digest != *expected {
            result.add_error(format!(
                "policy_digest inconsistency at index {i}: expected {expected}, found {}",
                env.policy_digest
            ));
            stable = false;
        }
    }
    (stable, !stable)
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
