//! Chain-level verification of receipt envelope sequences.
//!
//! A valid chain satisfies:
//! 1. The first envelope's `parent_id` is `None`.
//! 2. Each subsequent envelope's `parent_id` equals the previous envelope's
//!    `event_hash`.
//! 3. `logical_time` is strictly increasing across consecutive envelopes.
//! 4. All envelopes share the same `context_digest`.
//! 5. All envelopes share the same `policy_digest`.
//! 6. All envelopes share the same `schema_digest`.
//! 7. No duplicate `event_hash` values.

use std::collections::BTreeSet;

use crate::envelope::ReceiptEnvelope;
use crate::error::VerifyError;

/// Per-category chain check results for internal reporting.
///
/// Used by [`check_chain_detail`] to collect all violations across categories
/// rather than failing on the first.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct ChainDetail {
    /// Parent linkage and duplicate detection passed.
    pub linkage_ok: bool,
    /// Logical time monotonicity passed.
    pub ordering_ok: bool,
    /// All `context_digest` values match the first.
    pub context_uniform: bool,
    /// All `policy_digest` values match the first.
    pub policy_stable: bool,
    /// All `schema_digest` values match the first.
    pub schema_uniform: bool,
    /// All errors found across all checks.
    pub errors: Vec<VerifyError>,
}

/// Check all chain invariants, collecting every violation.
///
/// Returns a [`ChainDetail`] with per-category booleans and all errors.
/// This is the single source of truth for chain invariant logic.
pub(crate) fn check_chain_detail(envelopes: &[ReceiptEnvelope]) -> ChainDetail {
    let mut errors = Vec::new();
    let mut linkage_ok = true;
    let mut ordering_ok = true;
    let mut context_uniform = true;
    let mut policy_stable = true;
    let mut schema_uniform = true;

    if envelopes.is_empty() {
        return ChainDetail {
            linkage_ok,
            ordering_ok,
            context_uniform,
            policy_stable,
            schema_uniform,
            errors,
        };
    }

    let first = &envelopes[0];

    // First envelope must have no parent.
    if first.parent_id.is_some() {
        errors.push(VerifyError::ChainLinkageBroken {
            index: 0,
            expected: None,
            actual: first.parent_id,
        });
        linkage_ok = false;
    }

    // Context consistency: all must match first envelope.
    let expected_context = &first.context_digest;
    for (i, env) in envelopes.iter().enumerate().skip(1) {
        if env.context_digest != *expected_context {
            errors.push(VerifyError::ContextInconsistent {
                index: i,
                expected: *expected_context,
                found: env.context_digest,
            });
            context_uniform = false;
        }
    }

    // Policy consistency: all must match first envelope.
    let expected_policy = &first.policy_digest;
    for (i, env) in envelopes.iter().enumerate().skip(1) {
        if env.policy_digest != *expected_policy {
            errors.push(VerifyError::PolicyInconsistent {
                index: i,
                expected: *expected_policy,
                found: env.policy_digest,
            });
            policy_stable = false;
        }
    }

    // Schema consistency: all must match first envelope.
    let expected_schema = &first.schema_digest;
    for (i, env) in envelopes.iter().enumerate().skip(1) {
        if env.schema_digest != *expected_schema {
            errors.push(VerifyError::SchemaInconsistent {
                index: i,
                expected: *expected_schema,
                found: env.schema_digest,
            });
            schema_uniform = false;
        }
    }

    // Per-pair checks + duplicate detection.
    let mut seen_hashes = BTreeSet::new();
    seen_hashes.insert(first.event_hash);

    for i in 1..envelopes.len() {
        let prev = &envelopes[i - 1];
        let curr = &envelopes[i];

        // Duplicate event_hash detection.
        if !seen_hashes.insert(curr.event_hash) {
            errors.push(VerifyError::DuplicateEventHash {
                index: i,
                digest: curr.event_hash,
            });
            linkage_ok = false;
        }

        // Parent linkage: current parent_id must equal previous event_hash.
        let expected_parent = Some(prev.event_hash);
        if curr.parent_id != expected_parent {
            errors.push(VerifyError::ChainLinkageBroken {
                index: i,
                expected: expected_parent,
                actual: curr.parent_id,
            });
            linkage_ok = false;
        }

        // Logical time must be strictly increasing.
        if curr.logical_time <= prev.logical_time {
            errors.push(VerifyError::LogicalTimeNotMonotonic {
                index: i,
                previous: prev.logical_time.get(),
                current: curr.logical_time.get(),
            });
            ordering_ok = false;
        }
    }

    ChainDetail {
        linkage_ok,
        ordering_ok,
        context_uniform,
        policy_stable,
        schema_uniform,
        errors,
    }
}

/// Verify all chain invariants across a sequence of envelopes.
///
/// An empty slice is considered a valid (vacuously true) chain.
///
/// Checks (in order):
/// - First envelope has no parent
/// - Context digest consistency (all match first)
/// - Policy digest consistency (all match first)
/// - Schema digest consistency (all match first)
/// - Per-pair: parent linkage, logical time monotonicity, duplicate detection
///
/// # Errors
///
/// Returns the first violation found.
pub fn verify_chain(envelopes: &[ReceiptEnvelope]) -> Result<(), VerifyError> {
    let detail = check_chain_detail(envelopes);
    match detail.errors.into_iter().next() {
        Some(e) => Err(e),
        None => Ok(()),
    }
}
