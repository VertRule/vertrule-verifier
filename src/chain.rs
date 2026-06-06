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

    context_uniform = check_uniform(
        envelopes,
        |e| e.context_digest,
        |i, expected, found| VerifyError::ContextInconsistent {
            index: i,
            expected,
            found,
        },
        &mut errors,
    );

    policy_stable = check_uniform(
        envelopes,
        |e| e.policy_digest,
        |i, expected, found| VerifyError::PolicyInconsistent {
            index: i,
            expected,
            found,
        },
        &mut errors,
    );

    schema_uniform = check_uniform(
        envelopes,
        |e| e.schema_digest,
        |i, expected, found| VerifyError::SchemaInconsistent {
            index: i,
            expected,
            found,
        },
        &mut errors,
    );

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
                previous: prev.logical_time,
                current: curr.logical_time,
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

/// Check that a digest field is uniform across all envelopes (matching the first).
fn check_uniform(
    envelopes: &[ReceiptEnvelope],
    field: fn(&ReceiptEnvelope) -> vertrule_schemas::DigestBytes,
    make_err: fn(
        usize,
        vertrule_schemas::DigestBytes,
        vertrule_schemas::DigestBytes,
    ) -> VerifyError,
    errors: &mut Vec<VerifyError>,
) -> bool {
    let expected = field(&envelopes[0]);
    let mut uniform = true;
    for (i, env) in envelopes.iter().enumerate().skip(1) {
        let found = field(env);
        if found != expected {
            errors.push(make_err(i, expected, found));
            uniform = false;
        }
    }
    uniform
}

/// Verify all chain invariants, returning the first violation found.
///
/// An empty slice is vacuously valid.
///
/// # Errors
///
/// Returns the first [`VerifyError`] from `check_chain_detail`.
pub fn verify_chain(envelopes: &[ReceiptEnvelope]) -> Result<(), VerifyError> {
    let detail = check_chain_detail(envelopes);
    match detail.errors.into_iter().next() {
        Some(e) => Err(e),
        None => Ok(()),
    }
}
