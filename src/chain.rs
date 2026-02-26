//! Chain-level verification of receipt envelope sequences.
//!
//! A valid chain satisfies:
//! 1. The first envelope's `parent_id` is `None`.
//! 2. Each subsequent envelope's `parent_id` equals the previous envelope's
//!    `event_hash`.
//! 3. `logical_time` is strictly increasing across consecutive envelopes.
//! 4. All envelopes share the same `context_digest`.
//! 5. All envelopes share the same `policy_digest`.
//! 6. No duplicate `event_hash` values.

use std::collections::BTreeSet;

use crate::envelope::ReceiptEnvelope;
use crate::error::VerifyError;

/// Verify all chain invariants across a sequence of envelopes.
///
/// An empty slice is considered a valid (vacuously true) chain.
///
/// Checks (in order):
/// - First envelope has no parent
/// - Context digest consistency (all match first)
/// - Policy digest consistency (all match first)
/// - Per-pair: parent linkage, logical time monotonicity, duplicate detection
///
/// # Errors
///
/// Returns the first violation found.
pub fn verify_chain(envelopes: &[ReceiptEnvelope]) -> Result<(), VerifyError> {
    if envelopes.is_empty() {
        return Ok(());
    }

    // First envelope must have no parent.
    let first = &envelopes[0];
    if first.parent_id.is_some() {
        return Err(VerifyError::ChainLinkageBroken {
            index: 0,
            expected: None,
            actual: first.parent_id,
        });
    }

    // Context consistency: all must match first envelope.
    let expected_context = &first.context_digest;
    for (i, env) in envelopes.iter().enumerate().skip(1) {
        if env.context_digest != *expected_context {
            return Err(VerifyError::ContextInconsistent {
                index: i,
                expected: *expected_context,
                found: env.context_digest,
            });
        }
    }

    // Policy consistency: all must match first envelope.
    let expected_policy = &first.policy_digest;
    for (i, env) in envelopes.iter().enumerate().skip(1) {
        if env.policy_digest != *expected_policy {
            return Err(VerifyError::PolicyInconsistent {
                index: i,
                expected: *expected_policy,
                found: env.policy_digest,
            });
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
            return Err(VerifyError::DuplicateEventHash {
                index: i,
                digest: curr.event_hash,
            });
        }

        // Parent linkage: current parent_id must equal previous event_hash.
        let expected_parent = Some(prev.event_hash);
        if curr.parent_id != expected_parent {
            return Err(VerifyError::ChainLinkageBroken {
                index: i,
                expected: expected_parent,
                actual: curr.parent_id,
            });
        }

        // Logical time must be strictly increasing.
        if curr.logical_time <= prev.logical_time {
            return Err(VerifyError::LogicalTimeNotMonotonic {
                index: i,
                previous: prev.logical_time,
                current: curr.logical_time,
            });
        }
    }

    Ok(())
}
