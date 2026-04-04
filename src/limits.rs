//! Configurable resource limits for receipt verification.
//!
//! Prevents denial-of-service via oversized inputs. All limits have
//! sensible defaults; callers may tighten them via [`VerifierLimits`].

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Configurable resource limits for the verifier.
///
/// Every field has a default that is generous for legitimate receipts
/// but rejects adversarial inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierLimits {
    /// Maximum raw input size in bytes (default: 1 MiB).
    pub max_bytes: usize,
    /// Maximum JSON nesting depth (default: 64).
    pub max_depth: usize,
    /// Maximum total JSON nodes (objects + arrays + scalars) (default: 50 000).
    pub max_node_count: usize,
    /// Maximum keys in any single JSON object (default: 256).
    pub max_object_size: usize,
    /// Maximum elements in any single JSON array (default: 10 000).
    pub max_array_size: usize,
    /// Maximum envelopes in a receipt chain (default: 10 000).
    pub max_chain_length: usize,
}

impl Default for VerifierLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1_048_576,
            max_depth: 64,
            max_node_count: 50_000,
            max_object_size: 256,
            max_array_size: 10_000,
            max_chain_length: 10_000,
        }
    }
}

/// Stable error codes for limit violations.
///
/// Every variant carries `actual` (what was measured) and `limit` (the threshold).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum LimitViolation {
    /// Input exceeds [`VerifierLimits::max_bytes`].
    InputTooLarge { actual: usize, limit: usize },
    /// JSON nesting exceeds [`VerifierLimits::max_depth`].
    DepthExceeded { actual: usize, limit: usize },
    /// Total node count exceeds [`VerifierLimits::max_node_count`].
    NodeCountExceeded { actual: usize, limit: usize },
    /// A single JSON object has too many keys.
    ObjectTooLarge { actual: usize, limit: usize },
    /// A single JSON array has too many elements.
    ArrayTooLarge { actual: usize, limit: usize },
    /// Receipt chain has too many envelopes.
    ChainTooLong { actual: usize, limit: usize },
}

impl std::error::Error for LimitViolation {}

impl std::fmt::Display for LimitViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (label, actual, unit, limit) = match *self {
            Self::InputTooLarge { actual, limit } => ("input too large", actual, "bytes", limit),
            Self::DepthExceeded { actual, limit } => ("depth exceeded", actual, "levels", limit),
            Self::NodeCountExceeded { actual, limit } => {
                ("node count exceeded", actual, "nodes", limit)
            }
            Self::ObjectTooLarge { actual, limit } => ("object too large", actual, "keys", limit),
            Self::ArrayTooLarge { actual, limit } => ("array too large", actual, "elements", limit),
            Self::ChainTooLong { actual, limit } => ("chain too long", actual, "envelopes", limit),
        };
        write!(f, "{label}: {actual} {unit} exceeds limit of {limit}")
    }
}

/// Check raw input byte size against `limits.max_bytes`.
///
/// # Errors
///
/// Returns [`LimitViolation::InputTooLarge`] if exceeded.
pub const fn check_byte_limit(
    raw_bytes: &[u8],
    limits: &VerifierLimits,
) -> Result<(), LimitViolation> {
    if raw_bytes.len() > limits.max_bytes {
        return Err(LimitViolation::InputTooLarge {
            actual: raw_bytes.len(),
            limit: limits.max_bytes,
        });
    }
    Ok(())
}

/// Check chain length against `limits.max_chain_length`.
///
/// # Errors
///
/// Returns [`LimitViolation::ChainTooLong`] if exceeded.
pub const fn check_chain_length(
    length: usize,
    limits: &VerifierLimits,
) -> Result<(), LimitViolation> {
    if length > limits.max_chain_length {
        return Err(LimitViolation::ChainTooLong {
            actual: length,
            limit: limits.max_chain_length,
        });
    }
    Ok(())
}

/// Walk a parsed JSON value and check structural limits (depth, node count,
/// object size, array size).
///
/// # Errors
///
/// Returns the first [`LimitViolation`] encountered.
pub fn check_structure(value: &Value, limits: &VerifierLimits) -> Result<(), LimitViolation> {
    let mut state = WalkState {
        node_count: 0,
        limits,
    };
    walk(value, 0, &mut state)
}

struct WalkState<'a> {
    node_count: usize,
    limits: &'a VerifierLimits,
}

fn walk(value: &Value, depth: usize, state: &mut WalkState<'_>) -> Result<(), LimitViolation> {
    if depth > state.limits.max_depth {
        return Err(LimitViolation::DepthExceeded {
            actual: depth,
            limit: state.limits.max_depth,
        });
    }

    state.node_count += 1;
    if state.node_count > state.limits.max_node_count {
        return Err(LimitViolation::NodeCountExceeded {
            actual: state.node_count,
            limit: state.limits.max_node_count,
        });
    }

    match value {
        Value::Object(map) => {
            if map.len() > state.limits.max_object_size {
                return Err(LimitViolation::ObjectTooLarge {
                    actual: map.len(),
                    limit: state.limits.max_object_size,
                });
            }
            for v in map.values() {
                walk(v, depth + 1, state)?;
            }
        }
        Value::Array(arr) => {
            if arr.len() > state.limits.max_array_size {
                return Err(LimitViolation::ArrayTooLarge {
                    actual: arr.len(),
                    limit: state.limits.max_array_size,
                });
            }
            for v in arr {
                walk(v, depth + 1, state)?;
            }
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests;
