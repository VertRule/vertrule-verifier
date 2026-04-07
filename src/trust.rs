//! Authority-set trust validation for signed receipts.
//!
//! Extends signature self-consistency checks with real trust decisions:
//! is the signing key in a trusted authority set? Is it within epoch?
//! Has it been revoked? Is the timestamp within policy bounds?
//!
//! ## Trust Levels
//!
//! | Status | Meaning |
//! |--------|---------|
//! | `Trusted` | Key is in the active authority set, within epoch, not revoked |
//! | `Untrusted` | Key is not in any authority set |
//! | `Revoked` | Key was in an authority set but has been revoked |
//! | `WrongEpoch` | Key is in the authority set but outside its valid epoch |

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::signature::KeyId;

// ── Authority Set ──────────────────────────────────────────────────

/// A trusted authority set: a collection of public keys with epoch
/// bounds and optional revocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoritySet {
    /// Human-readable identifier for this authority set.
    pub set_id: String,
    /// Trusted keys, indexed by key ID.
    pub keys: BTreeMap<String, AuthorityKey>,
    /// Revoked key IDs with revocation reason.
    pub revocations: BTreeMap<String, Revocation>,
}

/// A single trusted authority key with epoch bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityKey {
    /// Base64-encoded Ed25519 public key.
    pub public_key_b64: String,
    /// Epoch in which this key is valid (inclusive).
    pub valid_from_epoch: u64,
    /// Epoch after which this key is no longer valid (exclusive).
    /// `None` means no upper bound.
    pub valid_until_epoch: Option<u64>,
}

/// A revocation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    /// Why the key was revoked.
    pub reason: String,
    /// Epoch at which revocation took effect.
    pub revoked_at_epoch: u64,
}

impl AuthoritySet {
    /// Create an empty authority set.
    #[must_use]
    pub const fn new(set_id: String) -> Self {
        Self {
            set_id,
            keys: BTreeMap::new(),
            revocations: BTreeMap::new(),
        }
    }

    /// Insert `key` under `key_id`, replacing any previous entry.
    pub fn add_key(&mut self, key_id: String, key: AuthorityKey) {
        self.keys.insert(key_id, key);
    }

    /// Record a revocation for `key_id` (checked before epoch bounds).
    pub fn revoke(&mut self, key_id: String, revocation: Revocation) {
        self.revocations.insert(key_id, revocation);
    }
}

// ── Trust Policy ───────────────────────────────────────────────────

/// Policy for trust validation decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustPolicy {
    /// Current epoch for key validity checking.
    pub current_epoch: u64,
    /// Whether to reject signatures from keys outside their epoch.
    pub enforce_epoch: bool,
    /// Whether to reject signatures from revoked keys.
    pub enforce_revocation: bool,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        Self {
            current_epoch: 1,
            enforce_epoch: true,
            enforce_revocation: true,
        }
    }
}

// ── Trust Decision ─────────────────────────────────────────────────

/// Machine-readable trust status for a signed receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustStatus {
    /// Key is trusted, within epoch, not revoked.
    Trusted,
    /// Key is not in any authority set.
    Untrusted,
    /// Key was in an authority set but has been revoked.
    Revoked,
    /// Key is in the authority set but outside its valid epoch.
    WrongEpoch,
}

impl std::fmt::Display for TrustStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Trusted => f.write_str("trusted"),
            Self::Untrusted => f.write_str("untrusted"),
            Self::Revoked => f.write_str("revoked"),
            Self::WrongEpoch => f.write_str("wrong_epoch"),
        }
    }
}

/// Trust validation result for a signed receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustValidation {
    /// Trust status of the signing key.
    pub status: TrustStatus,
    /// Authority set that was consulted.
    pub authority_set_id: String,
    /// Key ID that was evaluated.
    pub key_id: String,
    /// Current epoch used for evaluation.
    pub evaluated_at_epoch: u64,
    /// Detail message (empty when trusted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

// ── Evaluation ─────────────────────────────────────────────────────

/// Evaluate trust for a key ID against an authority set and policy.
///
/// When `claimed_public_key_b64` is provided, the evaluation also checks
/// that the claimed public key matches the authority set entry. A mismatch
/// produces [`TrustStatus::Untrusted`] — this prevents a valid `key_id` from
/// being paired with a different public key.
///
/// This is a pure function: no I/O, no global state. The caller
/// provides the authority set and policy; the function returns a
/// deterministic trust decision.
#[must_use]
pub fn evaluate_trust(
    key_id: &KeyId,
    authority_set: &AuthoritySet,
    policy: &TrustPolicy,
    claimed_public_key_b64: Option<&str>,
) -> TrustValidation {
    let kid = key_id.as_hex().to_string();

    let result = |status, detail| TrustValidation {
        status,
        authority_set_id: authority_set.set_id.clone(),
        key_id: kid.clone(),
        evaluated_at_epoch: policy.current_epoch,
        detail,
    };

    // Check revocation first (revocation overrides everything)
    if policy.enforce_revocation {
        if let Some(revocation) = authority_set.revocations.get(&kid) {
            return result(
                TrustStatus::Revoked,
                Some(format!(
                    "revoked at epoch {}: {}",
                    revocation.revoked_at_epoch, revocation.reason
                )),
            );
        }
    }

    // Check if key is in the authority set
    let Some(authority_key) = authority_set.keys.get(&kid) else {
        return result(
            TrustStatus::Untrusted,
            Some("key not found in authority set".to_string()),
        );
    };

    // Validate public key matches authority set entry
    if let Some(claimed) = claimed_public_key_b64 {
        if !authority_key.public_key_b64.is_empty() && claimed != authority_key.public_key_b64 {
            return result(
                TrustStatus::Untrusted,
                Some("claimed public_key_b64 does not match authority set entry".to_string()),
            );
        }
    }

    // Check epoch bounds
    if policy.enforce_epoch {
        if policy.current_epoch < authority_key.valid_from_epoch {
            return result(
                TrustStatus::WrongEpoch,
                Some(format!(
                    "current epoch {} is before key's valid_from_epoch {}",
                    policy.current_epoch, authority_key.valid_from_epoch
                )),
            );
        }

        if let Some(until) = authority_key.valid_until_epoch {
            if policy.current_epoch >= until {
                return result(
                    TrustStatus::WrongEpoch,
                    Some(format!(
                        "current epoch {} is at or past key's valid_until_epoch {until}",
                        policy.current_epoch
                    )),
                );
            }
        }
    }

    result(TrustStatus::Trusted, None)
}

#[cfg(test)]
mod tests;
