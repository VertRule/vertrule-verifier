//! Structured verification result for the public verifier.
//!
//! Mirrors the SP-ID report schema. Serializable to JCS-canonical JSON.

use serde::Serialize;

use vertrule_schemas::DigestBytes;

use crate::error::VerifyError;
use crate::schema_profile::PROFILE_VERSION;

/// Top-level verification result.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationResult {
    /// Overall status.
    pub status: VerificationStatus,
    /// Schema profile version used for verification.
    pub schema_version: String,
    /// Digest validation results.
    pub digest_validation: DigestValidation,
    /// Chain-level validation (present only for chain verification).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_validation: Option<ChainValidation>,
    /// Context consistency across chain (present only for chain verification).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_consistency: Option<ContextConsistency>,
    /// Policy consistency across chain (present only for chain verification).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_consistency: Option<PolicyConsistency>,
    /// Signature validation (present when signature bundle provided).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_validation: Option<SignatureValidation>,
    /// Error messages (empty when valid).
    pub errors: Vec<String>,
}

/// Verification status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationStatus {
    /// All checks passed (including signature if provided).
    Valid,
    /// One or more checks failed.
    Invalid,
    /// All structural checks passed but no signature was provided.
    Unsigned,
}

/// Digest-level validation results.
#[derive(Debug, Clone, Serialize)]
pub struct DigestValidation {
    /// All `event_hash` values match their recomputed digests.
    pub all_hashes_match: bool,
    /// Chain parent-id linkage is intact (true for single receipts).
    pub chain_integrity: bool,
    /// Logical time ordering is valid (true for single receipts).
    pub ordering_valid: bool,
}

/// Chain-level validation metadata.
#[derive(Debug, Clone, Serialize)]
pub struct ChainValidation {
    /// Number of envelopes in the chain.
    pub length: usize,
    /// Logical time of the first envelope.
    pub first_logical_time: u64,
    /// Logical time of the last envelope.
    pub last_logical_time: u64,
}

/// Context digest consistency across a chain.
#[derive(Debug, Clone, Serialize)]
pub struct ContextConsistency {
    /// All envelopes share the same `context_digest`.
    pub uniform_context: bool,
}

/// Policy digest consistency across a chain.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyConsistency {
    /// All envelopes share the same `policy_digest`.
    pub stable_policy: bool,
    /// Whether any policy transitions were detected.
    pub transitions_detected: bool,
}

/// Signature validation results.
#[derive(Debug, Clone, Serialize)]
pub struct SignatureValidation {
    /// Whether a signature bundle was provided.
    pub present: bool,
    /// Whether the signature verified successfully.
    pub valid: bool,
    /// Whether the `key_id` in the signature bundle is consistent with the
    /// public key (i.e. `key_id == BLAKE3(public_key)[..12]`).
    ///
    /// This is a self-consistency check, NOT a trust or authority assertion.
    /// It does not verify that the key belongs to a trusted party, is
    /// registered in any authority set, or has governance approval.
    /// Real authority verification requires a trust store (future work).
    pub key_id_consistent: bool,
}

impl VerificationResult {
    /// Create a new valid result for a single receipt.
    #[must_use]
    pub fn valid_single() -> Self {
        Self {
            status: VerificationStatus::Valid,
            schema_version: PROFILE_VERSION.to_string(),
            digest_validation: DigestValidation {
                all_hashes_match: true,
                chain_integrity: true,
                ordering_valid: true,
            },
            chain_validation: None,
            context_consistency: None,
            policy_consistency: None,
            signature_validation: None,
            errors: Vec::new(),
        }
    }

    /// Create a new unsigned result for a single receipt (structurally valid, no signature).
    #[must_use]
    pub fn unsigned_single() -> Self {
        let mut result = Self::valid_single();
        result.status = VerificationStatus::Unsigned;
        result.signature_validation = Some(SignatureValidation {
            present: false,
            valid: false,
            key_id_consistent: false,
        });
        result
    }

    /// Create an invalid result with the given error.
    #[must_use]
    pub fn invalid(error: String) -> Self {
        Self {
            status: VerificationStatus::Invalid,
            schema_version: PROFILE_VERSION.to_string(),
            digest_validation: DigestValidation {
                all_hashes_match: false,
                chain_integrity: false,
                ordering_valid: false,
            },
            chain_validation: None,
            context_consistency: None,
            policy_consistency: None,
            signature_validation: None,
            errors: vec![error],
        }
    }

    /// Add an error and set status to invalid.
    pub fn add_error(&mut self, error: String) {
        self.status = VerificationStatus::Invalid;
        self.errors.push(error);
    }

    /// Compute the BLAKE3 digest of this result's JCS-canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns error if canonicalization fails.
    pub fn digest(&self) -> Result<DigestBytes, VerifyError> {
        let value = serde_json::to_value(self).map_err(|e| VerifyError::Canon(e.to_string()))?;
        let canon_bytes =
            vertrule_schemas::jcs::to_canon_bytes(&value).map_err(|e| VerifyError::Canon(format!("{e}")))?;
        let hash = blake3::hash(&canon_bytes);
        Ok(DigestBytes::from_array(*hash.as_bytes()))
    }
}

#[cfg(test)]
#[path = "result_tests.rs"]
mod tests;
