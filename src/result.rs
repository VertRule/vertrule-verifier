//! Structured verification result for the public verifier.
//!
//! Mirrors the SP-ID report schema. Serializable to JCS-canonical JSON.

use serde::{Deserialize, Serialize};

use vertrule_schemas::DigestBytes;

use crate::error::VerifyError;
use crate::schema_profile::PROFILE_VERSION;

/// Serializable output of a verification pass, carrying per-check booleans
/// and any error messages. Serializes to JCS-canonical JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Schema consistency across chain (present only for chain verification).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_consistency: Option<SchemaConsistency>,
    /// Signature validation (present when signature bundle provided).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_validation: Option<SignatureValidation>,
    /// Trust validation (present when authority set provided).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_validation: Option<crate::trust::TrustValidation>,
    /// Error messages (empty when valid).
    pub errors: Vec<String>,
}

/// `VALID` when all checks pass; `INVALID` otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationStatus {
    /// All checks passed (including signature if provided).
    Valid,
    /// One or more checks failed.
    Invalid,
}

/// Per-receipt hash integrity and chain-level ordering checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestValidation {
    /// All `event_hash` values match their recomputed digests.
    pub all_hashes_match: bool,
    /// Chain parent-id linkage is intact (true for single receipts).
    pub chain_integrity: bool,
    /// Logical time ordering is valid (true for single receipts).
    pub ordering_valid: bool,
}

/// Envelope count and logical-time bounds for a verified chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainValidation {
    /// Number of envelopes in the chain.
    pub length: usize,
    /// Logical time of the first envelope.
    pub first_logical_time: u64,
    /// Logical time of the last envelope.
    pub last_logical_time: u64,
}

/// Whether all envelopes in a chain share the same `context_digest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextConsistency {
    /// All envelopes share the same `context_digest`.
    pub uniform_context: bool,
}

/// Whether all envelopes in a chain share the same `policy_digest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyConsistency {
    /// All envelopes share the same `policy_digest`.
    pub stable_policy: bool,
    /// Whether any policy transitions were detected.
    pub transitions_detected: bool,
}

/// Whether all envelopes in a chain share the same `schema_digest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaConsistency {
    /// All envelopes share the same `schema_digest`.
    pub uniform_schema: bool,
}

/// Ed25519 signature presence, validity, and `key_id` self-consistency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureValidation {
    /// Whether a signature bundle was supplied (regardless of parse success).
    /// Malformed bundles still count as present; validity is separate.
    pub present: bool,
    /// Whether the signature verified successfully.
    pub valid: bool,
    /// Whether the `key_id` in the signature bundle is consistent with the
    /// public key (i.e. `key_id == BLAKE3(public_key)[..12]`).
    ///
    /// This is a self-consistency check, NOT a trust or authority assertion.
    /// Trust evaluation is performed separately via
    /// [`verify_signed_receipt_with_trust`](crate::verify::verify_signed_receipt_with_trust).
    pub key_id_consistent: bool,
}

impl std::fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => f.write_str("VALID"),
            Self::Invalid => f.write_str("INVALID"),
        }
    }
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
            schema_consistency: None,
            signature_validation: None,
            trust_validation: None,
            errors: Vec::new(),
        }
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
            schema_consistency: None,
            signature_validation: None,
            trust_validation: None,
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
        let canon_bytes = crate::canon::typed_canon_bytes(&value)?;
        // Law: BLAKE3(JCS(self)). Derivation authority sealed 2026-08-11;
        // byte-neutral, pinned by the batch equivalence vectors.
        let digest = vertrule_crypto::identity::OpaqueBytesDigest::compute(&canon_bytes);
        Ok(DigestBytes::from_array(*digest.bytes()))
    }

    /// Serialize this result to JCS-canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns error if serialization or canonicalization fails.
    pub fn to_canon_bytes(&self) -> Result<Vec<u8>, VerifyError> {
        let value = serde_json::to_value(self).map_err(|e| VerifyError::Canon(e.to_string()))?;
        crate::canon::typed_canon_bytes(&value)
    }

    /// Serialize this result to a JCS-canonical JSON string.
    ///
    /// # Errors
    ///
    /// Returns error if serialization or canonicalization fails.
    pub fn to_canon_string(&self) -> Result<String, VerifyError> {
        let value = serde_json::to_value(self).map_err(|e| VerifyError::Canon(e.to_string()))?;
        crate::canon::typed_canon_string(&value)
    }
}

#[cfg(test)]
#[path = "result_tests.rs"]
mod tests;
