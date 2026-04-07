//! Execution bundle verification.
//!
//! Verifies a `vr-execution-bundle/v1` artifact: the canonical receipt
//! envelope plus sidecar digest bindings (`layer_trace`, `selection_policy`).
//!
//! ## Bundle format
//!
//! ```json
//! {
//!   "_format": "vr-execution-bundle/v1",
//!   "envelope_canonical": "<JCS-canonical receipt envelope>",
//!   "sidecars": {
//!     "layer_trace": { ... },
//!     "selection_policy": { ... }
//!   }
//! }
//! ```
//!
//! `envelope_canonical` is a raw JCS string — it is fed directly to the
//! receipt verifier without re-serialization.

use serde::{Deserialize, Serialize};

use crate::error::VerifyError;
use crate::result::{VerificationResult, VerificationStatus};
use crate::schema_profile::PROFILE_VERSION;

/// Expected bundle format identifier.
const EXPECTED_FORMAT: &str = "vr-execution-bundle/v1";

// ── Types ──────────────────────────────────────────────────────────

/// Deserialized execution bundle (input).
#[derive(Debug, Deserialize)]
struct ExecutionBundle {
    #[serde(rename = "_format")]
    format: String,
    envelope_canonical: String,
    #[serde(default)]
    sidecars: BundleSidecars,
}

/// Optional sidecar artifacts within a bundle.
///
/// Unknown sidecar types are silently ignored so the verifier remains
/// forward-compatible with future bundle versions.
#[derive(Debug, Default, Deserialize)]
struct BundleSidecars {
    layer_trace: Option<serde_json::Value>,
    selection_policy: Option<serde_json::Value>,
}

/// Result of verifying a single sidecar digest binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SidecarDigestCheck {
    /// Sidecar name (e.g. `"layer_trace"`).
    pub name: String,
    /// Digest declared in the envelope payload.
    pub expected: String,
    /// Digest recomputed from the sidecar artifact.
    pub computed: String,
    /// Whether the two digests match.
    pub matches: bool,
}

/// Structured result of verifying an execution bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleVerificationResult {
    /// Overall status — `VALID` only when the envelope verifies AND all
    /// sidecar digests match.
    pub status: VerificationStatus,
    /// Schema profile version used for envelope verification.
    pub schema_version: String,
    /// Full envelope verification result.
    pub envelope_result: VerificationResult,
    /// Per-sidecar digest check results.
    pub sidecar_checks: Vec<SidecarDigestCheck>,
    /// Collected error messages (empty when valid).
    pub errors: Vec<String>,
}

impl BundleVerificationResult {
    /// Serialize this result to JCS-canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns error if serialization or canonicalization fails.
    pub fn to_canon_bytes(&self) -> Result<Vec<u8>, VerifyError> {
        let value =
            serde_json::to_value(self).map_err(|e| VerifyError::Canon(format!("{e}")))?;
        crate::canon::typed_canon_bytes(&value)
    }

    /// Serialize this result to a JCS-canonical JSON string.
    ///
    /// # Errors
    ///
    /// Returns error if serialization or canonicalization fails.
    pub fn to_canon_string(&self) -> Result<String, VerifyError> {
        let value =
            serde_json::to_value(self).map_err(|e| VerifyError::Canon(format!("{e}")))?;
        crate::canon::typed_canon_string(&value)
    }
}

// ── Verification ───────────────────────────────────────────────────

/// Verify an execution bundle from raw JSON bytes.
///
/// Performs fail-closed parsing, envelope verification, and sidecar
/// digest rehashing. The result status is `VALID` only when all
/// checks pass.
#[must_use]
pub fn verify_bundle(raw_bytes: &[u8]) -> BundleVerificationResult {
    let bundle: ExecutionBundle = match serde_json::from_slice(raw_bytes) {
        Ok(b) => b,
        Err(e) => return invalid(format!("malformed bundle JSON: {e}")),
    };

    if bundle.format != EXPECTED_FORMAT {
        return invalid(format!(
            "unsupported bundle format: expected \"{EXPECTED_FORMAT}\", got \"{}\"",
            bundle.format
        ));
    }

    // 1. Verify the canonical envelope.
    let envelope_result = crate::verify_receipt(bundle.envelope_canonical.as_bytes());
    let mut errors = Vec::new();

    if envelope_result.status != VerificationStatus::Valid {
        for e in &envelope_result.errors {
            errors.push(format!("envelope: {e}"));
        }
    }

    // 2. Extract digest fields from the envelope payload.
    let payload_digests = extract_payload_digests(&bundle.envelope_canonical);

    // 3. Check each sidecar against its declared digest.
    let mut sidecar_checks = Vec::new();

    if let Some(ref trace) = bundle.sidecars.layer_trace {
        if let Some(ref expected) = payload_digests.layer_trace_digest {
            let check = check_sidecar("layer_trace", expected, trace);
            if !check.matches {
                errors.push(format!(
                    "sidecar layer_trace: digest mismatch (expected {expected}, computed {})",
                    check.computed
                ));
            }
            sidecar_checks.push(check);
        }
    }

    if let Some(ref policy) = bundle.sidecars.selection_policy {
        if let Some(ref expected) = payload_digests.selection_policy_digest {
            let check = check_sidecar("selection_policy", expected, policy);
            if !check.matches {
                errors.push(format!(
                    "sidecar selection_policy: digest mismatch (expected {expected}, computed {})",
                    check.computed
                ));
            }
            sidecar_checks.push(check);
        }
    }

    let status = if envelope_result.status == VerificationStatus::Valid
        && errors.is_empty()
        && sidecar_checks.iter().all(|c| c.matches)
    {
        VerificationStatus::Valid
    } else {
        VerificationStatus::Invalid
    };

    BundleVerificationResult {
        status,
        schema_version: PROFILE_VERSION.to_string(),
        envelope_result,
        sidecar_checks,
        errors,
    }
}

// ── Helpers ────────────────────────────────────────────────────────

/// Digest fields extracted from the envelope payload.
struct PayloadDigests {
    layer_trace_digest: Option<String>,
    selection_policy_digest: Option<String>,
}

/// Extract sidecar digest fields from the canonical envelope JSON.
///
/// Parses the envelope as a raw JSON value and reads string fields
/// from `payload`. Returns `None` for missing or non-string fields.
fn extract_payload_digests(envelope_json: &str) -> PayloadDigests {
    let value: serde_json::Value =
        serde_json::from_str(envelope_json).unwrap_or(serde_json::Value::Null);
    let payload = &value["payload"];

    PayloadDigests {
        layer_trace_digest: payload["layer_trace_digest"]
            .as_str()
            .map(String::from),
        selection_policy_digest: payload["selection_policy_digest"]
            .as_str()
            .map(String::from),
    }
}

/// Compute `BLAKE3(JCS(value))` — the same computation as
/// `vr-browser-runtime/src/canon.rs::digest_canonical`.
fn digest_canonical_value(value: &serde_json::Value) -> Result<String, VerifyError> {
    let json =
        serde_json::to_string(value).map_err(|e| VerifyError::Canon(format!("{e}")))?;
    let canonical = vr_jcs::to_canon_string_from_str(&json)
        .map_err(|e| VerifyError::Canon(format!("{e}")))?;
    let hash = blake3::hash(canonical.as_bytes());
    Ok(hash.to_hex().to_string())
}

/// Check a single sidecar against its expected digest.
fn check_sidecar(name: &str, expected: &str, value: &serde_json::Value) -> SidecarDigestCheck {
    let computed = digest_canonical_value(value).unwrap_or_default();
    SidecarDigestCheck {
        name: name.to_string(),
        expected: expected.to_string(),
        computed: computed.clone(),
        matches: computed == expected,
    }
}

/// Construct an invalid bundle result with a single error.
fn invalid(error: String) -> BundleVerificationResult {
    BundleVerificationResult {
        status: VerificationStatus::Invalid,
        schema_version: PROFILE_VERSION.to_string(),
        envelope_result: VerificationResult::invalid("bundle-level error".to_string()),
        sidecar_checks: Vec::new(),
        errors: vec![error],
    }
}

#[cfg(test)]
#[path = "bundle_tests.rs"]
mod tests;
