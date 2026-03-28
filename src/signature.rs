//! Ed25519 signature verification for receipt envelopes.
//!
//! Standalone implementation that mirrors the signing logic in `vertrule-crypto`
//! without importing it, keeping the verifier free of runtime dependencies.
//!
//! ## Domain Separation
//!
//! - `receipt_digest` = `BLAKE3(b"VR-ReceiptDigest|v1|" || JCS(payload))`
//! - `canonical_message` = `b"VR-ReceiptSig|v1|" || receipt_digest_hex || b"|" || timestamp`
//! - Ed25519 signature is over `canonical_message`

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

use vertrule_schemas::DigestBytes;

use crate::error::VerifyError;

/// Context prefix for receipt digests (domain separation).
const RECEIPT_PREFIX: &[u8] = b"VR-ReceiptDigest|v1|";

/// Context prefix for receipt signatures (domain separation).
const SIGNATURE_PREFIX: &[u8] = b"VR-ReceiptSig|v1|";

/// Expected algorithm string.
const EXPECTED_ALG: &str = "Ed25519";

/// Expected schema version.
const EXPECTED_SCHEMA_VERSION: &str = "0.2";

/// Expected basis identifier for BLAKE3+JCS receipts.
const EXPECTED_BASIS: &str = "BLAKE3+JCS";

/// Ed25519 public key length in bytes.
const ED25519_PK_LEN: usize = 32;

/// Ed25519 signature length in bytes.
const ED25519_SIG_LEN: usize = 64;

/// Key ID length (24 hex chars = 12 bytes of BLAKE3 prefix).
const KEY_ID_HEX_LEN: usize = 24;

// ---------------------------------------------------------------------------
// KeyId newtype
// ---------------------------------------------------------------------------

/// A validated key identifier: exactly 24 lowercase hex characters.
///
/// Derived as `hex(BLAKE3(public_key_bytes)[..12])`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyId(String);

impl KeyId {
    /// Parse and validate a hex string as a `KeyId`.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::SignatureDataMalformed`] if the string is not
    /// exactly 24 lowercase hex characters.
    pub fn from_hex(hex: &str) -> Result<Self, VerifyError> {
        if hex.len() != KEY_ID_HEX_LEN {
            return Err(VerifyError::SignatureDataMalformed {
                reason: format!(
                    "key_id wrong length: expected {KEY_ID_HEX_LEN}, got {}",
                    hex.len()
                ),
            });
        }
        if !hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(VerifyError::SignatureDataMalformed {
                reason: "key_id contains non-lowercase-hex characters".to_string(),
            });
        }
        Ok(Self(hex.to_string()))
    }

    /// Return the inner hex string as a slice.
    #[must_use]
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// SignatureBundle
// ---------------------------------------------------------------------------

/// Signature bundle for verification.
///
/// Mirrors `SignatureData` from `vertrule-crypto` plus the `timestamp` field
/// needed to reconstruct the canonical signed message.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureBundle {
    /// Signature algorithm (must be `"Ed25519"`).
    pub alg: String,
    /// Key ID (24 lowercase hex chars).
    pub key_id: KeyId,
    /// Base64-encoded Ed25519 public key.
    pub public_key_b64: String,
    /// Base64-encoded Ed25519 signature.
    pub signature_b64: String,
    /// Schema version (must be `"0.2"`).
    pub schema_version: String,
    /// Hash basis (must be `"BLAKE3+JCS"`).
    #[serde(rename = "digest_basis")]
    pub basis: String,
    /// RFC 3339 timestamp used in the canonical signed message.
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// Verification functions
// ---------------------------------------------------------------------------

/// Compute the domain-separated receipt digest.
///
/// - **V1**: `BLAKE3(prefix || JCS(payload))`
/// - **V2**: `BLAKE3(prefix || JCS(envelope \ {event_hash}))`
///
/// For V2, the digest covers all trust-bearing fields, matching the
/// commitment scope of `event_hash`.
///
/// # Errors
///
/// Returns error if JCS canonicalization fails.
pub fn compute_receipt_digest(
    envelope: &vertrule_schemas::ReceiptEnvelope,
) -> Result<DigestBytes, VerifyError> {
    let canon_bytes = if envelope.envelope_version.commits_full_envelope() {
        // V2: hash the full envelope minus event_hash
        let mut value =
            serde_json::to_value(envelope).map_err(|e| VerifyError::Canon(format!("{e}")))?;
        if let serde_json::Value::Object(ref mut map) = value {
            map.remove("event_hash");
        }
        vertrule_schemas::jcs::to_canon_bytes(&value)
            .map_err(|e| VerifyError::Canon(format!("{e}")))?
    } else {
        // V1: hash payload only
        vertrule_schemas::jcs::to_canon_bytes(envelope.payload.as_value())
            .map_err(|e| VerifyError::Canon(format!("{e}")))?
    };

    let mut hasher = blake3::Hasher::new();
    hasher.update(RECEIPT_PREFIX);
    hasher.update(&canon_bytes);
    let hash = hasher.finalize();

    Ok(DigestBytes::from_array(*hash.as_bytes()))
}

/// Verify an Ed25519 signature over a receipt payload.
///
/// Steps:
/// 1. Validate algorithm, schema version, and basis
/// 2. Decode and validate public key
/// 3. Verify `key_id` matches public key
/// 4. Compute domain-separated receipt digest
/// 5. Construct canonical message
/// 6. Verify Ed25519 signature
///
/// # Errors
///
/// Returns [`VerifyError::SignatureDataMalformed`] for structural issues,
/// [`VerifyError::SignatureInvalid`] for verification failure.
pub fn verify_signature(
    envelope: &vertrule_schemas::ReceiptEnvelope,
    bundle: &SignatureBundle,
) -> Result<(), VerifyError> {
    // 1. Validate metadata fields
    validate_metadata(bundle)?;

    // 2. Decode public key
    let verifying_key = decode_public_key(&bundle.public_key_b64)?;

    // 3. Verify key ID
    validate_key_id_matches(&verifying_key, &bundle.key_id)?;

    // 4. Compute receipt digest (version-aware: V1=payload, V2=full envelope)
    let receipt_digest = compute_receipt_digest(envelope)?;

    // 5. Construct canonical message
    let canonical_message = construct_canonical_message(&receipt_digest, &bundle.timestamp);

    // 6. Decode and verify signature
    let signature = decode_signature(&bundle.signature_b64)?;

    verifying_key
        .verify(&canonical_message, &signature)
        .map_err(|_| VerifyError::SignatureInvalid {
            reason: "Ed25519 signature verification failed".to_string(),
        })
}

/// Validate the metadata fields of a signature bundle.
fn validate_metadata(bundle: &SignatureBundle) -> Result<(), VerifyError> {
    if bundle.alg != EXPECTED_ALG {
        return Err(VerifyError::SignatureDataMalformed {
            reason: format!(
                "unsupported algorithm: expected {EXPECTED_ALG}, got {}",
                bundle.alg
            ),
        });
    }
    if bundle.schema_version != EXPECTED_SCHEMA_VERSION {
        return Err(VerifyError::SignatureDataMalformed {
            reason: format!(
                "unsupported schema version: expected {EXPECTED_SCHEMA_VERSION}, got {}",
                bundle.schema_version
            ),
        });
    }
    if bundle.basis != EXPECTED_BASIS {
        return Err(VerifyError::SignatureDataMalformed {
            reason: format!(
                "unsupported basis: expected {EXPECTED_BASIS}, got {}",
                bundle.basis
            ),
        });
    }
    Ok(())
}

/// Decode a base64 public key into a `VerifyingKey`.
fn decode_public_key(b64: &str) -> Result<VerifyingKey, VerifyError> {
    let pk_bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| VerifyError::SignatureDataMalformed {
            reason: format!("invalid public key base64: {e}"),
        })?;

    if pk_bytes.len() != ED25519_PK_LEN {
        return Err(VerifyError::SignatureDataMalformed {
            reason: format!(
                "public key wrong length: expected {ED25519_PK_LEN}, got {}",
                pk_bytes.len()
            ),
        });
    }

    let pk_array: [u8; 32] =
        pk_bytes
            .try_into()
            .map_err(|_| VerifyError::SignatureDataMalformed {
                reason: "public key conversion failed".to_string(),
            })?;

    VerifyingKey::from_bytes(&pk_array).map_err(|e| VerifyError::SignatureDataMalformed {
        reason: format!("invalid Ed25519 public key: {e}"),
    })
}

/// Decode a base64 signature into a `Signature`.
fn decode_signature(b64: &str) -> Result<Signature, VerifyError> {
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| VerifyError::SignatureDataMalformed {
            reason: format!("invalid signature base64: {e}"),
        })?;

    if sig_bytes.len() != ED25519_SIG_LEN {
        return Err(VerifyError::SignatureDataMalformed {
            reason: format!(
                "signature wrong length: expected {ED25519_SIG_LEN}, got {}",
                sig_bytes.len()
            ),
        });
    }

    let sig_array: [u8; 64] =
        sig_bytes
            .try_into()
            .map_err(|_| VerifyError::SignatureDataMalformed {
                reason: "signature conversion failed".to_string(),
            })?;

    Ok(Signature::from_bytes(&sig_array))
}

/// Validate that `key_id` matches the public key.
///
/// `key_id` = `hex(BLAKE3(public_key_bytes)[..12])` = 24 hex chars.
fn validate_key_id_matches(key: &VerifyingKey, expected: &KeyId) -> Result<(), VerifyError> {
    let hash = blake3::hash(key.as_bytes());
    let computed = hex::encode(&hash.as_bytes()[..12]);

    if computed != expected.as_hex() {
        return Err(VerifyError::SignatureInvalid {
            reason: format!("key_id mismatch: computed {computed}, declared {expected}"),
        });
    }

    Ok(())
}

/// Construct the canonical message for signature verification.
///
/// Message = `SIGNATURE_PREFIX || receipt_digest.as_hex() || b"|" || timestamp`
fn construct_canonical_message(receipt_digest: &DigestBytes, timestamp: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(SIGNATURE_PREFIX);
    msg.extend_from_slice(receipt_digest.to_hex().as_bytes());
    msg.push(b'|');
    msg.extend_from_slice(timestamp.as_bytes());
    msg
}

#[cfg(test)]
#[path = "signature_tests.rs"]
mod tests;
