//! Ed25519 signature verification for receipt envelopes.
//!
//! Standalone implementation that mirrors the signing logic in `vertrule-crypto`
//! without importing it, keeping the verifier free of runtime dependencies.
//!
//! ## Domain Separation
//!
//! - `receipt_digest` = `BLAKE3(b"VR-ReceiptDigest|v1|" || JCS(envelope \ {event_hash}))`
//! - `canonical_message` = `b"VR-ReceiptSig|v1|" || receipt_digest_hex || b"|" || timestamp`
//! - Ed25519 signature is over `canonical_message`

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyId(String);

/// Byte width of the V1 key identifier: the **leading** 12 bytes of the
/// digest. Protocol-visible as 24 lowercase hex characters.
const KEY_ID_BYTE_LEN: usize = KEY_ID_HEX_LEN / 2;

impl KeyId {
    /// Derive the V1 key identifier from raw public-key bytes.
    ///
    /// ```text
    /// KeyIdV1(pk) = lowerhex( BLAKE3(pk_bytes)[0..12] )
    /// ```
    ///
    /// Ratified 2026-08-11 exactly as it already existed. The 96-bit width is
    /// **frozen**: the value is protocol-visible (24 hex chars in signature
    /// bundles), so changing the width, the truncation end, or the preimage
    /// encoding is a `KeyIdV2` protocol migration — not digest-authority
    /// cleanup. Pinned by `tests/key_id_v1_law_vectors.rs`.
    ///
    /// Equivalent to the sealed `OpaqueBytesDigest::to_truncated_hex(24)`;
    /// the slice form is used so the constructor stays infallible.
    #[must_use]
    pub fn from_public_key_v1(public_key_bytes: &[u8; 32]) -> Self {
        let digest = vertrule_crypto::identity::OpaqueBytesDigest::compute(public_key_bytes);
        Self(hex::encode(&digest.bytes()[..KEY_ID_BYTE_LEN]))
    }

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Producer-supplied timestamp token used in the canonical signed message.
    ///
    /// Verifiers treat this as an opaque string and bind it exactly into the
    /// signed message. Producers may use RFC 3339 wall-clock time or a
    /// deterministic logical-time string, but they must emit the same string
    /// they originally signed.
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// Verification functions
// ---------------------------------------------------------------------------

/// Compute the domain-separated receipt digest.
///
/// `BLAKE3(prefix || JCS(envelope \ {event_hash}))` — the digest covers
/// all trust-bearing fields, matching the commitment scope of `event_hash`.
///
/// # Errors
///
/// Returns error if JCS canonicalization fails.
pub fn compute_receipt_digest(
    envelope: &vertrule_schemas::ReceiptEnvelope,
) -> Result<DigestBytes, VerifyError> {
    let mut value =
        serde_json::to_value(envelope).map_err(|e| VerifyError::Canon(format!("{e}")))?;
    let serde_json::Value::Object(ref mut map) = value else {
        return Err(VerifyError::Canon(
            "serialized envelope is not a JSON object".to_string(),
        ));
    };
    if map.remove("event_hash").is_none() {
        return Err(VerifyError::SignatureDataMalformed {
            reason: "receipt envelope missing top-level event_hash during digest construction"
                .to_string(),
        });
    }
    let canon_bytes = crate::canon::typed_canon_bytes(&value)?;

    // Law: BLAKE3(RECEIPT_PREFIX ‖ canonical bytes). `RECEIPT_PREFIX` is
    // `&'static`, so the domain is declared rather than caller-supplied —
    // which is what makes the sealed constructor applicable. Byte-neutral.
    let digest = vertrule_crypto::identity::VrPrefixedCanonicalDigest::from_pre_canonicalized_bytes(
        RECEIPT_PREFIX,
        &canon_bytes,
    );

    Ok(DigestBytes::from_array(*digest.bytes()))
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

    // 4. Compute receipt digest (full-envelope commitment)
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

/// Decode a base64 string into a fixed-length byte array.
fn decode_b64_fixed<const N: usize>(b64: &str, label: &str) -> Result<[u8; N], VerifyError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| VerifyError::SignatureDataMalformed {
            reason: format!("invalid {label} base64: {e}"),
        })?;

    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| VerifyError::SignatureDataMalformed {
            reason: format!("{label} wrong length: expected {N}, got {}", bytes.len()),
        })
}

/// Decode a base64 public key into a `VerifyingKey`.
fn decode_public_key(b64: &str) -> Result<VerifyingKey, VerifyError> {
    let pk_array = decode_b64_fixed::<ED25519_PK_LEN>(b64, "public key")?;
    VerifyingKey::from_bytes(&pk_array).map_err(|e| VerifyError::SignatureDataMalformed {
        reason: format!("invalid Ed25519 public key: {e}"),
    })
}

/// Decode a base64 signature into a `Signature`.
fn decode_signature(b64: &str) -> Result<Signature, VerifyError> {
    let sig_array = decode_b64_fixed::<ED25519_SIG_LEN>(b64, "signature")?;
    Ok(Signature::from_bytes(&sig_array))
}

/// Check whether the `key_id` in a signature bundle is consistent with
/// the declared `public_key_b64`.
///
/// Returns `true` when `key_id == hex(BLAKE3(decode(public_key_b64))[..12])`.
/// Returns `false` on decode failure or mismatch — never errors.
#[must_use]
pub fn check_key_id_consistency(bundle: &SignatureBundle) -> bool {
    let Ok(key) = decode_public_key(&bundle.public_key_b64) else {
        return false;
    };
    validate_key_id_matches(&key, &bundle.key_id).is_ok()
}

/// Validate that `key_id` matches the public key.
///
/// `key_id` = `hex(BLAKE3(public_key_bytes)[..12])` = 24 hex chars.
fn validate_key_id_matches(key: &VerifyingKey, expected: &KeyId) -> Result<(), VerifyError> {
    let computed = KeyId::from_public_key_v1(key.as_bytes()).as_hex().to_string();

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
