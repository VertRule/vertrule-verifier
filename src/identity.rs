//! Sealed verifier-owned identity newtypes.
//!
//! Domain-specific digest types for verification duties. Each newtype
//! has a domain-named constructor (`recompute_from_*`), private fields,
//! and no raw-bytes constructor. Per JCS Consumer Hardening Plan
//! § Gate 2:
//!
//! - **Verifier helpers MUST be named around verification duties**, not
//!   generic hashing.
//! - Schema-owned identities (receipt commitment, scope, policy) MUST
//!   be recomputed through `vertrule-schemas` constructors. This
//!   module owns only verifier-specific identity classes.
//!
//! ## Identity classes (three-class model)
//!
//! - Canonical JSON identity → `vr-jcs` strategy-bearing digest
//! - Raw domain-label identity → sealed raw-label constructor with marker
//! - Binary payload identity → sealed binary-digest constructor
//!
//! [`SidecarDigest`] is canonical-JSON identity: a sidecar JSON value's
//! `BLAKE3(JCS(value))` identifier used to verify a bundle sidecar
//! matches its declared digest.

use vr_jcs::{CanonicalDigest, DigestAlgorithm, DigestStrategy};

use crate::canonical_identity::digest_trusted_value;
use crate::error::VerifyError;

// ── SidecarDigest ────────────────────────────────────────────────
// Canonical JSON identity for bundle sidecars.

/// Sealed canonical-JSON digest for a bundle sidecar value.
///
/// Wraps [`CanonicalDigest`] so callers cannot confuse a sidecar
/// digest with any other 32-byte value. The inner field is private;
/// the only constructor is [`SidecarDigest::recompute_from_value`].
///
/// Byte-stable with the legacy `digest_canonical_value` function in
/// `bundle.rs` (Gate 2 preservation requirement).
#[derive(Debug, Clone)]
pub struct SidecarDigest {
    inner: CanonicalDigest,
}

impl SidecarDigest {
    /// Recompute the sidecar digest from its canonical-JSON value:
    /// `BLAKE3(JCS(value))`.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::Canon`] if canonicalization or digest
    /// computation fails.
    pub fn recompute_from_value(value: &serde_json::Value) -> Result<Self, VerifyError> {
        let inner = digest_trusted_value(value, &DigestStrategy::blake3_untagged())?;
        Ok(Self { inner })
    }

    /// Stable algorithm-name identifier (`"blake3-untagged"`).
    #[must_use]
    pub const fn algorithm_name(&self) -> &'static str {
        self.inner.algorithm.name()
    }

    /// Borrow the underlying [`DigestAlgorithm`].
    #[must_use]
    pub const fn algorithm(&self) -> &DigestAlgorithm {
        &self.inner.algorithm
    }

    /// Borrow the raw digest bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.inner.bytes
    }

    /// Lowercase-hex string form, matching the receipt-schema wire
    /// format for sidecar digests.
    #[must_use]
    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.inner.bytes)
    }

    /// Consume and return the algorithm-bearing [`CanonicalDigest`].
    #[must_use]
    pub fn into_canonical_digest(self) -> CanonicalDigest {
        self.inner
    }
}

// ── GenericByteDigest ────────────────────────────────────────────
// Binary identity: BLAKE3 over arbitrary input bytes, NOT JCS.

/// Sealed binary-identity digest: `BLAKE3(input_bytes)`.
///
/// Used for inputs that are **not** canonical JSON — e.g. a public key
/// fingerprint, an arbitrary byte blob exposed to a WASM/JS caller. The
/// input bytes are the canonical representation; there is no JSON shape
/// to canonicalize.
///
/// Per the JCS Consumer Hardening Plan's three-class identity model,
/// binary-payload identity is a legitimate non-JCS digest contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenericByteDigest {
    bytes: [u8; 32],
}

impl GenericByteDigest {
    /// Compute `BLAKE3(input)` for arbitrary input bytes.
    ///
    /// # ALLOW-JCS-BYPASS
    ///
    /// Binary payload identity, not canonical JSON identity.
    #[must_use]
    pub fn from_bytes(input: &[u8]) -> Self {
        // ALLOW-JCS-BYPASS: binary payload digest, not canonical JSON identity
        Self {
            bytes: *blake3::hash(input).as_bytes(),
        }
    }

    /// Borrow the raw digest bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Lowercase-hex string form.
    #[must_use]
    pub fn to_hex_string(&self) -> String {
        hex::encode(self.bytes)
    }
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod identity_tests;
