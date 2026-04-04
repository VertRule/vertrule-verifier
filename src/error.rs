//! Error types for receipt verification.

use vertrule_schemas::{DefinitionError, DigestBytes};

/// Errors produced during receipt envelope or chain verification.
///
/// Variant-level docs describe the failure; field names are self-documenting.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum VerifyError {
    /// The computed `event_hash` does not match the declared value.
    #[error("event hash mismatch: expected {expected}, actual {actual}")]
    EventHashMismatch {
        expected: DigestBytes,
        actual: DigestBytes,
    },

    /// The `envelope_version` is not in the supported set.
    #[error("unsupported envelope version: {version}")]
    UnsupportedVersion { version: u32 },

    /// A chain link's `parent_id` does not point to the previous envelope's `event_hash`.
    #[error("chain linkage broken at index {index}: expected {expected:?}, actual {actual:?}")]
    ChainLinkageBroken {
        index: usize,
        expected: Option<DigestBytes>,
        actual: Option<DigestBytes>,
    },

    /// `logical_time` did not strictly increase between consecutive envelopes.
    #[error("logical time not monotonic at index {index}: previous {previous}, current {current}")]
    LogicalTimeNotMonotonic {
        index: usize,
        previous: u64,
        current: u64,
    },

    /// Canonicalization of the payload failed.
    #[error("canonicalization error: {0}")]
    Canon(String),

    /// A definition-level validation error (e.g., invalid digest shape).
    #[error(transparent)]
    Definition(#[from] DefinitionError),

    /// An unknown field was present in the envelope JSON.
    #[error("unknown field \"{field}\" in envelope")]
    UnknownField { field: String },

    /// A required field was missing from the envelope JSON.
    #[error("missing required field \"{field}\"")]
    MissingRequiredField { field: String },

    /// The `receipt_type` value is not in the known set.
    #[error("unknown receipt type \"{value}\"")]
    UnknownReceiptType { value: String },

    /// The `boundary_origin` value is not in the known set.
    #[error("unknown boundary origin \"{value}\"")]
    UnknownBoundaryOrigin { value: String },

    /// Duplicate `event_hash` detected in chain.
    #[error("duplicate event_hash at index {index}: {digest}")]
    DuplicateEventHash { index: usize, digest: DigestBytes },

    /// `context_digest` inconsistency across chain.
    #[error("context_digest inconsistency at index {index}: expected {expected}, found {found}")]
    ContextInconsistent {
        index: usize,
        expected: DigestBytes,
        found: DigestBytes,
    },

    /// `policy_digest` inconsistency across chain.
    #[error("policy_digest inconsistency at index {index}: expected {expected}, found {found}")]
    PolicyInconsistent {
        index: usize,
        expected: DigestBytes,
        found: DigestBytes,
    },

    /// `schema_digest` inconsistency across chain.
    #[error("schema_digest inconsistency at index {index}: expected {expected}, found {found}")]
    SchemaInconsistent {
        index: usize,
        expected: DigestBytes,
        found: DigestBytes,
    },

    /// A float value was found in a structural field.
    #[error("float value in structural field \"{field}\"")]
    FloatInStructuralField { field: String },

    /// Input bytes are not in JCS canonical form.
    #[error("non-canonical JSON: {reason}")]
    NonCanonical { reason: String },

    /// Malformed JSON input.
    #[error("malformed JSON: {reason}")]
    MalformedJson { reason: String },

    /// Declared `digest_algorithm` does not match the spec version binding.
    #[error("digest algorithm mismatch: declared \"{declared}\", expected \"{expected}\"")]
    DigestAlgorithmMismatch { declared: String, expected: String },

    /// Declared `canonicalization` does not match the spec version binding.
    #[error("canonicalization mismatch: declared \"{declared}\", expected \"{expected}\"")]
    CanonicalizationMismatch { declared: String, expected: String },

    /// Ed25519 signature verification failed.
    #[error("signature verification failed: {reason}")]
    SignatureInvalid { reason: String },

    /// Signature data is structurally invalid.
    #[error("invalid signature data: {reason}")]
    SignatureDataMalformed { reason: String },

    /// A configurable resource limit was exceeded.
    #[error("limit exceeded: {0}")]
    LimitExceeded(#[from] crate::limits::LimitViolation),

    /// Payload shape constraint violated (e.g., vector length vs `batch_len`).
    #[error("payload shape mismatch: {reason}")]
    PayloadShapeMismatch { reason: String },
}
