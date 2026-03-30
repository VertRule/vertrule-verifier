//! Error types for receipt verification.

use vertrule_schemas::{DefinitionError, DigestBytes};

/// Errors produced during receipt envelope or chain verification.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The computed `event_hash` does not match the declared value.
    #[error("event hash mismatch: expected {expected}, actual {actual}")]
    EventHashMismatch {
        /// The `event_hash` declared in the envelope.
        expected: DigestBytes,
        /// The `event_hash` recomputed from the canonical payload.
        actual: DigestBytes,
    },

    /// The `envelope_version` is not in the supported set.
    #[error("unsupported envelope version: {version}")]
    UnsupportedVersion {
        /// The version found in the envelope.
        version: u32,
    },

    /// A chain link's `parent_id` does not point to the previous envelope's `event_hash`.
    #[error("chain linkage broken at index {index}: expected {expected:?}, actual {actual:?}")]
    ChainLinkageBroken {
        /// Index of the offending envelope in the chain slice.
        index: usize,
        /// The expected `parent_id` (previous envelope's `event_hash`, or `None` for the first).
        expected: Option<DigestBytes>,
        /// The actual `parent_id` found in the envelope.
        actual: Option<DigestBytes>,
    },

    /// `logical_time` did not strictly increase between consecutive envelopes.
    #[error("logical time not monotonic at index {index}: previous {previous}, current {current}")]
    LogicalTimeNotMonotonic {
        /// Index of the offending envelope in the chain slice.
        index: usize,
        /// The `logical_time` of the previous envelope.
        previous: u64,
        /// The `logical_time` of the current envelope.
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
    UnknownField {
        /// The unrecognized field name.
        field: String,
    },

    /// A required field was missing from the envelope JSON.
    #[error("missing required field \"{field}\"")]
    MissingRequiredField {
        /// The missing field name.
        field: String,
    },

    /// The `receipt_type` value is not in the known set.
    #[error("unknown receipt type \"{value}\"")]
    UnknownReceiptType {
        /// The unrecognized receipt type.
        value: String,
    },

    /// The `boundary_origin` value is not in the known set.
    #[error("unknown boundary origin \"{value}\"")]
    UnknownBoundaryOrigin {
        /// The unrecognized boundary origin.
        value: String,
    },

    /// Duplicate `event_hash` detected in chain.
    #[error("duplicate event_hash at index {index}: {digest}")]
    DuplicateEventHash {
        /// Index of the duplicate.
        index: usize,
        /// The duplicated digest.
        digest: DigestBytes,
    },

    /// `context_digest` is not consistent across chain.
    #[error("context_digest inconsistency at index {index}: expected {expected}, found {found}")]
    ContextInconsistent {
        /// Index of the inconsistent envelope.
        index: usize,
        /// The expected `context_digest` (from first envelope).
        expected: DigestBytes,
        /// The actual `context_digest` found.
        found: DigestBytes,
    },

    /// `policy_digest` is not consistent across chain.
    #[error("policy_digest inconsistency at index {index}: expected {expected}, found {found}")]
    PolicyInconsistent {
        /// Index of the inconsistent envelope.
        index: usize,
        /// The expected `policy_digest` (from first envelope).
        expected: DigestBytes,
        /// The actual `policy_digest` found.
        found: DigestBytes,
    },

    /// `schema_digest` is not consistent across chain.
    #[error("schema_digest inconsistency at index {index}: expected {expected}, found {found}")]
    SchemaInconsistent {
        /// Index of the inconsistent envelope.
        index: usize,
        /// The expected `schema_digest` (from first envelope).
        expected: DigestBytes,
        /// The actual `schema_digest` found.
        found: DigestBytes,
    },

    /// A float value was found in a structural field.
    #[error("float value in structural field \"{field}\"")]
    FloatInStructuralField {
        /// The field containing a float.
        field: String,
    },

    /// Input bytes are not in JCS canonical form.
    #[error("non-canonical JSON: {reason}")]
    NonCanonical {
        /// Why the input is non-canonical.
        reason: String,
    },

    /// Malformed JSON input.
    #[error("malformed JSON: {reason}")]
    MalformedJson {
        /// Parse error description.
        reason: String,
    },

    /// Declared `digest_algorithm` does not match the spec version binding.
    #[error("digest algorithm mismatch: declared \"{declared}\", expected \"{expected}\"")]
    DigestAlgorithmMismatch {
        /// The algorithm declared in the envelope.
        declared: String,
        /// The algorithm required by the spec version.
        expected: String,
    },

    /// Declared `canonicalization` does not match the spec version binding.
    #[error("canonicalization mismatch: declared \"{declared}\", expected \"{expected}\"")]
    CanonicalizationMismatch {
        /// The canonicalization declared in the envelope.
        declared: String,
        /// The canonicalization required by the spec version.
        expected: String,
    },

    /// Ed25519 signature verification failed.
    #[error("signature verification failed: {reason}")]
    SignatureInvalid {
        /// Why verification failed.
        reason: String,
    },

    /// Signature data is structurally invalid.
    #[error("invalid signature data: {reason}")]
    SignatureDataMalformed {
        /// What is wrong with the signature data.
        reason: String,
    },

    /// A configurable resource limit was exceeded.
    #[error("limit exceeded: {0}")]
    LimitExceeded(#[from] crate::limits::LimitViolation),

    /// Payload shape constraint violated (e.g., vector length vs `batch_len`).
    #[error("payload shape mismatch: {reason}")]
    PayloadShapeMismatch {
        /// What shape constraint was violated.
        reason: String,
    },
}
