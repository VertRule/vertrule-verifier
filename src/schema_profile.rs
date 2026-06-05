//! Schema profile enforcement for receipt envelope validation.
//!
//! Defines the v1 governance profile: which fields are required, which are
//! optional, and which values are permitted for discriminator fields.
//! Unknown fields and missing required fields cause hard failures.

use crate::error::VerifyError;

/// Schema profile version.
pub const PROFILE_VERSION: &str = "v1";

/// Required fields in a v1 receipt envelope.
const REQUIRED_ENVELOPE_FIELDS: &[&str] = &[
    "envelope_version",
    "receipt_type",
    "context_digest",
    "schema_digest",
    "policy_digest",
    "logical_time",
    "event_hash",
    "payload",
];

/// Optional fields in a v1 receipt envelope.
const OPTIONAL_ENVELOPE_FIELDS: &[&str] = &[
    "parent_id",
    "boundary_origin",
    "digest_algorithm",
    "canonicalization",
    "event_hash_profile",
];

/// Known `receipt_type` values (canonical lowercase only).
const KNOWN_RECEIPT_TYPES: &[&str] = &[
    "event",
    "llm",
    "mri",
    "governance",
    "adapter",
    "projection",
    "training",
    "operation",
    "finalization",
    "abort",
];

/// Known `boundary_origin` values (canonical lowercase only).
const KNOWN_BOUNDARY_ORIGINS: &[&str] = &[
    "engine",
    "adapter",
    "numeric",
    "governance",
    "model",
    "training",
];

/// Validate that a raw JSON value conforms to the v1 envelope schema profile.
///
/// Checks:
/// 1. The value is a JSON object.
/// 2. Every key is either required or optional (no unknown fields).
/// 3. Every required field is present.
/// 4. `receipt_type` is in the known set.
/// 5. `boundary_origin`, if present, is in the known set.
///
/// # Errors
///
/// Returns the first violation found.
pub fn validate_envelope_schema(raw: &serde_json::Value) -> Result<(), VerifyError> {
    let obj = raw.as_object().ok_or_else(|| VerifyError::MalformedJson {
        reason: "envelope must be a JSON object".to_string(),
    })?;

    // Check for unknown fields
    for key in obj.keys() {
        if !is_known_field(key) {
            return Err(VerifyError::UnknownField { field: key.clone() });
        }
    }

    // Check for missing required fields
    for &field in REQUIRED_ENVELOPE_FIELDS {
        if !obj.contains_key(field) {
            return Err(VerifyError::MissingRequiredField {
                field: field.to_string(),
            });
        }
    }

    // Validate receipt_type value
    if let Some(rt) = obj.get("receipt_type").and_then(serde_json::Value::as_str) {
        if !is_known_receipt_type(rt) {
            return Err(VerifyError::UnknownReceiptType {
                value: rt.to_string(),
            });
        }
    }

    // Validate boundary_origin value if present
    if let Some(bo) = obj
        .get("boundary_origin")
        .and_then(serde_json::Value::as_str)
    {
        if !is_known_boundary_origin(bo) {
            return Err(VerifyError::UnknownBoundaryOrigin {
                value: bo.to_string(),
            });
        }
    }

    Ok(())
}

/// Check if a field name is in the known set (required or optional).
fn is_known_field(field: &str) -> bool {
    REQUIRED_ENVELOPE_FIELDS.contains(&field) || OPTIONAL_ENVELOPE_FIELDS.contains(&field)
}

/// Check if a receipt type value is known (exact lowercase match only).
fn is_known_receipt_type(value: &str) -> bool {
    KNOWN_RECEIPT_TYPES.contains(&value)
}

/// Check if a boundary origin value is known (exact lowercase match only).
fn is_known_boundary_origin(value: &str) -> bool {
    KNOWN_BOUNDARY_ORIGINS.contains(&value)
}

#[cfg(test)]
#[path = "schema_profile_tests.rs"]
mod tests;
