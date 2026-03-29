//! Fail-closed ingestion for receipt envelope JSON.
//!
//! All external JSON enters the verifier through this module.
//! Validates resource limits, schema profile, rejects structural floats,
//! and checks canonical form before deserializing.

use crate::envelope::ReceiptEnvelope;
use crate::error::VerifyError;
use crate::limits::{self, VerifierLimits};
use crate::schema_profile::validate_envelope_schema;

/// Structural integer fields that must not contain float literals.
const STRUCTURAL_INTEGER_FIELDS: &[&str] = &["envelope_version", "logical_time"];

/// Ingest a single receipt envelope from raw JSON bytes using default limits.
///
/// # Errors
///
/// Returns the first validation failure encountered.
pub fn ingest_envelope(raw_bytes: &[u8]) -> Result<ReceiptEnvelope, VerifyError> {
    ingest_envelope_with_limits(raw_bytes, &VerifierLimits::default())
}

/// Ingest a single receipt envelope with configurable limits.
///
/// Performs in order:
/// 1. Byte-size limit check
/// 2. JSON parse
/// 3. Structural limit checks (depth, node count, object size, array size)
/// 4. Schema profile validation (unknown/missing fields)
/// 5. Structural float detection
/// 6. Canonical form check
/// 7. Typed deserialization
///
/// # Errors
///
/// Returns the first validation failure encountered.
pub fn ingest_envelope_with_limits(
    raw_bytes: &[u8],
    limits: &VerifierLimits,
) -> Result<ReceiptEnvelope, VerifyError> {
    // 1. Byte-size limit
    limits::check_byte_limit(raw_bytes, limits)?;

    // 2. Parse raw bytes as JSON Value
    let value: serde_json::Value =
        serde_json::from_slice(raw_bytes).map_err(|e| VerifyError::MalformedJson {
            reason: e.to_string(),
        })?;

    // 3. Structural limits
    limits::check_structure(&value, limits)?;

    // 4. Schema profile validation
    validate_envelope_schema(&value)?;

    // 5. Reject floats in structural integer fields
    reject_structural_floats(&value)?;

    // 6. Canonical form check
    verify_canonical_form(raw_bytes, &value)?;

    // 7. Typed deserialization
    let envelope: ReceiptEnvelope =
        serde_json::from_value(value).map_err(|e| VerifyError::MalformedJson {
            reason: e.to_string(),
        })?;

    Ok(envelope)
}

/// Ingest a chain of receipt envelopes from raw JSON bytes using default limits.
///
/// # Errors
///
/// Returns the first validation failure encountered across any element.
pub fn ingest_chain(raw_bytes: &[u8]) -> Result<Vec<ReceiptEnvelope>, VerifyError> {
    ingest_chain_with_limits(raw_bytes, &VerifierLimits::default())
}

/// Ingest a chain of receipt envelopes with configurable limits.
///
/// # Errors
///
/// Returns the first validation failure encountered across any element.
pub fn ingest_chain_with_limits(
    raw_bytes: &[u8],
    limits: &VerifierLimits,
) -> Result<Vec<ReceiptEnvelope>, VerifyError> {
    // Byte-size limit
    limits::check_byte_limit(raw_bytes, limits)?;

    // Parse as array
    let array: serde_json::Value =
        serde_json::from_slice(raw_bytes).map_err(|e| VerifyError::MalformedJson {
            reason: e.to_string(),
        })?;

    // Structural limits on the full array
    limits::check_structure(&array, limits)?;

    let serde_json::Value::Array(elements) = array else {
        return Err(VerifyError::MalformedJson {
            reason: "chain must be a JSON array".to_string(),
        });
    };

    if elements.is_empty() {
        return Ok(Vec::new());
    }

    // Chain length limit
    limits::check_chain_length(elements.len(), limits)?;

    // Canonical form: verify the entire array was in JCS canonical form.
    // Re-serialize from owned elements to compare against raw input.
    let array_value = serde_json::Value::Array(elements.clone());
    verify_canonical_form(raw_bytes, &array_value)?;

    let mut envelopes = Vec::with_capacity(elements.len());

    // Take ownership of elements — no per-element clone needed.
    for (i, elem) in elements.into_iter().enumerate() {
        // Schema profile validation per element
        validate_envelope_schema(&elem)?;

        // Float detection per element
        reject_structural_floats(&elem)?;

        // Typed deserialization — consumes the Value, no clone
        let envelope: ReceiptEnvelope =
            serde_json::from_value(elem).map_err(|e| VerifyError::MalformedJson {
                reason: format!("element {i}: {e}"),
            })?;

        envelopes.push(envelope);
    }

    Ok(envelopes)
}

/// Reject float values in structural integer fields.
fn reject_structural_floats(value: &serde_json::Value) -> Result<(), VerifyError> {
    let Some(obj) = value.as_object() else {
        return Ok(());
    };

    for &field in STRUCTURAL_INTEGER_FIELDS {
        if let Some(val) = obj.get(field) {
            if let Some(n) = val.as_number() {
                if n.is_f64() && !n.is_u64() && !n.is_i64() {
                    return Err(VerifyError::FloatInStructuralField {
                        field: field.to_string(),
                    });
                }
            }
        }
    }

    Ok(())
}

/// Verify that the raw input bytes are in JCS canonical form.
fn verify_canonical_form(raw_bytes: &[u8], value: &serde_json::Value) -> Result<(), VerifyError> {
    let canonical =
        vr_jcs::to_canon_bytes(value).map_err(|e| VerifyError::NonCanonical {
            reason: format!("canonicalization failed: {e}"),
        })?;

    if raw_bytes != canonical.as_slice() {
        return Err(VerifyError::NonCanonical {
            reason: "input is not in JCS canonical form".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
#[path = "ingestion_tests.rs"]
mod tests;
