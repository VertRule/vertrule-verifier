//! Fail-closed ingestion for receipt envelope JSON.
//!
//! All external JSON enters the verifier through this module.
//! Validates schema profile, rejects structural floats, and
//! checks canonical form before deserializing.

use crate::envelope::ReceiptEnvelope;
use crate::error::VerifyError;
use crate::schema_profile::validate_envelope_schema;

/// Structural integer fields that must not contain float literals.
const STRUCTURAL_INTEGER_FIELDS: &[&str] = &["envelope_version", "logical_time"];

/// Ingest a single receipt envelope from raw JSON bytes.
///
/// Performs in order:
/// 1. JSON parse
/// 2. Schema profile validation (unknown/missing fields)
/// 3. Structural float detection
/// 4. Canonical form check
/// 5. Typed deserialization
///
/// # Errors
///
/// Returns the first validation failure encountered.
pub fn ingest_envelope(
    raw_bytes: &[u8],
) -> Result<(serde_json::Value, ReceiptEnvelope), VerifyError> {
    // 1. Parse raw bytes as JSON Value
    let value: serde_json::Value =
        serde_json::from_slice(raw_bytes).map_err(|e| VerifyError::MalformedJson {
            reason: e.to_string(),
        })?;

    // 2. Schema profile validation
    validate_envelope_schema(&value)?;

    // 3. Reject floats in structural integer fields
    reject_structural_floats(&value)?;

    // 4. Canonical form check
    verify_canonical_form(raw_bytes, &value)?;

    // 5. Typed deserialization
    let envelope: ReceiptEnvelope =
        serde_json::from_value(value.clone()).map_err(|e| VerifyError::MalformedJson {
            reason: e.to_string(),
        })?;

    Ok((value, envelope))
}

/// Ingest a chain of receipt envelopes from raw JSON bytes (JSON array).
///
/// # Errors
///
/// Returns the first validation failure encountered across any element.
pub fn ingest_chain(
    raw_bytes: &[u8],
) -> Result<(Vec<serde_json::Value>, Vec<ReceiptEnvelope>), VerifyError> {
    // Parse as array
    let array: serde_json::Value =
        serde_json::from_slice(raw_bytes).map_err(|e| VerifyError::MalformedJson {
            reason: e.to_string(),
        })?;

    let elements = array.as_array().ok_or_else(|| VerifyError::MalformedJson {
        reason: "chain must be a JSON array".to_string(),
    })?;

    if elements.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    // Canonical form: verify the entire array is in JCS canonical form.
    // If the full array is canonical, every element is necessarily canonical.
    verify_canonical_form(raw_bytes, &array)?;

    let mut values = Vec::with_capacity(elements.len());
    let mut envelopes = Vec::with_capacity(elements.len());

    for (i, elem) in elements.iter().enumerate() {
        // Schema profile validation per element
        validate_envelope_schema(elem)?;

        // Float detection per element
        reject_structural_floats(elem)?;

        // Typed deserialization
        let envelope: ReceiptEnvelope =
            serde_json::from_value(elem.clone()).map_err(|e| VerifyError::MalformedJson {
                reason: format!("element {i}: {e}"),
            })?;

        values.push(elem.clone());
        envelopes.push(envelope);
    }

    Ok((values, envelopes))
}

/// Reject float values in structural integer fields.
///
/// Checks `envelope_version` and `logical_time` in the raw JSON Value.
/// A number like `1.0` parses as `is_f64() == true && is_u64() == false`.
fn reject_structural_floats(value: &serde_json::Value) -> Result<(), VerifyError> {
    let Some(obj) = value.as_object() else {
        return Ok(()); // Non-object caught by schema validation
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
///
/// Re-canonicalizes the parsed Value and compares to the input.
fn verify_canonical_form(raw_bytes: &[u8], value: &serde_json::Value) -> Result<(), VerifyError> {
    let canonical = vr_jcs::to_canon_bytes(value).map_err(|e| VerifyError::NonCanonical {
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
