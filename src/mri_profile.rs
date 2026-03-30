//! Payload-level validation for MRI batch-aware receipts.
//!
//! This module validates the *structure* of an MRI batch payload
//! after it has been successfully parsed. Unknown enum variants
//! (e.g., an unrecognized `ReductionMode`) are parse failures
//! handled by serde — not semantic checks here.
//!
//! Checks performed:
//! - Per-example vector present → `batch_len` must be present
//! - `batch_len` present + vector present → lengths must match
//! - Per-example vector present → `provenance` must be present (always is, since required field)

use vertrule_schemas::{GradientCouplingPayload, MriBatchPayload};

use crate::error::VerifyError;

/// Expected schema identifier for gradient coupling payloads.
const GRADIENT_COUPLING_SCHEMA: &str = "mri2.gradient_coupling@0.1";

/// Validate the structural invariants of an [`MriBatchPayload`].
///
/// This does NOT check enum variant validity (that is a parse failure)
/// or cryptographic commitments (that is envelope-level verification).
/// It checks shape constraints that are only meaningful after
/// successful deserialization.
///
/// # Errors
///
/// Returns [`VerifyError::PayloadShapeMismatch`] if:
/// - `q_per_example` is present but `batch_len` is absent
/// - `q_per_example` length does not equal `batch_len`
pub fn validate_mri_batch_payload(payload: &MriBatchPayload) -> Result<(), VerifyError> {
    check_vector_field(
        payload.batch_len,
        payload.q_per_example.as_ref(),
        "q_per_example",
    )?;
    check_vector_field(
        payload.batch_len,
        payload.e_per_example.as_ref(),
        "e_per_example",
    )?;
    check_vector_field(
        payload.batch_len,
        payload.h_per_example.as_ref(),
        "h_per_example",
    )?;
    check_vector_field(
        payload.batch_len,
        payload.c_per_example.as_ref(),
        "c_per_example",
    )?;

    if let Some(ref mask) = payload.degenerate_mask {
        let Some(batch_len) = payload.batch_len else {
            return Err(VerifyError::PayloadShapeMismatch {
                reason: "degenerate_mask present but batch_len is absent".to_string(),
            });
        };
        let expected = batch_len as usize;
        if mask.len() != expected {
            return Err(VerifyError::PayloadShapeMismatch {
                reason: format!(
                    "degenerate_mask length {actual} does not match batch_len {expected}",
                    actual = mask.len(),
                ),
            });
        }
    }

    Ok(())
}

/// Validate the structural invariants of a [`GradientCouplingPayload`].
///
/// # Checks
/// - `schema` must equal `"mri2.gradient_coupling@0.1"`
/// - `num_layers` must be > 0
/// - All vector fields must have length == `num_layers`
/// - All decoded `F32Bits` values must be finite
/// - `profile_cosine` decoded value must be in `[-1.0, 1.0]`
///
/// # Errors
///
/// Returns [`VerifyError::PayloadShapeMismatch`] on any violation.
pub fn validate_gradient_coupling_payload(
    payload: &GradientCouplingPayload,
) -> Result<(), VerifyError> {
    // Schema identity
    if payload.schema != GRADIENT_COUPLING_SCHEMA {
        return Err(VerifyError::PayloadShapeMismatch {
            reason: format!(
                "schema must be \"{GRADIENT_COUPLING_SCHEMA}\", got \"{}\"",
                payload.schema,
            ),
        });
    }

    // Non-zero layers
    if payload.num_layers == 0 {
        return Err(VerifyError::PayloadShapeMismatch {
            reason: "num_layers must be > 0".to_string(),
        });
    }

    let n = payload.num_layers as usize;

    // Vector lengths
    check_fixed_vector(n, &payload.grad_q_norms, "grad_q_norms")?;
    check_fixed_vector(n, &payload.grad_lm_norms, "grad_lm_norms")?;
    check_fixed_vector(n, &payload.coupling_ratios, "coupling_ratios")?;

    // Finite floats
    check_all_finite(&payload.grad_q_norms, "grad_q_norms")?;
    check_all_finite(&payload.grad_lm_norms, "grad_lm_norms")?;
    check_all_finite(&payload.coupling_ratios, "coupling_ratios")?;

    let cosine = f32::from_bits(payload.profile_cosine);
    if !cosine.is_finite() {
        return Err(VerifyError::PayloadShapeMismatch {
            reason: format!("profile_cosine is not finite: {cosine}"),
        });
    }
    if !(-1.0..=1.0).contains(&cosine) {
        return Err(VerifyError::PayloadShapeMismatch {
            reason: format!("profile_cosine {cosine} is outside [-1.0, 1.0]"),
        });
    }

    Ok(())
}

/// Check a required fixed-length vector field against expected length.
fn check_fixed_vector(expected: usize, field: &[u32], name: &str) -> Result<(), VerifyError> {
    if field.len() != expected {
        return Err(VerifyError::PayloadShapeMismatch {
            reason: format!(
                "{name} length {actual} does not match num_layers {expected}",
                actual = field.len(),
            ),
        });
    }
    Ok(())
}

/// Check that all F32Bits-encoded values in a vector are finite.
fn check_all_finite(field: &[u32], name: &str) -> Result<(), VerifyError> {
    for (i, &bits) in field.iter().enumerate() {
        let val = f32::from_bits(bits);
        if !val.is_finite() {
            return Err(VerifyError::PayloadShapeMismatch {
                reason: format!("{name}[{i}] is not finite: {val}"),
            });
        }
    }
    Ok(())
}

/// Check a single optional per-example vector field against `batch_len`.
fn check_vector_field(
    batch_len: Option<u32>,
    field: Option<&Vec<u32>>,
    name: &str,
) -> Result<(), VerifyError> {
    if let Some(vec) = field {
        let Some(batch_len) = batch_len else {
            return Err(VerifyError::PayloadShapeMismatch {
                reason: format!("{name} present but batch_len is absent"),
            });
        };
        let expected = batch_len as usize;
        if vec.len() != expected {
            return Err(VerifyError::PayloadShapeMismatch {
                reason: format!(
                    "{name} length {actual} does not match batch_len {expected}",
                    actual = vec.len(),
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vertrule_schemas::{
        BatchReduction, ReductionAxis, ReductionMode, ReductionProvenance, TokenReduction,
    };

    fn sample_provenance() -> ReductionProvenance {
        ReductionProvenance {
            reduction_mode: ReductionMode::PerExampleThenMean,
            reduced_axes: vec![
                ReductionAxis::Token,
                ReductionAxis::Hidden,
                ReductionAxis::Batch,
            ],
            token_reduction: TokenReduction::Mean,
            batch_reduction: BatchReduction::Mean,
        }
    }

    fn scalar_only() -> MriBatchPayload {
        MriBatchPayload {
            schema: "mri2.batch_invariant@0.1".to_string(),
            layer: 0,
            q_scalar: 0x3F80_0000,
            e_scalar: None,
            h_scalar: None,
            c_scalar: None,
            provenance: sample_provenance(),
            batch_len: None,
            q_per_example: None,
            e_per_example: None,
            h_per_example: None,
            c_per_example: None,
            degenerate_mask: None,
        }
    }

    #[test]
    fn scalar_only_passes() {
        assert!(validate_mri_batch_payload(&scalar_only()).is_ok());
    }

    #[test]
    fn valid_vector_passes() {
        let mut p = scalar_only();
        p.batch_len = Some(3);
        p.q_per_example = Some(vec![0x3F80_0000, 0x4000_0000, 0x4040_0000]);
        assert!(validate_mri_batch_payload(&p).is_ok());
    }

    #[test]
    fn vector_without_batch_len_rejected() -> Result<(), anyhow::Error> {
        let mut p = scalar_only();
        p.q_per_example = Some(vec![0x3F80_0000]);
        let Err(err) = validate_mri_batch_payload(&p) else {
            return Err(anyhow::anyhow!("expected validation to fail"));
        };
        let VerifyError::PayloadShapeMismatch { ref reason } = err else {
            return Err(anyhow::anyhow!("expected PayloadShapeMismatch, got: {err}"));
        };
        assert!(reason.contains("batch_len is absent"), "got: {reason}");
        Ok(())
    }

    #[test]
    fn vector_length_mismatch_rejected() -> Result<(), anyhow::Error> {
        let mut p = scalar_only();
        p.batch_len = Some(4);
        p.q_per_example = Some(vec![0x3F80_0000, 0x4000_0000]);
        let Err(err) = validate_mri_batch_payload(&p) else {
            return Err(anyhow::anyhow!("expected validation to fail"));
        };
        let VerifyError::PayloadShapeMismatch { ref reason } = err else {
            return Err(anyhow::anyhow!("expected PayloadShapeMismatch, got: {err}"));
        };
        assert!(reason.contains("does not match"), "got: {reason}");
        Ok(())
    }

    #[test]
    fn batch_len_without_vector_passes() {
        let mut p = scalar_only();
        p.batch_len = Some(8);
        assert!(validate_mri_batch_payload(&p).is_ok());
    }

    #[test]
    fn empty_vector_with_zero_batch_len_passes() {
        let mut p = scalar_only();
        p.batch_len = Some(0);
        p.q_per_example = Some(vec![]);
        assert!(validate_mri_batch_payload(&p).is_ok());
    }

    #[test]
    fn e_per_example_without_batch_len_rejected() {
        let mut p = scalar_only();
        p.e_per_example = Some(vec![0x3F80_0000]);
        assert!(validate_mri_batch_payload(&p).is_err());
    }

    #[test]
    fn degenerate_mask_length_mismatch_rejected() {
        let mut p = scalar_only();
        p.batch_len = Some(3);
        p.degenerate_mask = Some(vec![0, 1]); // 2 != 3
        assert!(validate_mri_batch_payload(&p).is_err());
    }

    #[test]
    fn all_vectors_valid_passes() {
        let mut p = scalar_only();
        p.batch_len = Some(2);
        p.q_per_example = Some(vec![0x3F80_0000, 0x4000_0000]);
        p.e_per_example = Some(vec![0x4040_0000, 0x4080_0000]);
        p.h_per_example = Some(vec![0x40A0_0000, 0x40C0_0000]);
        p.c_per_example = Some(vec![0x40E0_0000, 0x4100_0000]);
        p.degenerate_mask = Some(vec![0, 1]);
        assert!(validate_mri_batch_payload(&p).is_ok());
    }

    // ── Gradient coupling validator tests ───────────────────────────────

    use vertrule_schemas::GradientCouplingPayload;

    fn gc_provenance() -> ReductionProvenance {
        ReductionProvenance {
            reduction_mode: ReductionMode::BatchCollapsed,
            reduced_axes: vec![ReductionAxis::Batch],
            token_reduction: TokenReduction::Mean,
            batch_reduction: BatchReduction::Mean,
        }
    }

    fn valid_gc() -> GradientCouplingPayload {
        GradientCouplingPayload {
            schema: "mri2.gradient_coupling@0.1".to_string(),
            step: 100,
            num_layers: 2,
            grad_q_norms: vec![0x3F80_0000, 0x4000_0000],
            grad_lm_norms: vec![0x4040_0000, 0x4080_0000],
            coupling_ratios: vec![0x3E4C_CCCD, 0x3E99_999A],
            profile_cosine: 0x3F00_0000, // 0.5
            provenance: gc_provenance(),
        }
    }

    #[test]
    fn gc_valid_passes() {
        assert!(validate_gradient_coupling_payload(&valid_gc()).is_ok());
    }

    #[test]
    fn gc_wrong_schema_rejected() {
        let mut p = valid_gc();
        p.schema = "wrong@0.1".to_string();
        assert!(validate_gradient_coupling_payload(&p).is_err());
    }

    #[test]
    fn gc_zero_layers_rejected() {
        let mut p = valid_gc();
        p.num_layers = 0;
        p.grad_q_norms = vec![];
        p.grad_lm_norms = vec![];
        p.coupling_ratios = vec![];
        assert!(validate_gradient_coupling_payload(&p).is_err());
    }

    #[test]
    fn gc_length_mismatch_rejected() {
        let mut p = valid_gc();
        p.grad_q_norms = vec![0x3F80_0000]; // 1 != 2
        assert!(validate_gradient_coupling_payload(&p).is_err());
    }

    #[test]
    fn gc_nan_norm_rejected() {
        let mut p = valid_gc();
        p.grad_q_norms[0] = 0x7FC0_0000; // NaN
        assert!(validate_gradient_coupling_payload(&p).is_err());
    }

    #[test]
    fn gc_inf_ratio_rejected() {
        let mut p = valid_gc();
        p.coupling_ratios[1] = 0x7F80_0000; // +Inf
        assert!(validate_gradient_coupling_payload(&p).is_err());
    }

    #[test]
    fn gc_cosine_out_of_range_rejected() {
        let mut p = valid_gc();
        p.profile_cosine = 0x4000_0000; // 2.0, outside [-1,1]
        assert!(validate_gradient_coupling_payload(&p).is_err());
    }

    #[test]
    fn gc_cosine_negative_one_passes() {
        let mut p = valid_gc();
        p.profile_cosine = 0xBF80_0000; // -1.0
        assert!(validate_gradient_coupling_payload(&p).is_ok());
    }

    #[test]
    fn gc_cosine_zero_passes() {
        let mut p = valid_gc();
        p.profile_cosine = 0; // 0.0
        assert!(validate_gradient_coupling_payload(&p).is_ok());
    }

    #[test]
    fn unknown_reduction_mode_is_parse_not_validation() {
        // This test verifies the design decision: unknown enum variants
        // are serde parse failures, not validate_mri_batch_payload errors.
        let json = r#"{
            "schema": "mri2.batch_invariant@0.1",
            "layer": 0,
            "q_scalar": 1065353216,
            "provenance": {
                "reduction_mode": "invented_mode",
                "reduced_axes": ["token"],
                "token_reduction": "mean",
                "batch_reduction": "mean"
            }
        }"#;
        let result: Result<MriBatchPayload, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "unknown reduction_mode must fail at parse, not validation"
        );
    }
}
