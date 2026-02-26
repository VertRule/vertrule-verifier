//! Tests for schema profile validation.

use vr_kernel_testutils::vr_test;

use super::*;

fn valid_envelope_json() -> serde_json::Value {
    serde_json::json!({
        "envelope_version": 1,
        "receipt_type": "governance",
        "context_digest": "a".repeat(64),
        "schema_digest": "b".repeat(64),
        "policy_digest": "c".repeat(64),
        "logical_time": 1000,
        "event_hash": "d".repeat(64),
        "payload": {"key": "value"}
    })
}

vr_test!(
    fn test_valid_envelope_passes() {
        let json = valid_envelope_json();
        validate_envelope_schema(&json)?;
    }
);

vr_test!(
    fn test_valid_with_optional_fields() {
        let mut json = valid_envelope_json();
        json["parent_id"] = serde_json::json!("e".repeat(64));
        json["boundary_origin"] = serde_json::json!("Engine");
        validate_envelope_schema(&json)?;
    }
);

vr_test!(
    fn test_unknown_field_rejected() {
        let mut json = valid_envelope_json();
        json["bogus"] = serde_json::json!(1);
        let Err(err) = validate_envelope_schema(&json) else {
            anyhow::bail!("expected error, got Ok")
        };
        match err {
            VerifyError::UnknownField { field } => {
                assert_eq!(field, "bogus");
            }
            other => anyhow::bail!("expected UnknownField, got: {other}"),
        }
    }
);

vr_test!(
    fn test_missing_required_field_rejected() {
        let mut json = valid_envelope_json();
        json.as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("not an object"))?
            .remove("event_hash");
        let Err(err) = validate_envelope_schema(&json) else {
            anyhow::bail!("expected error, got Ok")
        };
        match err {
            VerifyError::MissingRequiredField { field } => {
                assert_eq!(field, "event_hash");
            }
            other => anyhow::bail!("expected MissingRequiredField, got: {other}"),
        }
    }
);

vr_test!(
    fn test_unknown_receipt_type_rejected() {
        let mut json = valid_envelope_json();
        json["receipt_type"] = serde_json::json!("quantum");
        let Err(err) = validate_envelope_schema(&json) else {
            anyhow::bail!("expected error, got Ok")
        };
        match err {
            VerifyError::UnknownReceiptType { value } => {
                assert_eq!(value, "quantum");
            }
            other => anyhow::bail!("expected UnknownReceiptType, got: {other}"),
        }
    }
);

vr_test!(
    fn test_unknown_boundary_origin_rejected() {
        let mut json = valid_envelope_json();
        json["boundary_origin"] = serde_json::json!("wormhole");
        let Err(err) = validate_envelope_schema(&json) else {
            anyhow::bail!("expected error, got Ok")
        };
        match err {
            VerifyError::UnknownBoundaryOrigin { value } => {
                assert_eq!(value, "wormhole");
            }
            other => anyhow::bail!("expected UnknownBoundaryOrigin, got: {other}"),
        }
    }
);

vr_test!(
    fn test_receipt_type_case_insensitive() {
        let mut json = valid_envelope_json();
        json["receipt_type"] = serde_json::json!("GOVERNANCE");
        validate_envelope_schema(&json)?;
    }
);

vr_test!(
    fn test_boundary_origin_case_insensitive() {
        let mut json = valid_envelope_json();
        json["boundary_origin"] = serde_json::json!("ADAPTER");
        validate_envelope_schema(&json)?;
    }
);

vr_test!(
    fn test_non_object_rejected() {
        let json = serde_json::json!([1, 2, 3]);
        let Err(err) = validate_envelope_schema(&json) else {
            anyhow::bail!("expected error, got Ok")
        };
        match err {
            VerifyError::MalformedJson { .. } => {}
            other => anyhow::bail!("expected MalformedJson, got: {other}"),
        }
    }
);

vr_test!(
    fn test_all_receipt_types_accepted() {
        let types = [
            "Event",
            "Llm",
            "Mri",
            "Governance",
            "Adapter",
            "Projection",
            "Training",
        ];
        for t in types {
            let mut json = valid_envelope_json();
            json["receipt_type"] = serde_json::json!(t);
            validate_envelope_schema(&json)?;
        }
    }
);

vr_test!(
    fn test_all_boundary_origins_accepted() {
        let origins = [
            "Engine",
            "Adapter",
            "Numeric",
            "Governance",
            "Model",
            "Training",
        ];
        for o in origins {
            let mut json = valid_envelope_json();
            json["boundary_origin"] = serde_json::json!(o);
            validate_envelope_schema(&json)?;
        }
    }
);
