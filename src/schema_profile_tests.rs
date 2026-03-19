//! Tests for schema profile validation.

use crate::test_support::vr_test;

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
    fn test_valid_with_algorithm_fields() {
        let mut json = valid_envelope_json();
        json["digest_algorithm"] = serde_json::json!("BLAKE3");
        json["canonicalization"] = serde_json::json!("JCS");
        validate_envelope_schema(&json)?;
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

vr_test!(
    fn test_governance_profile_matches_constants() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let path = format!("{manifest_dir}/governance-profile-v1.json");
        let profile_bytes =
            std::fs::read(&path).map_err(|e| anyhow::anyhow!("reading {path}: {e}"))?;
        let profile: serde_json::Value = serde_json::from_slice(&profile_bytes)
            .map_err(|e| anyhow::anyhow!("parsing profile: {e}"))?;

        // Required fields
        let profile_required: Vec<&str> = profile["envelope"]["required_fields"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("required_fields must be array"))?
            .iter()
            .filter_map(|f| f["name"].as_str())
            .collect();
        if profile_required.as_slice() != super::REQUIRED_ENVELOPE_FIELDS {
            anyhow::bail!(
                "required fields mismatch:\n  profile: {profile_required:?}\n  code: {:?}",
                super::REQUIRED_ENVELOPE_FIELDS
            );
        }

        // Optional fields
        let profile_optional: Vec<&str> = profile["envelope"]["optional_fields"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("optional_fields must be array"))?
            .iter()
            .filter_map(|f| f["name"].as_str())
            .collect();
        if profile_optional.as_slice() != super::OPTIONAL_ENVELOPE_FIELDS {
            anyhow::bail!(
                "optional fields mismatch:\n  profile: {profile_optional:?}\n  code: {:?}",
                super::OPTIONAL_ENVELOPE_FIELDS
            );
        }

        // Receipt types (case-insensitive)
        let profile_types: Vec<String> = profile["known_receipt_types"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("known_receipt_types must be array"))?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_lowercase))
            .collect();
        let code_types: Vec<String> = super::KNOWN_RECEIPT_TYPES
            .iter()
            .map(|&s| s.to_lowercase())
            .collect();
        if profile_types != code_types {
            anyhow::bail!(
                "receipt types mismatch:\n  profile: {profile_types:?}\n  code: {code_types:?}"
            );
        }

        // Boundary origins (case-insensitive)
        let profile_origins: Vec<String> = profile["known_boundary_origins"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("known_boundary_origins must be array"))?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_lowercase))
            .collect();
        let code_origins: Vec<String> = super::KNOWN_BOUNDARY_ORIGINS
            .iter()
            .map(|&s| s.to_lowercase())
            .collect();
        if profile_origins != code_origins {
            anyhow::bail!(
                "boundary origins mismatch:\n  profile: {profile_origins:?}\n  code: {code_origins:?}"
            );
        }
    }
);
