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
        json["boundary_origin"] = serde_json::json!("engine");
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
    fn test_receipt_type_title_case_rejected() {
        let mut json = valid_envelope_json();
        json["receipt_type"] = serde_json::json!("Governance");
        let Err(err) = validate_envelope_schema(&json) else {
            anyhow::bail!("expected error for title case receipt_type")
        };
        match err {
            VerifyError::UnknownReceiptType { value } => {
                assert_eq!(value, "Governance");
            }
            other => anyhow::bail!("expected UnknownReceiptType, got: {other}"),
        }
    }
);

vr_test!(
    fn test_receipt_type_upper_case_rejected() {
        let mut json = valid_envelope_json();
        json["receipt_type"] = serde_json::json!("GOVERNANCE");
        let Err(err) = validate_envelope_schema(&json) else {
            anyhow::bail!("expected error for upper case receipt_type")
        };
        match err {
            VerifyError::UnknownReceiptType { value } => {
                assert_eq!(value, "GOVERNANCE");
            }
            other => anyhow::bail!("expected UnknownReceiptType, got: {other}"),
        }
    }
);

vr_test!(
    fn test_boundary_origin_title_case_rejected() {
        let mut json = valid_envelope_json();
        json["boundary_origin"] = serde_json::json!("Adapter");
        let Err(err) = validate_envelope_schema(&json) else {
            anyhow::bail!("expected error for title case boundary_origin")
        };
        match err {
            VerifyError::UnknownBoundaryOrigin { value } => {
                assert_eq!(value, "Adapter");
            }
            other => anyhow::bail!("expected UnknownBoundaryOrigin, got: {other}"),
        }
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
            "event",
            "llm",
            "mri",
            "governance",
            "adapter",
            "projection",
            "training",
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
            "engine",
            "adapter",
            "numeric",
            "governance",
            "model",
            "training",
        ];
        for o in origins {
            let mut json = valid_envelope_json();
            json["boundary_origin"] = serde_json::json!(o);
            validate_envelope_schema(&json)?;
        }
    }
);

vr_test!(
    fn test_receipt_types_match_schema_crate() {
        // Guard against drift: every ReceiptType variant in vertrule-schemas must
        // be in KNOWN_RECEIPT_TYPES, and the counts must match.
        let schema_types = [
            vertrule_schemas::ReceiptType::Event,
            vertrule_schemas::ReceiptType::Llm,
            vertrule_schemas::ReceiptType::Mri,
            vertrule_schemas::ReceiptType::Governance,
            vertrule_schemas::ReceiptType::Adapter,
            vertrule_schemas::ReceiptType::Projection,
            vertrule_schemas::ReceiptType::Training,
            vertrule_schemas::ReceiptType::Operation,
            vertrule_schemas::ReceiptType::Finalization,
            vertrule_schemas::ReceiptType::Abort,
        ];
        if schema_types.len() != super::KNOWN_RECEIPT_TYPES.len() {
            anyhow::bail!(
                "ReceiptType variant count ({}) != KNOWN_RECEIPT_TYPES count ({})",
                schema_types.len(),
                super::KNOWN_RECEIPT_TYPES.len(),
            );
        }
        for variant in &schema_types {
            let name = format!("{variant}");
            if !super::KNOWN_RECEIPT_TYPES.contains(&name.as_str()) {
                anyhow::bail!(
                    "ReceiptType::{variant:?} (serializes as \"{name}\") not in KNOWN_RECEIPT_TYPES"
                );
            }
        }
    }
);

vr_test!(
    fn test_boundary_origins_match_schema_crate() {
        // Guard against drift: every BoundaryOrigin variant in vertrule-schemas must
        // be in KNOWN_BOUNDARY_ORIGINS, and the counts must match.
        let schema_origins = [
            vertrule_schemas::BoundaryOrigin::Engine,
            vertrule_schemas::BoundaryOrigin::Adapter,
            vertrule_schemas::BoundaryOrigin::Numeric,
            vertrule_schemas::BoundaryOrigin::Governance,
            vertrule_schemas::BoundaryOrigin::Model,
            vertrule_schemas::BoundaryOrigin::Training,
        ];
        if schema_origins.len() != super::KNOWN_BOUNDARY_ORIGINS.len() {
            anyhow::bail!(
                "BoundaryOrigin variant count ({}) != KNOWN_BOUNDARY_ORIGINS count ({})",
                schema_origins.len(),
                super::KNOWN_BOUNDARY_ORIGINS.len(),
            );
        }
        for variant in &schema_origins {
            let name = format!("{variant}");
            if !super::KNOWN_BOUNDARY_ORIGINS.contains(&name.as_str()) {
                anyhow::bail!(
                    "BoundaryOrigin::{variant:?} (serializes as \"{name}\") not in KNOWN_BOUNDARY_ORIGINS"
                );
            }
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

        // Receipt types (exact lowercase match)
        let profile_types: Vec<&str> = profile["known_receipt_types"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("known_receipt_types must be array"))?
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        if profile_types.as_slice() != super::KNOWN_RECEIPT_TYPES {
            anyhow::bail!(
                "receipt types mismatch:\n  profile: {profile_types:?}\n  code: {:?}",
                super::KNOWN_RECEIPT_TYPES
            );
        }

        // Boundary origins (exact lowercase match)
        let profile_origins: Vec<&str> = profile["known_boundary_origins"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("known_boundary_origins must be array"))?
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        if profile_origins.as_slice() != super::KNOWN_BOUNDARY_ORIGINS {
            anyhow::bail!(
                "boundary origins mismatch:\n  profile: {profile_origins:?}\n  code: {:?}",
                super::KNOWN_BOUNDARY_ORIGINS
            );
        }
    }
);
