//! Tests for `VerificationResult`.

use crate::test_support::vr_test;

use super::*;

vr_test!(
    fn test_valid_single_serializes() {
        let result = VerificationResult::valid_single();
        let value =
            serde_json::to_value(&result).map_err(|e| anyhow::anyhow!("serialize failed: {e}"))?;
        assert_eq!(value["status"], "VALID");
        assert_eq!(value["schema_version"], "v1");
        assert_eq!(value["digest_validation"]["all_hashes_match"], true);
        // chain_validation absent for single receipt
        assert!(value.get("chain_validation").is_none());
    }
);

vr_test!(
    fn test_unsigned_single_serializes() {
        let result = VerificationResult::unsigned_single();
        let value =
            serde_json::to_value(&result).map_err(|e| anyhow::anyhow!("serialize failed: {e}"))?;
        assert_eq!(value["status"], "UNSIGNED");
        assert_eq!(value["signature_validation"]["present"], false);
    }
);

vr_test!(
    fn test_invalid_contains_error() {
        let result = VerificationResult::invalid("something broke".to_string());
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0], "something broke");
    }
);

vr_test!(
    fn test_add_error_sets_invalid() {
        let mut result = VerificationResult::valid_single();
        assert_eq!(result.status, VerificationStatus::Valid);
        result.add_error("oops".to_string());
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert_eq!(result.errors.len(), 1);
    }
);

vr_test!(
    fn test_digest_is_deterministic() {
        let result = VerificationResult::valid_single();
        let d1 = result.digest()?;
        let d2 = result.digest()?;
        assert_eq!(d1, d2);
    }
);

vr_test!(
    fn test_different_results_produce_different_digests() {
        let valid = VerificationResult::valid_single();
        let invalid = VerificationResult::invalid("bad".to_string());
        let d1 = valid.digest()?;
        let d2 = invalid.digest()?;
        assert_ne!(d1, d2);
    }
);
