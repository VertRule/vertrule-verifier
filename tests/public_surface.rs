//! Public surface regression test for vertrule-verifier v0.1.
//!
//! Asserts that the blessed public API symbols compile and are usable.
//! Review against `PUBLIC_SURFACE.md` when preparing releases.

#![deny(unused_imports)]

// Verification entry points
use vertrule_verifier::verify_receipt;
use vertrule_verifier::verify_receipt_chain;
use vertrule_verifier::verify_receipt_chain_with_limits;
use vertrule_verifier::verify_receipt_with_limits;
use vertrule_verifier::verify_signed_receipt;
use vertrule_verifier::verify_signed_receipt_with_trust;

// Envelope integrity (re-homed from vertrule-schemas)
use vertrule_verifier::validate_receipt_envelope_integrity;

// MRI payload validation
use vertrule_verifier::validate_gradient_coupling_payload;
use vertrule_verifier::validate_mri_batch_payload;

// Result types
use vertrule_verifier::result::VerificationResult;
use vertrule_verifier::result::VerificationStatus;

// Error
use vertrule_verifier::VerifyError;

// Limits
use vertrule_verifier::VerifierLimits;

// Trust
use vertrule_verifier::AuthoritySet;
use vertrule_verifier::TrustPolicy;
use vertrule_verifier::TrustStatus;
use vertrule_verifier::TrustValidation;

// Re-exports from schemas
use vertrule_verifier::DigestBytes;
use vertrule_verifier::ReceiptEnvelope;
use vertrule_verifier::SchemaVersion;

#[test]
fn public_surface_symbols_are_usable() {
    // Verification entry points return VerificationResult
    let result = verify_receipt(b"{}");
    assert_eq!(result.status, VerificationStatus::Invalid);

    let result = verify_receipt_with_limits(b"{}", &VerifierLimits::default());
    assert_eq!(result.status, VerificationStatus::Invalid);

    let result = verify_receipt_chain(b"[]");
    assert_eq!(result.status, VerificationStatus::Valid);

    let result = verify_receipt_chain_with_limits(b"[]", &VerifierLimits::default());
    assert_eq!(result.status, VerificationStatus::Valid);

    let result = verify_signed_receipt(b"{}", b"{}");
    assert_eq!(result.status, VerificationStatus::Invalid);

    let authority_set = AuthoritySet::new("test-set".to_string());
    let trust_policy = TrustPolicy {
        current_epoch: 0,
        enforce_epoch: false,
        enforce_revocation: false,
    };
    let result = verify_signed_receipt_with_trust(b"{}", b"{}", &authority_set, &trust_policy);
    assert_eq!(result.status, VerificationStatus::Invalid);

    // Suppress unused-import warnings for types used only as existence checks
    let _ = std::any::type_name::<VerificationResult>();
    let _ = std::any::type_name::<VerifyError>();
    let _ = std::any::type_name::<TrustValidation>();
    let _ = std::any::type_name::<TrustStatus>();
    let _ = std::any::type_name::<DigestBytes>();
    let _ = std::any::type_name::<ReceiptEnvelope>();
    let _ = std::any::type_name::<SchemaVersion>();
    let _ = validate_receipt_envelope_integrity as fn(&ReceiptEnvelope) -> Result<(), VerifyError>;
    let _ = validate_mri_batch_payload
        as fn(&vertrule_schemas::MriBatchPayload) -> Result<(), VerifyError>;
    let _ = validate_gradient_coupling_payload
        as fn(&vertrule_schemas::GradientCouplingPayload) -> Result<(), VerifyError>;
}
