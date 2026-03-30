//! Public surface regression test for vertrule-verifier v0.1.
//!
//! Asserts that the blessed public API symbols compile and are usable.
//! Review against `PUBLIC_SURFACE.md` when preparing releases.

#![deny(unused_imports)]

// Verification entry points
use vr_verifier::verify_receipt;
use vr_verifier::verify_receipt_chain;
use vr_verifier::verify_receipt_chain_with_limits;
use vr_verifier::verify_receipt_with_limits;
use vr_verifier::verify_signed_receipt;
use vr_verifier::verify_signed_receipt_with_trust;

// Envelope integrity (re-homed from vertrule-schemas)
use vr_verifier::validate_receipt_envelope_integrity;

// MRI payload validation
use vr_verifier::validate_gradient_coupling_payload;
use vr_verifier::validate_mri_batch_payload;

// Result types
use vr_verifier::result::VerificationResult;
use vr_verifier::result::VerificationStatus;

// Error
use vr_verifier::VerifyError;

// Limits
use vr_verifier::VerifierLimits;

// Trust
use vr_verifier::AuthoritySet;
use vr_verifier::TrustPolicy;
use vr_verifier::TrustStatus;
use vr_verifier::TrustValidation;

// Re-exports from schemas
use vr_verifier::DigestBytes;
use vr_verifier::ReceiptEnvelope;
use vr_verifier::SchemaVersion;

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
    let _ = validate_mri_batch_payload as fn(&vertrule_schemas::MriBatchPayload) -> Result<(), VerifyError>;
    let _ = validate_gradient_coupling_payload as fn(&vertrule_schemas::GradientCouplingPayload) -> Result<(), VerifyError>;
}
