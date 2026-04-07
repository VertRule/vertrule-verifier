use super::*;

fn test_key_id() -> Result<KeyId, crate::error::VerifyError> {
    // Deterministic: BLAKE3([42u8; 32])[..12] as hex
    let seed = [42u8; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key();
    let hash = blake3::hash(pk.as_bytes());
    KeyId::from_hex(&hex::encode(&hash.as_bytes()[..12]))
}

fn test_key_id_hex() -> Result<String, crate::error::VerifyError> {
    Ok(test_key_id()?.as_hex().to_string())
}

fn make_authority_set() -> Result<AuthoritySet, crate::error::VerifyError> {
    let mut set = AuthoritySet::new("test-set".to_string());
    set.add_key(
        test_key_id_hex()?,
        AuthorityKey {
            public_key_b64: String::new(), // empty = skips public key match
            valid_from_epoch: 1,
            valid_until_epoch: Some(10),
        },
    );
    Ok(set)
}

// ── Trusted ────────────────────────────────────────────────────────

#[test]
fn trusted_key_in_valid_epoch() -> Result<(), crate::error::VerifyError> {
    let set = make_authority_set()?;
    let policy = TrustPolicy {
        current_epoch: 5,
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id()?, &set, &policy, None);
    assert_eq!(result.status, TrustStatus::Trusted);
    assert!(result.detail.is_none());
    Ok(())
}

#[test]
fn trusted_at_first_valid_epoch() -> Result<(), crate::error::VerifyError> {
    let set = make_authority_set()?;
    let policy = TrustPolicy {
        current_epoch: 1,
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id()?, &set, &policy, None);
    assert_eq!(result.status, TrustStatus::Trusted);
    Ok(())
}

#[test]
fn trusted_at_last_valid_epoch() -> Result<(), crate::error::VerifyError> {
    let set = make_authority_set()?;
    let policy = TrustPolicy {
        current_epoch: 9,
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id()?, &set, &policy, None);
    assert_eq!(result.status, TrustStatus::Trusted);
    Ok(())
}

// ── Untrusted ──────────────────────────────────────────────────────

#[test]
fn untrusted_key_not_in_set() -> Result<(), crate::error::VerifyError> {
    let set = make_authority_set()?;
    let unknown_key = KeyId::from_hex(&"b".repeat(24))?;
    let policy = TrustPolicy::default();

    let result = evaluate_trust(&unknown_key, &set, &policy, None);
    assert_eq!(result.status, TrustStatus::Untrusted);
    assert!(result
        .detail
        .as_ref()
        .is_some_and(|d| d.contains("not found")));
    Ok(())
}

#[test]
fn untrusted_empty_authority_set() -> Result<(), crate::error::VerifyError> {
    let set = AuthoritySet::new("empty".to_string());
    let policy = TrustPolicy::default();

    let result = evaluate_trust(&test_key_id()?, &set, &policy, None);
    assert_eq!(result.status, TrustStatus::Untrusted);
    Ok(())
}

// ── Revoked ────────────────────────────────────────────────────────

#[test]
fn revoked_key_rejected() -> Result<(), crate::error::VerifyError> {
    let mut set = make_authority_set()?;
    set.revoke(
        test_key_id_hex()?,
        Revocation {
            reason: "compromised".to_string(),
            revoked_at_epoch: 3,
        },
    );
    let policy = TrustPolicy {
        current_epoch: 5,
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id()?, &set, &policy, None);
    assert_eq!(result.status, TrustStatus::Revoked);
    assert!(result
        .detail
        .as_ref()
        .is_some_and(|d| d.contains("compromised")));
    Ok(())
}

#[test]
fn revoked_overrides_valid_epoch() -> Result<(), crate::error::VerifyError> {
    let mut set = make_authority_set()?;
    set.revoke(
        test_key_id_hex()?,
        Revocation {
            reason: "key rotation".to_string(),
            revoked_at_epoch: 5,
        },
    );
    let policy = TrustPolicy {
        current_epoch: 5,
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id()?, &set, &policy, None);
    assert_eq!(result.status, TrustStatus::Revoked);
    Ok(())
}

#[test]
fn revocation_not_enforced_when_disabled() -> Result<(), crate::error::VerifyError> {
    let mut set = make_authority_set()?;
    set.revoke(
        test_key_id_hex()?,
        Revocation {
            reason: "test".to_string(),
            revoked_at_epoch: 3,
        },
    );
    let policy = TrustPolicy {
        current_epoch: 5,
        enforce_revocation: false,
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id()?, &set, &policy, None);
    assert_eq!(result.status, TrustStatus::Trusted);
    Ok(())
}

// ── Wrong Epoch ────────────────────────────────────────────────────

#[test]
fn wrong_epoch_before_valid() -> Result<(), crate::error::VerifyError> {
    let set = make_authority_set()?;
    let policy = TrustPolicy {
        current_epoch: 0,
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id()?, &set, &policy, None);
    assert_eq!(result.status, TrustStatus::WrongEpoch);
    assert!(result.detail.as_ref().is_some_and(|d| d.contains("before")));
    Ok(())
}

#[test]
fn wrong_epoch_at_expiry() -> Result<(), crate::error::VerifyError> {
    let set = make_authority_set()?;
    let policy = TrustPolicy {
        current_epoch: 10, // valid_until_epoch is 10 (exclusive)
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id()?, &set, &policy, None);
    assert_eq!(result.status, TrustStatus::WrongEpoch);
    assert!(result.detail.as_ref().is_some_and(|d| d.contains("past")));
    Ok(())
}

#[test]
fn wrong_epoch_after_expiry() -> Result<(), crate::error::VerifyError> {
    let set = make_authority_set()?;
    let policy = TrustPolicy {
        current_epoch: 100,
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id()?, &set, &policy, None);
    assert_eq!(result.status, TrustStatus::WrongEpoch);
    Ok(())
}

#[test]
fn epoch_not_enforced_when_disabled() -> Result<(), crate::error::VerifyError> {
    let set = make_authority_set()?;
    let policy = TrustPolicy {
        current_epoch: 100,
        enforce_epoch: false,
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id()?, &set, &policy, None);
    assert_eq!(result.status, TrustStatus::Trusted);
    Ok(())
}

// ── No upper epoch bound ───────────────────────────────────────────

#[test]
fn key_without_upper_bound_trusted_at_high_epoch() -> Result<(), crate::error::VerifyError> {
    let mut set = AuthoritySet::new("unbounded".to_string());
    set.add_key(
        test_key_id_hex()?,
        AuthorityKey {
            public_key_b64: String::new(),
            valid_from_epoch: 1,
            valid_until_epoch: None,
        },
    );
    let policy = TrustPolicy {
        current_epoch: 999_999,
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id()?, &set, &policy, None);
    assert_eq!(result.status, TrustStatus::Trusted);
    Ok(())
}

// ── Result structure ───────────────────────────────────────────────

#[test]
fn result_contains_authority_set_id() -> Result<(), crate::error::VerifyError> {
    let set = make_authority_set()?;
    let policy = TrustPolicy::default();

    let result = evaluate_trust(&test_key_id()?, &set, &policy, None);
    assert_eq!(result.authority_set_id, "test-set");
    Ok(())
}

#[test]
fn result_contains_evaluated_epoch() -> Result<(), crate::error::VerifyError> {
    let set = make_authority_set()?;
    let policy = TrustPolicy {
        current_epoch: 7,
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id()?, &set, &policy, None);
    assert_eq!(result.evaluated_at_epoch, 7);
    Ok(())
}

// ── Public key validation ──────────────────────────────────────────

#[test]
fn public_key_mismatch_is_untrusted() -> Result<(), crate::error::VerifyError> {
    let seed = [42u8; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key();
    let real_pk_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        pk.as_bytes(),
    );

    let mut set = AuthoritySet::new("pk-test".to_string());
    set.add_key(
        test_key_id_hex()?,
        AuthorityKey {
            public_key_b64: real_pk_b64,
            valid_from_epoch: 1,
            valid_until_epoch: Some(10),
        },
    );
    let policy = TrustPolicy {
        current_epoch: 5,
        ..TrustPolicy::default()
    };

    // Correct public key → trusted
    let result = evaluate_trust(
        &test_key_id()?,
        &set,
        &policy,
        Some(&base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            pk.as_bytes(),
        )),
    );
    assert_eq!(result.status, TrustStatus::Trusted);

    // Wrong public key → untrusted
    let result = evaluate_trust(
        &test_key_id()?,
        &set,
        &policy,
        Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
    );
    assert_eq!(result.status, TrustStatus::Untrusted);
    assert!(result
        .detail
        .as_ref()
        .is_some_and(|d| d.contains("does not match")));

    Ok(())
}

#[test]
fn trust_status_display_is_stable() {
    assert_eq!(TrustStatus::Trusted.to_string(), "trusted");
    assert_eq!(TrustStatus::Untrusted.to_string(), "untrusted");
    assert_eq!(TrustStatus::Revoked.to_string(), "revoked");
    assert_eq!(TrustStatus::WrongEpoch.to_string(), "wrong_epoch");
}

#[test]
fn trust_status_serializes_to_lowercase() -> Result<(), serde_json::Error> {
    assert_eq!(serde_json::to_string(&TrustStatus::Trusted)?, "\"trusted\"");
    assert_eq!(
        serde_json::to_string(&TrustStatus::WrongEpoch)?,
        "\"wrong_epoch\""
    );
    Ok(())
}
