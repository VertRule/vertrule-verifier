use super::*;

fn test_key_id() -> KeyId {
    // Deterministic: BLAKE3([42u8; 32])[..12] as hex
    let seed = [42u8; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key();
    let hash = blake3::hash(pk.as_bytes());
    KeyId::from_hex(&hex::encode(&hash.as_bytes()[..12]))
        .ok()
        .unwrap_or_else(|| {
            // Fallback: use a synthetic key ID for testing
            KeyId::from_hex(&"a".repeat(24))
                .ok()
                .unwrap_or_else(|| unreachable!())
        })
}

fn test_key_id_hex() -> String {
    test_key_id().as_hex().to_string()
}

fn make_authority_set() -> AuthoritySet {
    let mut set = AuthoritySet::new("test-set".to_string());
    set.add_key(
        test_key_id_hex(),
        AuthorityKey {
            public_key_b64: String::new(), // not checked by evaluate_trust
            valid_from_epoch: 1,
            valid_until_epoch: Some(10),
        },
    );
    set
}

// ── Trusted ────────────────────────────────────────────────────────

#[test]
fn trusted_key_in_valid_epoch() {
    let set = make_authority_set();
    let policy = TrustPolicy {
        current_epoch: 5,
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id(), &set, &policy);
    assert_eq!(result.status, TrustStatus::Trusted);
    assert!(result.detail.is_none());
}

#[test]
fn trusted_at_first_valid_epoch() {
    let set = make_authority_set();
    let policy = TrustPolicy {
        current_epoch: 1,
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id(), &set, &policy);
    assert_eq!(result.status, TrustStatus::Trusted);
}

#[test]
fn trusted_at_last_valid_epoch() {
    let set = make_authority_set();
    let policy = TrustPolicy {
        current_epoch: 9,
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id(), &set, &policy);
    assert_eq!(result.status, TrustStatus::Trusted);
}

// ── Untrusted ──────────────────────────────────────────────────────

#[test]
fn untrusted_key_not_in_set() {
    let set = make_authority_set();
    let unknown_key = KeyId::from_hex(&"b".repeat(24));
    let policy = TrustPolicy::default();

    if let Ok(kid) = unknown_key {
        let result = evaluate_trust(&kid, &set, &policy);
        assert_eq!(result.status, TrustStatus::Untrusted);
        assert!(result
            .detail
            .as_ref()
            .is_some_and(|d| d.contains("not found")));
    }
}

#[test]
fn untrusted_empty_authority_set() {
    let set = AuthoritySet::new("empty".to_string());
    let policy = TrustPolicy::default();

    let result = evaluate_trust(&test_key_id(), &set, &policy);
    assert_eq!(result.status, TrustStatus::Untrusted);
}

// ── Revoked ────────────────────────────────────────────────────────

#[test]
fn revoked_key_rejected() {
    let mut set = make_authority_set();
    set.revoke(
        test_key_id_hex(),
        Revocation {
            reason: "compromised".to_string(),
            revoked_at_epoch: 3,
        },
    );
    let policy = TrustPolicy {
        current_epoch: 5,
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id(), &set, &policy);
    assert_eq!(result.status, TrustStatus::Revoked);
    assert!(result
        .detail
        .as_ref()
        .is_some_and(|d| d.contains("compromised")));
}

#[test]
fn revoked_overrides_valid_epoch() {
    let mut set = make_authority_set();
    set.revoke(
        test_key_id_hex(),
        Revocation {
            reason: "key rotation".to_string(),
            revoked_at_epoch: 5,
        },
    );
    let policy = TrustPolicy {
        current_epoch: 5,
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id(), &set, &policy);
    assert_eq!(result.status, TrustStatus::Revoked);
}

#[test]
fn revocation_not_enforced_when_disabled() {
    let mut set = make_authority_set();
    set.revoke(
        test_key_id_hex(),
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

    let result = evaluate_trust(&test_key_id(), &set, &policy);
    assert_eq!(result.status, TrustStatus::Trusted);
}

// ── Wrong Epoch ────────────────────────────────────────────────────

#[test]
fn wrong_epoch_before_valid() {
    let set = make_authority_set();
    let policy = TrustPolicy {
        current_epoch: 0,
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id(), &set, &policy);
    assert_eq!(result.status, TrustStatus::WrongEpoch);
    assert!(result.detail.as_ref().is_some_and(|d| d.contains("before")));
}

#[test]
fn wrong_epoch_at_expiry() {
    let set = make_authority_set();
    let policy = TrustPolicy {
        current_epoch: 10, // valid_until_epoch is 10 (exclusive)
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id(), &set, &policy);
    assert_eq!(result.status, TrustStatus::WrongEpoch);
    assert!(result.detail.as_ref().is_some_and(|d| d.contains("past")));
}

#[test]
fn wrong_epoch_after_expiry() {
    let set = make_authority_set();
    let policy = TrustPolicy {
        current_epoch: 100,
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id(), &set, &policy);
    assert_eq!(result.status, TrustStatus::WrongEpoch);
}

#[test]
fn epoch_not_enforced_when_disabled() {
    let set = make_authority_set();
    let policy = TrustPolicy {
        current_epoch: 100,
        enforce_epoch: false,
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id(), &set, &policy);
    assert_eq!(result.status, TrustStatus::Trusted);
}

// ── No upper epoch bound ───────────────────────────────────────────

#[test]
fn key_without_upper_bound_trusted_at_high_epoch() {
    let mut set = AuthoritySet::new("unbounded".to_string());
    set.add_key(
        test_key_id_hex(),
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

    let result = evaluate_trust(&test_key_id(), &set, &policy);
    assert_eq!(result.status, TrustStatus::Trusted);
}

// ── Result structure ───────────────────────────────────────────────

#[test]
fn result_contains_authority_set_id() {
    let set = make_authority_set();
    let policy = TrustPolicy::default();

    let result = evaluate_trust(&test_key_id(), &set, &policy);
    assert_eq!(result.authority_set_id, "test-set");
}

#[test]
fn result_contains_evaluated_epoch() {
    let set = make_authority_set();
    let policy = TrustPolicy {
        current_epoch: 7,
        ..TrustPolicy::default()
    };

    let result = evaluate_trust(&test_key_id(), &set, &policy);
    assert_eq!(result.evaluated_at_epoch, 7);
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
