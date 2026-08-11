//! ADR-011 law vectors for `KeyId` V1.
//!
//! ```text
//! KeyIdV1(pk) = lowerhex( BLAKE3(pk_bytes)[0..12] )
//! ```
//!
//! The value is **protocol-visible** — 24 lowercase hex characters carried in
//! signature bundles and compared by verifiers. It is therefore ratified
//! exactly as it already exists. The 96-bit width may be questionable as a
//! greenfield choice; that is irrelevant here:
//!
//! ```text
//! WidthChange ⇒ KeyIdV2
//! ```
//!
//! A protocol upgrade must not be smuggled into digest-authority cleanup.
//!
//! # What these vectors pin
//!
//! | Property | Why it needs its own assertion |
//! |---|---|
//! | Exact public-key preimage | The law hashes the raw 32 key bytes, not a hex or base64 rendering of them |
//! | **Leading** 12 bytes | Trailing-12 is an equally plausible reimplementation and would pass a width-only check |
//! | Exactly 24 hex chars | Guards the width itself |
//! | Lowercase | `hex::encode` is lowercase; uppercase would break bundle comparison |
//! | Two distinct keys | A constructor ignoring its input passes a single vector |
//! | Changed key ⇒ changed id | Sensitivity to the preimage |
//!
//! Goldens computed with `b3sum 1.8.2` outside the workspace over the raw key
//! bytes, so they pin the law rather than the implementation.

use vertrule_verifier::signature::KeyId;

/// `(label, public key bytes, full BLAKE3 hex, expected key id)`.
struct Vector {
    label: &'static str,
    public_key: [u8; 32],
    full_digest_hex: &'static str,
    key_id: &'static str,
}

fn vectors() -> Vec<Vector> {
    vec![
        Vector {
            label: "all-zero key bytes",
            public_key: [0u8; 32],
            full_digest_hex: "2ada83c1819a5372dae1238fc1ded123c8104fdaa15862aaee69428a1820fcda",
            key_id: "2ada83c1819a5372dae1238f",
        },
        Vector {
            label: "all-ones key bytes",
            public_key: [0xFFu8; 32],
            full_digest_hex: "9b34f060fbc0f0aa11f150e26519deff613277b60656f0f8356ed2261505f5c5",
            key_id: "9b34f060fbc0f0aa11f150e2",
        },
        Vector {
            label: "ramp 0x00..0x1f",
            public_key: {
                let mut bytes = [0u8; 32];
                let mut index = 0usize;
                while index < 32 {
                    bytes[index] = u8::try_from(index).unwrap_or(0);
                    index += 1;
                }
                bytes
            },
            full_digest_hex: "e528e95798037df410543d9f31e396ecdd458d71b157d6014398bae32fb56c65",
            key_id: "e528e95798037df410543d9f",
        },
    ]
}

#[test]
fn key_id_matches_the_frozen_goldens() {
    for vector in vectors() {
        assert_eq!(
            KeyId::from_public_key_v1(&vector.public_key).as_hex(),
            vector.key_id,
            "KeyId V1 law moved for {}",
            vector.label,
        );
    }
}

#[test]
fn key_id_is_the_leading_twelve_digest_bytes() {
    // The decisive assertion. A trailing-12 implementation produces a
    // well-formed 24-char lowercase hex id and would satisfy every other test
    // in this file.
    for vector in vectors() {
        let leading = &vector.full_digest_hex[..24];
        let trailing = &vector.full_digest_hex[vector.full_digest_hex.len() - 24..];
        assert_eq!(
            KeyId::from_public_key_v1(&vector.public_key).as_hex(),
            leading,
            "{}: id must be the leading 12 bytes",
            vector.label,
        );
        assert_ne!(
            KeyId::from_public_key_v1(&vector.public_key).as_hex(),
            trailing,
            "{}: leading and trailing must be distinguishable, or this \
             vector cannot prove truncation direction",
            vector.label,
        );
    }
}

#[test]
fn key_id_is_exactly_twenty_four_lowercase_hex_chars() {
    for vector in vectors() {
        let id = KeyId::from_public_key_v1(&vector.public_key);
        let hex = id.as_hex();
        assert_eq!(hex.len(), 24, "{}: width is frozen at 96 bits", vector.label);
        assert!(
            hex.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "{}: lowercase hex only — bundle comparison is byte-wise",
            vector.label,
        );
    }
}

#[test]
fn distinct_keys_produce_distinct_ids() {
    let ids: std::collections::BTreeSet<String> = vectors()
        .iter()
        .map(|v| KeyId::from_public_key_v1(&v.public_key).as_hex().to_string())
        .collect();
    assert_eq!(ids.len(), 3, "a constructor ignoring its input would collapse these");
}

#[test]
fn one_flipped_key_byte_changes_the_id() {
    let base = [0u8; 32];
    let mut flipped = base;
    flipped[31] = 1;
    assert_ne!(
        KeyId::from_public_key_v1(&base).as_hex(),
        KeyId::from_public_key_v1(&flipped).as_hex(),
    );
}

#[test]
fn derived_ids_round_trip_through_from_hex() {
    // The derived form must satisfy the parser that validates ids arriving
    // over the wire; otherwise derivation and validation could diverge.
    for vector in vectors() {
        let derived = KeyId::from_public_key_v1(&vector.public_key);
        let parsed = KeyId::from_hex(derived.as_hex());
        assert!(
            parsed.is_ok(),
            "{}: derived id must parse as a valid KeyId",
            vector.label,
        );
    }
}
