//! CLI-level tests for `vr-verify` limit flags and trust-policy verification
//! (issue #3).
//!
//! Drives the compiled binary against committed fixtures, asserting the
//! documented contract:
//! - limit flags (`--max-bytes`, `--max-chain-length`) select the hardened
//!   verifier and reject oversized input with a typed limit violation,
//! - omitting all new flags preserves the existing default verification path,
//! - `signed --trust <t.json>` reflects the trust decision in result + exit code,
//! - zero limits and flags invalid for a subcommand are CLI usage errors.

use std::process::Output;

macro_rules! vr_test {
    ( $(#[$meta:meta])* fn $name:ident() $body:block ) => {
        $(#[$meta])*
        #[test]
        fn $name() -> anyhow::Result<()> {
            $body
            Ok(())
        }
    };
}

/// Absolute path to a committed raw fixture under `test-vectors/raw/`.
fn raw_path(name: &str) -> String {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test-vectors")
        .join("raw")
        .join(format!("{name}.json"))
        .to_string_lossy()
        .into_owned()
}

/// Run the compiled `vr-verify` binary with the given arguments.
fn run_vr_verify(args: &[&str]) -> anyhow::Result<Output> {
    Ok(std::process::Command::new(env!("CARGO_BIN_EXE_vr-verify"))
        .args(args)
        .output()?)
}

/// Byte length of a committed raw fixture.
fn raw_len(name: &str) -> anyhow::Result<usize> {
    Ok(usize::try_from(std::fs::metadata(raw_path(name))?.len())?)
}

vr_test!(
    // Acceptance criterion: "omitting the new flags preserves current default
    // behavior." In this codebase the legacy `verify_receipt` path is already
    // `ingest_envelope_with_limits(.., &VerifierLimits::default())`, so the
    // default 1 MiB byte cap applies even with no flags. This guards against a
    // regression that re-routes the no-flag path to an uncapped verifier: an
    // input larger than `VerifierLimits::default().max_bytes` must still be
    // rejected as a typed limit violation when no flags are supplied, exactly
    // as a tightened explicit limit would.
    fn no_flag_path_preserves_default_byte_cap() {
        let oversized = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("oversized.json");
        let padding = "a".repeat(1_200_000);
        std::fs::write(&oversized, format!("{{\"x\":\"{padding}\"}}"))?;
        let path = oversized.to_string_lossy().into_owned();

        let no_flags = run_vr_verify(&["receipt", &path])?;
        assert_eq!(
            no_flags.status.code(),
            Some(1),
            "no-flag path must still enforce the default byte cap"
        );
        let no_flags_out = format!(
            "{}{}",
            String::from_utf8_lossy(&no_flags.stdout),
            String::from_utf8_lossy(&no_flags.stderr)
        );
        assert!(
            no_flags_out.contains("input too large"),
            "no-flag path must reject via the default limit; output={no_flags_out}"
        );

        // A tightened explicit limit rejects the same input identically.
        let limited = run_vr_verify(&["receipt", &path, "--max-bytes", "1048576"])?;
        assert_eq!(
            limited.status.code(),
            Some(1),
            "explicit default limit must also reject oversized input"
        );
    }
);

vr_test!(
    fn receipt_within_max_bytes_passes() {
        let len = raw_len("valid_single_envelope")?;
        let exact = len.to_string();
        let out = run_vr_verify(&[
            "receipt",
            &raw_path("valid_single_envelope"),
            "--max-bytes",
            &exact,
        ])?;
        assert_eq!(
            out.status.code(),
            Some(0),
            "receipt at exactly --max-bytes must pass; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
);

vr_test!(
    fn receipt_over_max_bytes_is_rejected() {
        let len = raw_len("valid_single_envelope")?;
        let under = (len - 1).to_string();
        let out = run_vr_verify(&[
            "receipt",
            &raw_path("valid_single_envelope"),
            "--max-bytes",
            &under,
        ])?;
        assert_eq!(
            out.status.code(),
            Some(1),
            "receipt larger than --max-bytes must be rejected; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            combined.contains("input too large"),
            "rejection must be a typed limit violation; output={combined}"
        );
    }
);

vr_test!(
    fn chain_without_flags_uses_default_path() {
        let out = run_vr_verify(&["chain", &raw_path("valid_chain_3")])?;
        assert_eq!(
            out.status.code(),
            Some(0),
            "no-flag chain must pass via the existing default path; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
);

vr_test!(
    fn chain_within_max_chain_length_passes() {
        let out = run_vr_verify(&[
            "chain",
            &raw_path("valid_chain_3"),
            "--max-chain-length",
            "3",
        ])?;
        assert_eq!(
            out.status.code(),
            Some(0),
            "3-envelope chain must pass at --max-chain-length 3; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
);

vr_test!(
    fn signed_with_trusted_policy_passes() {
        let out = run_vr_verify(&[
            "signed",
            &raw_path("valid_signed"),
            &raw_path("valid_sig"),
            "--trust",
            &raw_path("trust_accept"),
        ])?;
        assert_eq!(
            out.status.code(),
            Some(0),
            "signed receipt with trusted key must pass; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("\"trusted\""),
            "result must reflect the trust decision; stdout={stdout}"
        );
    }
);

vr_test!(
    fn signed_with_untrusted_policy_is_rejected() {
        let out = run_vr_verify(&[
            "signed",
            &raw_path("valid_signed"),
            &raw_path("valid_sig"),
            "--trust",
            &raw_path("trust_deny"),
        ])?;
        assert_eq!(
            out.status.code(),
            Some(1),
            "signed receipt with untrusted key must be rejected; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("\"untrusted\""),
            "result must reflect the untrusted decision; stdout={stdout}"
        );
    }
);

vr_test!(
    fn signed_without_trust_flag_uses_default_path() {
        let out = run_vr_verify(&["signed", &raw_path("valid_signed"), &raw_path("valid_sig")])?;
        assert_eq!(
            out.status.code(),
            Some(0),
            "no-trust signed verification must preserve existing behavior; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
);

vr_test!(
    fn zero_max_bytes_is_usage_error() {
        let out = run_vr_verify(&[
            "receipt",
            &raw_path("valid_single_envelope"),
            "--max-bytes",
            "0",
        ])?;
        assert_eq!(
            out.status.code(),
            Some(2),
            "--max-bytes 0 must be a CLI usage error, not an unlimited cap; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
);

vr_test!(
    fn max_chain_length_rejected_on_receipt() {
        let out = run_vr_verify(&[
            "receipt",
            &raw_path("valid_single_envelope"),
            "--max-chain-length",
            "5",
        ])?;
        assert_eq!(
            out.status.code(),
            Some(2),
            "--max-chain-length is not valid for 'receipt'; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
);

vr_test!(
    fn chain_over_max_chain_length_is_rejected() {
        let out = run_vr_verify(&[
            "chain",
            &raw_path("valid_chain_3"),
            "--max-chain-length",
            "2",
        ])?;
        assert_eq!(
            out.status.code(),
            Some(1),
            "3-envelope chain must be rejected at --max-chain-length 2; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
);
