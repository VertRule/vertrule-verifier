//! CLI-level tests for the `vr-verify external` subcommand.
//!
//! Drives the compiled binary against committed external-receipt fixtures
//! produced by `examples/generate_test_vectors.rs`, asserting the documented
//! contract: exit `0` for a valid externally-minted receipt and `1` for an
//! invalid (tampered) one.

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

vr_test!(
    fn external_valid_receipt_exits_zero() {
        let out = run_vr_verify(&["external", &raw_path("valid_external_receipt")])?;
        assert_eq!(
            out.status.code(),
            Some(0),
            "expected exit 0 for a valid external receipt; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
);

vr_test!(
    fn external_emits_canonical_metadata_json() {
        let out = run_vr_verify(&["external", &raw_path("valid_external_receipt")])?;
        let stdout = out.stdout;
        let body = stdout.strip_suffix(b"\n").unwrap_or(&stdout);
        assert!(
            !body.is_empty(),
            "external should emit verified metadata on stdout"
        );
        let value: serde_json::Value = serde_json::from_slice(body)?;
        let recanon = vr_jcs::to_canon_bytes_from_slice(&serde_json::to_vec(&value)?)?;
        assert_eq!(
            body,
            recanon.as_slice(),
            "stdout metadata must be JCS-canonical"
        );
    }
);

vr_test!(
    fn external_invalid_receipt_exits_one() {
        let out = run_vr_verify(&["external", &raw_path("invalid_external_receipt")])?;
        assert_eq!(
            out.status.code(),
            Some(1),
            "expected exit 1 for a tampered external receipt; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
);

vr_test!(
    fn usage_lists_external_subcommand() {
        let out = run_vr_verify(&["bogus", "x.json"])?;
        assert_eq!(
            out.status.code(),
            Some(2),
            "unknown subcommand should be a usage error"
        );
        let usage = String::from_utf8_lossy(&out.stderr);
        assert!(
            usage.contains("external"),
            "usage text should list the 'external' subcommand; stderr={usage}"
        );
    }
);
