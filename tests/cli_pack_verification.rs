//! CLI-level tests for the `vr-verify` binary's layered-family pack
//! subcommands (`layered` / `decision` / `closure`).
//!
//! These drive the compiled binary against committed fixtures produced by
//! `examples/generate_test_vectors.rs`, asserting the documented contract:
//! exit `0` for a valid artifact, `1` for a single-fault-invalid one, and
//! JCS-canonical result JSON on stdout.

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
    fn layered_valid_pack_exits_zero() {
        let out = run_vr_verify(&["layered", &raw_path("valid_layered_pack")])?;
        assert_eq!(
            out.status.code(),
            Some(0),
            "expected exit 0 for a valid layered pack; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
);

vr_test!(
    fn layered_invalid_pack_exits_one() {
        let out = run_vr_verify(&["layered", &raw_path("invalid_layered_pack")])?;
        assert_eq!(
            out.status.code(),
            Some(1),
            "expected exit 1 for a single-fault-invalid layered pack; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
);

vr_test!(
    fn layered_emits_canonical_result_json() {
        let out = run_vr_verify(&["layered", &raw_path("valid_layered_pack")])?;
        let stdout = out.stdout;
        let body = stdout.strip_suffix(b"\n").unwrap_or(&stdout);
        let value: serde_json::Value = serde_json::from_slice(body)?;
        let recanon = vr_jcs::to_canon_bytes_from_slice(&serde_json::to_vec(&value)?)?;
        assert_eq!(
            body,
            recanon.as_slice(),
            "stdout result must be JCS-canonical"
        );
    }
);

vr_test!(
    fn decision_valid_pack_exits_zero() {
        let out = run_vr_verify(&["decision", &raw_path("valid_decision_pack")])?;
        assert_eq!(
            out.status.code(),
            Some(0),
            "expected exit 0 for a valid decision pack; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
);

vr_test!(
    fn decision_invalid_pack_exits_one() {
        let out = run_vr_verify(&["decision", &raw_path("invalid_decision_pack")])?;
        assert_eq!(
            out.status.code(),
            Some(1),
            "expected exit 1 for a single-fault-invalid decision pack; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
);

vr_test!(
    fn closure_valid_bundle_exits_zero() {
        let out = run_vr_verify(&["closure", &raw_path("valid_closure_bundle")])?;
        assert_eq!(
            out.status.code(),
            Some(0),
            "expected exit 0 for a valid closure bundle; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
);

vr_test!(
    fn closure_invalid_bundle_exits_one() {
        let out = run_vr_verify(&["closure", &raw_path("invalid_closure_bundle")])?;
        assert_eq!(
            out.status.code(),
            Some(1),
            "expected exit 1 for a single-fault-invalid closure bundle; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
);

vr_test!(
    fn unknown_subcommand_exits_two_and_usage_lists_packs() {
        let out = run_vr_verify(&["bogus", "x.json"])?;
        assert_eq!(
            out.status.code(),
            Some(2),
            "unknown subcommand should be a usage error"
        );
        let usage = String::from_utf8_lossy(&out.stderr);
        for sub in ["layered", "decision", "closure"] {
            assert!(
                usage.contains(sub),
                "usage text should list the '{sub}' subcommand; stderr={usage}"
            );
        }
    }
);
