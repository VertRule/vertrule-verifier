//! Bundle verification integration tests.
//!
//! Exercises bundle verification using only `vertrule-verifier`,
//! without browser runtime. This is the verifier-only gate described
//! in the bundle verification roadmap.

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

fn bundles_dir() -> std::path::PathBuf {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../vertrule-website/public/fixtures/bundles")
}

fn bundle_files() -> Vec<std::path::PathBuf> {
    let dir = bundles_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
        .collect()
}

vr_test!(
    /// Each shipped bundle fixture passes full verification.
    fn shipped_bundles_pass_verification() {
        let files = bundle_files();
        if files.is_empty() {
            eprintln!("SKIP: no bundle fixtures found");
            return Ok(());
        }

        for path in &files {
            let bytes = std::fs::read(path)
                .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
            let result = vertrule_verifier::verify_bundle(&bytes);

            anyhow::ensure!(
                result.status == vertrule_verifier::result::VerificationStatus::Valid,
                "{}: expected VALID, got {:?} — errors: {:?}",
                path.display(),
                result.status,
                result.errors,
            );

            for check in &result.sidecar_checks {
                anyhow::ensure!(
                    check.matches,
                    "{}: sidecar {} digest mismatch (expected {}, computed {})",
                    path.display(),
                    check.name,
                    check.expected,
                    check.computed,
                );
            }
        }
    }
);

vr_test!(
    /// Tampered sidecar data produces a digest mismatch.
    fn tampered_sidecar_detected() {
        let files = bundle_files();
        let Some(first) = files.first() else {
            eprintln!("SKIP: no bundle fixtures found");
            return Ok(());
        };

        let raw = std::fs::read_to_string(first)
            .map_err(|e| anyhow::anyhow!("read: {e}"))?;
        let mut bundle: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("parse: {e}"))?;

        // Tamper with the layer_trace sidecar
        if let Some(trace) = bundle
            .get_mut("sidecars")
            .and_then(|s| s.get_mut("layer_trace"))
        {
            trace["tampered_field"] = serde_json::json!("injected");
        }

        let bytes = serde_json::to_vec(&bundle)
            .map_err(|e| anyhow::anyhow!("serialize: {e}"))?;
        let result = vertrule_verifier::verify_bundle(&bytes);

        anyhow::ensure!(
            result.status == vertrule_verifier::result::VerificationStatus::Invalid,
            "tampered bundle should be INVALID",
        );
        anyhow::ensure!(
            result.sidecar_checks.iter().any(|c| !c.matches),
            "at least one sidecar check should fail",
        );
    }
);
