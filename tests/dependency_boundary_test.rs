//! Dependency boundary enforcement test.
//!
//! Ensures that `vertrule-verifier` does not depend on any runtime crates.
//! This is the single most important architectural invariant of the crate:
//! it must be auditable without trusting the runtime.

/// Runtime crate names that must NEVER appear as package dependencies.
const FORBIDDEN_DEPS: &[&str] = &[
    "vertrule-core",
    "vertrule-app",
    "vertrule-adapters",
    "vertrule-cli",
    "vertrule-runtime",
    "vertrule-crypto",
    "vertrule-governance",
];

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

vr_test!(
    fn no_runtime_dependencies_in_cargo_toml() {
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cargo_toml = std::fs::read_to_string(manifest.join("Cargo.toml"))
            .map_err(|e| anyhow::anyhow!("failed to read Cargo.toml: {e}"))?;

        let dependency_names = extract_dependency_names(&cargo_toml);

        for dep in FORBIDDEN_DEPS {
            anyhow::ensure!(
                !dependency_names.iter().any(|name| name == dep),
                "Cargo.toml [dependencies] must not contain dependency on '{dep}'"
            );
        }
    }
);

/// Extract the dependency keys from the `[dependencies]` section of a Cargo.toml file.
fn extract_dependency_names(cargo_toml: &str) -> Vec<String> {
    let mut in_deps = false;
    let mut names = Vec::new();

    for line in cargo_toml.lines() {
        let trimmed = line.trim();
        if trimmed == "[dependencies]" {
            in_deps = true;
            continue;
        }
        if in_deps && trimmed.starts_with('[') {
            break;
        }
        if !in_deps || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some((name, _)) = trimmed.split_once('=') {
            names.push(name.trim().to_string());
        }
    }

    names
}
