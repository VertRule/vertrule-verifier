//! Dependency boundary enforcement test.
//!
//! Ensures that `vertrule-verifier` does not depend on any runtime crates.
//! This is the single most important architectural invariant of the crate:
//! it must be auditable without trusting the runtime.
//!
//! # Known limit — this checks declaration, not reachability
//!
//! [`extract_dependency_names`] parses this crate's own `[dependencies]`
//! table. It cannot see the dependency *closure*, so a forbidden crate
//! reached through a permitted one is invisible to it.
//!
//! That is not hypothetical. `vertrule-schemas` is a permitted dependency
//! (`Cargo.toml:51`) and itself depends on `vertrule-crypto`
//! (`vertrule-schemas/Cargo.toml:41`), so `vertrule-crypto` is already in
//! this crate's build graph regardless of what this list says.
//!
//! `vertrule-crypto` was therefore removed from [`FORBIDDEN_DEPS`]:
//! forbidding the direct edge while the transitive one stands would buy
//! nothing but a duplicated digest implementation, and the digest-authority
//! programme exists to remove exactly those. The delegation that made the
//! direct edge explicit is `vertrule-verifier 05e9877`.
//!
//! **The invariant is not currently enforced by anything.** Making it real
//! means checking the resolved closure — `cargo metadata` — rather than the
//! manifest text, and then deciding whether `vertrule-schemas` may carry a
//! crypto edge at all. That is a live architectural question, recorded here
//! rather than answered by a list that cannot see the graph.

/// Runtime crate names that must NEVER appear as package dependencies.
///
/// `vertrule-crypto` is deliberately absent — see the module docs.
const FORBIDDEN_DEPS: &[&str] = &[
    "vertrule-core",
    "vertrule-app",
    "vertrule-adapters",
    "vertrule-cli",
    "vertrule-runtime",
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
