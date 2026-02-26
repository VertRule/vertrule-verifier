//! Dependency boundary enforcement test.
//!
//! Ensures that `vr-verifier` does not depend on any runtime crates.
//! This is the single most important architectural invariant of the crate:
//! it must be auditable without trusting the runtime.

use vr_kernel_testutils::vr_test;

/// Runtime crate names that must NEVER appear as package dependencies.
const FORBIDDEN_DEPS: &[&str] = &[
    "vertrule-core",
    "vertrule-schema",
    "vertrule-app",
    "vertrule-adapters",
    "vertrule-cli",
];

vr_test!(
    fn no_runtime_dependencies_in_cargo_toml() {
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cargo_toml = std::fs::read_to_string(manifest.join("Cargo.toml"))
            .map_err(|e| anyhow::anyhow!("failed to read Cargo.toml: {e}"))?;

        // Extract only the [dependencies] section (not [dev-dependencies])
        // to avoid false positives from path strings.
        let deps_section = extract_dependencies_section(&cargo_toml);

        for dep in FORBIDDEN_DEPS {
            anyhow::ensure!(
                !deps_section.contains(dep),
                "Cargo.toml [dependencies] must not contain dependency on '{dep}'"
            );
        }
    }
);

/// Extract the `[dependencies]` section from a Cargo.toml string.
/// Returns only the lines between `[dependencies]` and the next `[` section header.
fn extract_dependencies_section(cargo_toml: &str) -> String {
    let mut in_deps = false;
    let mut section = String::new();
    for line in cargo_toml.lines() {
        let trimmed = line.trim();
        if trimmed == "[dependencies]" {
            in_deps = true;
            continue;
        }
        if in_deps && trimmed.starts_with('[') {
            break;
        }
        if in_deps {
            section.push_str(line);
            section.push('\n');
        }
    }
    section
}
