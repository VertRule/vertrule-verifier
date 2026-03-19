//! Generate constitutional artifacts for all 6 constitutional crates.
//!
//! Produces one `ReceiptEnvelope` per crate, chained in layer order,
//! then self-verifies every artifact using the `vr-verifier` facade API.
//!
//! Run with:
//! ```bash
//! cargo run --example generate_constitutional_artifact -p vr-verifier
//! ```

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

struct CrateSpec {
    name: &'static str,
    source_rel: &'static str,
    layer: u32,
    logical_time: u64,
}

const CONSTITUTIONAL_CRATES: &[CrateSpec] = &[
    CrateSpec {
        name: "vertrule-schemas",
        source_rel: "vertrule-schemas",
        layer: 0,
        logical_time: 0,
    },
    CrateSpec {
        name: "vr-jcs",
        source_rel: "vertrule-runtime/crates/vr-jcs",
        layer: 1,
        logical_time: 1000,
    },
    CrateSpec {
        name: "vr-time",
        source_rel: "vertrule-runtime/crates/vr-time",
        layer: 1,
        logical_time: 1001,
    },
    CrateSpec {
        name: "vr-receipt",
        source_rel: "vertrule-runtime/crates/vr-receipt",
        layer: 2,
        logical_time: 2000,
    },
    CrateSpec {
        name: "vr-rbh",
        source_rel: "vertrule-runtime/crates/vr-rbh",
        layer: 3,
        logical_time: 3000,
    },
    CrateSpec {
        name: "vr-verifier",
        source_rel: "vertrule-verifier",
        layer: 4,
        logical_time: 4000,
    },
];

// ---------------------------------------------------------------------------
// Source digest
// ---------------------------------------------------------------------------

/// Recursively collect all `.rs` files under `dir`, relative to `base`.
fn collect_rs_files(
    base: &Path,
    dir: &Path,
    out: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(base, &path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let rel = path.strip_prefix(base)?;
            out.push(rel.to_path_buf());
        }
    }
    Ok(())
}

/// Compute a content-only source digest for a crate's `src/` directory.
///
/// Algorithm:
/// 1. Walk `src/` recursively, collect all `.rs` files
/// 2. Sort paths lexicographically (with `/` separators)
/// 3. For each file: `blake3::hash(file_bytes)`
/// 4. Build manifest: `"path\0hex_digest\n"` per file
/// 5. Return `blake3::hash(manifest_bytes)`
fn compute_source_digest(crate_dir: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let src_dir = crate_dir.join("src");
    let mut files = Vec::new();
    collect_rs_files(crate_dir, &src_dir, &mut files)?;

    // Normalize to forward slashes and sort
    let mut normalized: Vec<String> = files
        .iter()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .collect();
    normalized.sort();

    let mut manifest = Vec::new();
    for rel_path in &normalized {
        let full = crate_dir.join(rel_path);
        let bytes = std::fs::read(&full)?;
        let digest = hex::encode(blake3::hash(&bytes).as_bytes());
        manifest.extend_from_slice(rel_path.as_bytes());
        manifest.push(0); // \0
        manifest.extend_from_slice(digest.as_bytes());
        manifest.push(b'\n');
    }

    Ok(hex::encode(blake3::hash(&manifest).as_bytes()))
}

/// Compute BLAKE3 hex digest of a file's contents.
fn file_digest(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    Ok(hex::encode(blake3::hash(&bytes).as_bytes()))
}

// ---------------------------------------------------------------------------
// TOML parsing (section-aware, no toml crate)
// ---------------------------------------------------------------------------

/// Extract a field value from a TOML file within a specific section.
///
/// Looks for `[section]` header, then finds `field = "value"` within it.
fn extract_field_from_section(content: &str, section: &str, field: &str) -> Option<String> {
    let section_header = format!("[{section}]");
    let mut in_section = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_section = trimmed == section_header;
            continue;
        }
        if in_section {
            if let Some(rest) = trimmed.strip_prefix(field) {
                let rest = rest.trim_start();
                if let Some(rest) = rest.strip_prefix('=') {
                    let val = rest.trim().trim_matches('"');
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Toolchain capture
// ---------------------------------------------------------------------------

fn capture_toolchain() -> Result<(String, String), Box<dyn std::error::Error>> {
    let version_output = Command::new("rustc").arg("--version").output()?;
    let rustc_version = String::from_utf8(version_output.stdout)?.trim().to_string();

    let verbose_output = Command::new("rustc").arg("-vV").output()?;
    let verbose = String::from_utf8(verbose_output.stdout)?;
    let host = verbose
        .lines()
        .find(|l| l.starts_with("host:"))
        .map(|l| l.trim_start_matches("host:").trim().to_string())
        .ok_or("could not find host in rustc -vV output")?;

    Ok((rustc_version, host))
}

// ---------------------------------------------------------------------------
// Hashing helpers
// ---------------------------------------------------------------------------

/// Compute BLAKE3 hex digest of the JCS-canonical form of a JSON value.
fn canon_hash(value: &serde_json::Value) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = vertrule_schemas::jcs::to_canon_bytes(value)?;
    Ok(hex::encode(blake3::hash(&bytes).as_bytes()))
}

/// Compute `context_digest`: BLAKE3 of canonical `{authority_set_digest, policy_digest}`.
fn compute_context_digest(
    authority_set_digest: &str,
    policy_digest: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let obj = json!({
        "authority_set_digest": authority_set_digest,
        "policy_digest": policy_digest,
    });
    canon_hash(&obj)
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Sign a payload following the exact protocol from `generate_test_vectors.rs`.
///
/// Key constraint: signature is over the **payload** (not the envelope).
fn sign_payload(
    payload: &serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let seed: [u8; 32] = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key();

    // Domain-separated receipt digest
    let canon_bytes = vertrule_schemas::jcs::to_canon_bytes(payload)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"VR-ReceiptDigest|v1|");
    hasher.update(&canon_bytes);
    let receipt_hex = hex::encode(hasher.finalize().as_bytes());

    // Canonical message with fixed timestamp
    let timestamp = "ceremony-v0";
    let mut msg = Vec::new();
    msg.extend_from_slice(b"VR-ReceiptSig|v1|");
    msg.extend_from_slice(receipt_hex.as_bytes());
    msg.push(b'|');
    msg.extend_from_slice(timestamp.as_bytes());

    // Sign
    let sig = sk.sign(&msg);
    let kid = hex::encode(&blake3::hash(pk.as_bytes()).as_bytes()[..12]);

    Ok(json!({
        "alg": "Ed25519",
        "key_id": kid,
        "public_key_b64": base64::engine::general_purpose::STANDARD.encode(pk.as_bytes()),
        "signature_b64": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        "schema_version": "0.2",
        "digest_basis": "BLAKE3+JCS",
        "timestamp": timestamp,
    }))
}

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

/// Write JCS-canonical bytes to a file.
fn write_canonical(
    path: &Path,
    value: &serde_json::Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let canon = vertrule_schemas::jcs::to_canon_bytes(value)?;
    let mut file = std::fs::File::create(path)?;
    file.write_all(&canon)?;
    file.flush()?;
    eprintln!("  wrote {}", path.display());
    Ok(canon)
}

// ---------------------------------------------------------------------------
// Self-verification
// ---------------------------------------------------------------------------

fn verify_artifacts(out_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("\n=== Self-Verification ===");

    // Verify each individual envelope + signature
    for spec in CONSTITUTIONAL_CRATES {
        let env_path = out_dir.join(format!("{}.json", spec.name));
        let sig_path = out_dir.join(format!("{}.sig.json", spec.name));

        let env_bytes = std::fs::read(&env_path)?;
        let sig_bytes = std::fs::read(&sig_path)?;

        let result = vr_verifier::verify_signed_receipt(&env_bytes, &sig_bytes);
        if result.status != vr_verifier::result::VerificationStatus::Valid {
            return Err(format!(
                "signed receipt verification failed for {}: {:?}",
                spec.name, result.errors
            )
            .into());
        }
        eprintln!("  {} signed receipt: VALID", spec.name);
    }

    // Verify chain
    let chain_path = out_dir.join("chain.json");
    let chain_bytes = std::fs::read(&chain_path)?;
    let result = vr_verifier::verify_receipt_chain(&chain_bytes);

    if result.status != vr_verifier::result::VerificationStatus::Valid {
        return Err(format!("chain verification failed: {:?}", result.errors).into());
    }

    let dv = &result.digest_validation;
    if !dv.chain_integrity {
        return Err("chain_integrity is false".into());
    }
    if !dv.ordering_valid {
        return Err("ordering_valid is false".into());
    }

    if let Some(ref cc) = result.context_consistency {
        if !cc.uniform_context {
            return Err("uniform_context is false".into());
        }
    }

    if let Some(ref pc) = result.policy_consistency {
        if !pc.stable_policy {
            return Err("stable_policy is false".into());
        }
    }

    eprintln!(
        "  chain: VALID (length={}, integrity=true, ordering=true)",
        result.chain_validation.as_ref().map_or(0, |cv| cv.length)
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let repositories_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let repositories_root = repositories_root.canonicalize()?;
    let out_dir = repositories_root.join("artifacts").join("constitutional");
    std::fs::create_dir_all(&out_dir)?;

    eprintln!("=== Constitutional Artifact Generation ===");
    eprintln!("  repositories: {}", repositories_root.display());
    eprintln!("  output:    {}", out_dir.display());

    // Capture toolchain (deterministic per machine)
    let (rustc_version, target) = capture_toolchain()?;
    eprintln!("  toolchain: {rustc_version}");
    eprintln!("  target:    {target}");

    // Shared digests across all envelopes
    // authority_set_digest: BLAKE3 of the governance authority set (placeholder for Stage 0)
    let authority_set_hex = hex::encode(blake3::hash(b"constitutional-ceremony-v0").as_bytes());
    // policy_digest: BLAKE3 of the determinism policy file
    let policy_path = repositories_root
        .join("vertrule-schemas")
        .join("governance")
        .join("policies")
        .join("determinism@0.1")
        .join("policy.toml");
    let policy_digest_hex = file_digest(&policy_path)?;
    // context_digest: BLAKE3(canonical {authority_set_digest, policy_digest})
    let context_digest_hex = compute_context_digest(&authority_set_hex, &policy_digest_hex)?;
    // schema_digest: BLAKE3 of schema identifier string
    let schema_digest_hex = hex::encode(blake3::hash(b"GovernanceReceipt.schema.json").as_bytes());

    eprintln!("\n=== Generating Envelopes ===");

    let mut envelopes = Vec::new();
    let mut parent_hash: Option<String> = None;

    for spec in CONSTITUTIONAL_CRATES {
        let spec_dir = repositories_root.join(spec.source_rel);
        let manifest_path = spec_dir.join("governance").join("manifest.toml");
        let known_nd_path = spec_dir
            .join("governance")
            .join("known-nondeterminism.toml");

        // Read manifest
        let manifest_content = std::fs::read_to_string(&manifest_path)?;
        let crate_version = extract_field_from_section(&manifest_content, "crate", "version")
            .ok_or_else(|| format!("missing version in {}", manifest_path.display()))?;
        let determinism = extract_field_from_section(&manifest_content, "stage", "determinism")
            .ok_or_else(|| format!("missing determinism in {}", manifest_path.display()))?;

        // Compute digests
        let source_digest = compute_source_digest(&spec_dir)?;
        let gov_manifest_digest = file_digest(&manifest_path)?;
        let known_nd_digest = file_digest(&known_nd_path)?;

        // Build payload
        let payload = json!({
            "artifact_version": 1,
            "crate_name": spec.name,
            "crate_version": crate_version,
            "layer": spec.layer,
            "stage": 0,
            "determinism": determinism,
            "source_digest": source_digest,
            "governance_manifest_digest": gov_manifest_digest,
            "known_nondeterminism_digest": known_nd_digest,
            "toolchain": {
                "rustc_version": rustc_version,
                "target": target,
            },
        });

        let event_hash = canon_hash(&payload)?;

        // Build envelope
        let mut envelope = json!({
            "envelope_version": 1,
            "receipt_type": "governance",
            "context_digest": context_digest_hex,
            "schema_digest": schema_digest_hex,
            "policy_digest": policy_digest_hex,
            "logical_time": spec.logical_time,
            "event_hash": event_hash,
            "boundary_origin": "governance",
            "payload": payload,
        });

        if let Some(ref pid) = parent_hash {
            envelope["parent_id"] = json!(pid);
        }

        // Sign the payload
        let sig_bundle = sign_payload(&payload)?;

        // Write envelope
        let env_path = out_dir.join(format!("{}.json", spec.name));
        write_canonical(&env_path, &envelope)?;

        // Write signature bundle
        let sig_path = out_dir.join(format!("{}.sig.json", spec.name));
        write_canonical(&sig_path, &sig_bundle)?;

        parent_hash = Some(event_hash);
        envelopes.push(envelope);

        eprintln!(
            "  {} (layer={}, time={}): OK",
            spec.name, spec.layer, spec.logical_time
        );
    }

    // Write chain
    eprintln!("\n=== Writing Chain ===");
    let chain = serde_json::Value::Array(envelopes);
    let chain_path = out_dir.join("chain.json");
    write_canonical(&chain_path, &chain)?;

    // Self-verify
    verify_artifacts(&out_dir)?;

    eprintln!("\n=== DONE ===");
    eprintln!("All 6 constitutional artifacts generated and verified.");
    Ok(())
}
