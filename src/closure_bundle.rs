//! Closure-committed bundle verification (ADR-040, transitive law).
//!
//! Verifies a `vr-layered-bundle/v1` artifact: a root `pack.v0` receipt, a
//! [`ClosureManifest`](vertrule_schemas::ClosureManifest), and every
//! receipt in the resolved transitive closure. This is the between-node
//! authority the policy clause kernel deliberately does not own.
//!
//! The deny table beyond per-envelope verification:
//!
//! - **manifest self-commit drift** — `BLAKE3(JCS(manifest \
//!   {manifest_digest}))` must equal both the manifest's own
//!   `manifest_digest` and the root pack receipt's committed
//!   `closure_manifest_digest`;
//! - **root mismatch** — the manifest's `root_event_hash` must equal the
//!   root envelope's `event_hash`;
//! - **untyped edge** in any layered-family receipt → reject;
//! - **missing / failed / schema-mismatched** typed edge → reject;
//! - **dependency cycle** over `depends_on` → reject;
//! - **closure completeness** — the set reachable from the root must equal
//!   `receipt_closure` exactly (a reachable receipt absent from the
//!   manifest, or a manifest entry not reachable, → reject), and
//!   `dependency_count` must equal `receipt_closure.len()`.
//!
//! The walk is deterministic: edges are followed in committed support-set
//! order, the closure set is a `BTreeSet`, and there is no clock.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use vertrule_schemas::receipts::{MODEL_PAYLOAD_KIND, PACK_PAYLOAD_KIND, PROVIDER_PAYLOAD_KIND};
use vertrule_schemas::SupportMember;

use crate::error::VerifyError;
use crate::layered_pack::{EdgeCheck, EdgeStatus};
use crate::result::{VerificationResult, VerificationStatus};
use crate::schema_profile::PROFILE_VERSION;

/// Expected bundle format identifier.
const EXPECTED_FORMAT: &str = "vr-layered-bundle/v1";

/// Layered-family payload kinds admitted in a closure bundle.
const LAYERED_KINDS: [&str; 3] = [PROVIDER_PAYLOAD_KIND, MODEL_PAYLOAD_KIND, PACK_PAYLOAD_KIND];

// ── Types ──────────────────────────────────────────────────────────

/// Deserialized closure bundle (input).
#[derive(Debug, Deserialize)]
struct ClosureBundle {
    #[serde(rename = "_format")]
    format: String,
    root_canonical: String,
    manifest: serde_json::Value,
    #[serde(default)]
    receipts: Vec<String>,
}

/// Structured result of verifying a closure bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureBundleVerificationResult {
    /// Overall status — `VALID` only when every check below holds.
    pub status: VerificationStatus,
    /// Schema profile version used for envelope verification.
    pub schema_version: String,
    /// Full verification result for the root pack envelope.
    pub root_result: VerificationResult,
    /// The root pack receipt's `event_hash`, when parseable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_event_hash: Option<String>,
    /// Number of receipts in the resolved reachable closure.
    pub closure_size: usize,
    /// Whether the manifest self-digest matches both the manifest and the
    /// root's committed `closure_manifest_digest`.
    pub manifest_digest_ok: bool,
    /// Whether the reachable closure equals the committed `receipt_closure`.
    pub closure_complete: bool,
    /// Whether a `depends_on` cycle was detected.
    pub cycle_detected: bool,
    /// Per-edge walk results across the whole closure, in walk order.
    pub edge_checks: Vec<EdgeCheck>,
    /// Collected error messages (empty when valid).
    pub errors: Vec<String>,
}

impl ClosureBundleVerificationResult {
    /// Serialize this result to JCS-canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns error if serialization or canonicalization fails.
    pub fn to_canon_bytes(&self) -> Result<Vec<u8>, VerifyError> {
        let value = serde_json::to_value(self).map_err(|e| VerifyError::Canon(format!("{e}")))?;
        crate::canon::typed_canon_bytes(&value)
    }
}

// ── Verification ───────────────────────────────────────────────────

/// A receipt resolved into the closure graph.
struct Node {
    payload_kind: String,
    support_set: Vec<SupportMember>,
    verify_status: VerificationStatus,
    verify_detail: String,
}

/// Verify a closure bundle from raw JSON bytes.
///
/// Fail-closed: any malformed input, failed envelope, manifest drift,
/// untyped edge, cycle, or closure-completeness failure yields `INVALID`.
#[must_use]
pub fn verify_closure_bundle(raw_bytes: &[u8]) -> ClosureBundleVerificationResult {
    let bundle: ClosureBundle = match serde_json::from_slice(raw_bytes) {
        Ok(b) => b,
        Err(e) => return invalid(format!("malformed bundle JSON: {e}")),
    };
    if bundle.format != EXPECTED_FORMAT {
        return invalid(format!(
            "unsupported bundle format: expected \"{EXPECTED_FORMAT}\", got \"{}\"",
            bundle.format
        ));
    }

    let mut errors = Vec::new();

    // 1. Verify the root pack envelope and admit it as pack.v0.
    let root_result = crate::verify_receipt(bundle.root_canonical.as_bytes());
    if root_result.status != VerificationStatus::Valid {
        for e in &root_result.errors {
            errors.push(format!("root envelope: {e}"));
        }
    }
    let root_value: serde_json::Value = match serde_json::from_str(&bundle.root_canonical) {
        Ok(v) => v,
        Err(e) => return invalid(format!("malformed root envelope: {e}")),
    };
    let root_event_hash = read_event_hash(&root_value);
    let root_kind = read_payload_kind(&root_value);
    if root_kind.as_deref() != Some(PACK_PAYLOAD_KIND) {
        errors.push(format!(
            "root is not a pack receipt: payload_kind {root_kind:?} != \"{PACK_PAYLOAD_KIND}\""
        ));
    }
    let committed_closure_digest = root_value
        .get("payload")
        .and_then(|p| p.get("closure_manifest_digest"))
        .and_then(serde_json::Value::as_str)
        .map(String::from);

    // 2. Verify the manifest self-commit against itself and the root.
    let manifest_digest_ok = check_manifest_digest(
        &bundle.manifest,
        committed_closure_digest.as_deref(),
        &mut errors,
    );

    // 3. Build the receipt graph (root + supplied), keyed by event_hash.
    let mut index: BTreeMap<String, Node> = BTreeMap::new();
    insert_node(&mut index, &root_value, &bundle.root_canonical);
    for raw in &bundle.receipts {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
            insert_node(&mut index, &v, raw);
        } else {
            errors.push("a supplied receipt is not valid JSON and was ignored".to_string());
        }
    }

    // 4. Transitive walk from the root over typed depends_on edges.
    let mut edge_checks = Vec::new();
    let mut reachable: BTreeSet<String> = BTreeSet::new();
    let mut cycle_detected = false;
    if let Some(root_h) = &root_event_hash {
        let mut on_stack: BTreeSet<String> = BTreeSet::new();
        walk(
            root_h,
            &index,
            &mut reachable,
            &mut on_stack,
            &mut edge_checks,
            &mut cycle_detected,
        );
    } else {
        errors.push("root envelope has no readable event_hash".to_string());
    }
    for c in &edge_checks {
        if c.status != EdgeStatus::Resolved {
            errors.push(format!(
                "lineage edge \"{}\" is OUT ({:?})",
                c.event_hash, c.status
            ));
        }
    }
    if cycle_detected {
        errors.push("dependency cycle detected over depends_on".to_string());
    }

    // 5. Closure completeness: the dependency set (reachable, excluding
    //    the root) must equal the committed receipt_closure exactly.
    let committed: BTreeSet<String> = bundle
        .manifest
        .get("receipt_closure")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let mut dependencies = reachable.clone();
    if let Some(root_h) = &root_event_hash {
        dependencies.remove(root_h);
    }
    let closure_complete = committed == dependencies;
    if !closure_complete {
        for missing in dependencies.difference(&committed) {
            errors.push(format!(
                "reachable dependency \"{missing}\" is absent from receipt_closure"
            ));
        }
        for extra in committed.difference(&dependencies) {
            errors.push(format!(
                "receipt_closure entry \"{extra}\" is not reachable from the root"
            ));
        }
    }

    let status = if root_result.status == VerificationStatus::Valid
        && manifest_digest_ok
        && closure_complete
        && !cycle_detected
        && errors.is_empty()
    {
        VerificationStatus::Valid
    } else {
        VerificationStatus::Invalid
    };

    ClosureBundleVerificationResult {
        status,
        schema_version: PROFILE_VERSION.to_string(),
        root_result,
        root_event_hash,
        closure_size: dependencies.len(),
        manifest_digest_ok,
        closure_complete,
        cycle_detected,
        edge_checks,
        errors,
    }
}

// ── Helpers ────────────────────────────────────────────────────────

/// Recompute the manifest self-digest and check it against the manifest's
/// own `manifest_digest`, the root's `closure_manifest_digest`, the
/// `root_event_hash`, and the `dependency_count` invariant.
fn check_manifest_digest(
    manifest: &serde_json::Value,
    committed_root_digest: Option<&str>,
    errors: &mut Vec<String>,
) -> bool {
    let Some(obj) = manifest.as_object() else {
        errors.push("bundle manifest is not a JSON object".to_string());
        return false;
    };
    let stated = obj
        .get("manifest_digest")
        .and_then(serde_json::Value::as_str);
    let mut body = obj.clone();
    body.remove("manifest_digest");
    let recomputed = crate::canon::typed_canon_bytes(&serde_json::Value::Object(body))
        .ok()
        .map(|b| crate::identity::GenericByteDigest::from_bytes(&b).to_hex_string());

    let mut ok = true;
    match (recomputed.as_deref(), stated) {
        (Some(r), Some(s)) if r == s => {}
        (Some(r), Some(s)) => {
            errors.push(format!(
                "manifest_digest drift: recomputed \"{r}\" != stated \"{s}\""
            ));
            ok = false;
        }
        _ => {
            errors.push("manifest_digest could not be computed or is absent".to_string());
            ok = false;
        }
    }
    if let (Some(r), Some(c)) = (recomputed.as_deref(), committed_root_digest) {
        if r != c {
            errors.push(format!(
                "root closure_manifest_digest \"{c}\" != manifest digest \"{r}\""
            ));
            ok = false;
        }
    } else if committed_root_digest.is_none() {
        errors.push("root pack receipt does not commit a closure_manifest_digest".to_string());
        ok = false;
    }
    let count = obj
        .get("dependency_count")
        .and_then(serde_json::Value::as_u64);
    let listed = obj
        .get("receipt_closure")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len);
    if let (Some(c), Some(l)) = (count, listed) {
        if usize::try_from(c).ok() != Some(l) {
            errors.push(format!(
                "dependency_count {c} != receipt_closure length {l}"
            ));
            ok = false;
        }
    }
    ok
}

/// Insert a verified receipt node into the graph index.
fn insert_node(index: &mut BTreeMap<String, Node>, value: &serde_json::Value, raw: &str) {
    let Some(event_hash) = read_event_hash(value) else {
        return;
    };
    let payload_kind = read_payload_kind(value).unwrap_or_default();
    let support_set = value
        .get("payload")
        .and_then(|p| p.get("support_set"))
        .cloned()
        .map_or_else(Vec::new, |s| serde_json::from_value(s).unwrap_or_default());
    let result = crate::verify_receipt(raw.as_bytes());
    index.insert(
        event_hash,
        Node {
            payload_kind,
            support_set,
            verify_status: result.status,
            verify_detail: result.errors.join("; "),
        },
    );
}

/// Depth-first transitive walk over typed `depends_on` edges with cycle
/// detection. Records one [`EdgeCheck`] per dependency member and the set
/// of reachable receipts (including the root).
fn walk(
    node_hash: &str,
    index: &BTreeMap<String, Node>,
    reachable: &mut BTreeSet<String>,
    on_stack: &mut BTreeSet<String>,
    edge_checks: &mut Vec<EdgeCheck>,
    cycle_detected: &mut bool,
) {
    if reachable.contains(node_hash) {
        return;
    }
    reachable.insert(node_hash.to_string());
    on_stack.insert(node_hash.to_string());

    if let Some(node) = index.get(node_hash) {
        for member in &node.support_set {
            match member {
                SupportMember::TypedReceiptDependency {
                    event_hash,
                    role,
                    target_schema,
                    ..
                } => {
                    let role_label = serde_json::to_value(role)
                        .ok()
                        .and_then(|v| v.as_str().map(String::from));
                    let target = index.get(event_hash);
                    let (status, detail) = classify_edge(event_hash, target, target_schema);
                    edge_checks.push(EdgeCheck {
                        event_hash: event_hash.clone(),
                        role: role_label,
                        target_schema: Some(target_schema.clone()),
                        status,
                        detail,
                    });
                    if on_stack.contains(event_hash) {
                        *cycle_detected = true;
                    } else if status == EdgeStatus::Resolved {
                        walk(
                            event_hash,
                            index,
                            reachable,
                            on_stack,
                            edge_checks,
                            cycle_detected,
                        );
                    }
                }
                SupportMember::DependedOnReceipt { event_hash } => {
                    edge_checks.push(EdgeCheck {
                        event_hash: event_hash.clone(),
                        role: None,
                        target_schema: None,
                        status: EdgeStatus::UntypedEdge,
                        detail: Some(
                            "untyped depended_on_receipt edge in a layered-family receipt"
                                .to_string(),
                        ),
                    });
                }
                SupportMember::CitedLink { .. }
                | SupportMember::EvidenceDigest { .. }
                | SupportMember::SelectorValue { .. } => {}
            }
        }
    }
    on_stack.remove(node_hash);
}

/// Classify a typed edge against the resolved target node.
fn classify_edge(
    event_hash: &str,
    target: Option<&Node>,
    target_schema: &str,
) -> (EdgeStatus, Option<String>) {
    match target {
        None => (
            EdgeStatus::Missing,
            Some(format!(
                "depended-on receipt \"{event_hash}\" not supplied in bundle"
            )),
        ),
        Some(n) if n.verify_status != VerificationStatus::Valid => (
            EdgeStatus::Failed,
            Some(format!(
                "supplied receipt does not verify: {}",
                n.verify_detail
            )),
        ),
        Some(n) if n.payload_kind != target_schema => (
            EdgeStatus::SchemaMismatch,
            Some(format!(
                "edge target_schema \"{target_schema}\" != supplied payload_kind \"{}\"",
                n.payload_kind
            )),
        ),
        Some(n) if !LAYERED_KINDS.contains(&n.payload_kind.as_str()) => (
            EdgeStatus::SchemaMismatch,
            Some(format!(
                "depended-on receipt payload_kind \"{}\" is not a layered-family kind",
                n.payload_kind
            )),
        ),
        Some(_) => (EdgeStatus::Resolved, None),
    }
}

/// Read the `event_hash` field from an envelope value.
fn read_event_hash(value: &serde_json::Value) -> Option<String> {
    value
        .get("event_hash")
        .and_then(serde_json::Value::as_str)
        .map(String::from)
}

/// Read the payload `payload_kind` from an envelope value.
fn read_payload_kind(value: &serde_json::Value) -> Option<String> {
    value
        .get("payload")
        .and_then(|p| p.get("payload_kind"))
        .and_then(serde_json::Value::as_str)
        .map(String::from)
}

/// Construct an invalid bundle result with a single error.
fn invalid(error: String) -> ClosureBundleVerificationResult {
    ClosureBundleVerificationResult {
        status: VerificationStatus::Invalid,
        schema_version: PROFILE_VERSION.to_string(),
        root_result: VerificationResult::invalid("bundle-level error".to_string()),
        root_event_hash: None,
        closure_size: 0,
        manifest_digest_ok: false,
        closure_complete: false,
        cycle_detected: false,
        edge_checks: Vec::new(),
        errors: vec![error],
    }
}

#[cfg(test)]
#[path = "closure_bundle_tests.rs"]
mod tests;
