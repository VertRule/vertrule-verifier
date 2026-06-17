//! Layered receipt-family pack verification (ADR-040).
//!
//! Verifies a `vr-layered-pack/v1` artifact: a layered-family root receipt
//! (payload kind `provider.v0` / `model.v0`, see
//! `vertrule_schemas::receipts::layered`) plus the receipts its **typed**
//! lineage edges depend on. This is the minimal composition-law slice —
//! one provider → one model — proving that:
//!
//! - a typed edge ([`SupportMember::TypedReceiptDependency`]) resolves to a
//!   supplied, verifying receipt whose `payload_kind` equals the edge's
//!   committed `target_schema`;
//! - an **untyped** edge ([`SupportMember::DependedOnReceipt`]) in a
//!   layered-family receipt is rejected — layered receipts carry only
//!   typed lineage;
//! - a missing depended-on node, or a `target_schema` mismatch, is a
//!   rejection.
//!
//! Role/target are part of the committed support set, so swapping a role
//! changes the root receipt's `event_hash` — proven by a sibling fixture,
//! not by this walk.
//!
//! ## Pack format
//!
//! ```json
//! {
//!   "_format": "vr-layered-pack/v1",
//!   "root_canonical": "<JCS-canonical layered root envelope>",
//!   "receipts": ["<JCS-canonical depended-on envelope>", ...]
//! }
//! ```
//!
//! Closure commitment (root `pack.v0` + bundle manifest) and transitive,
//! multi-level traversal are added by a later slice; this module walks the
//! root's direct typed edges only.

use serde::{Deserialize, Serialize};
use vertrule_schemas::receipts::{MODEL_PAYLOAD_KIND, PROVIDER_PAYLOAD_KIND};
use vertrule_schemas::SupportMember;

use crate::error::VerifyError;
use crate::result::{VerificationResult, VerificationStatus};
use crate::schema_profile::PROFILE_VERSION;

/// Expected pack format identifier.
const EXPECTED_FORMAT: &str = "vr-layered-pack/v1";

/// Layered-family payload kinds admitted as a pack root or dependency.
const LAYERED_KINDS: [&str; 2] = [PROVIDER_PAYLOAD_KIND, MODEL_PAYLOAD_KIND];

// ── Types ──────────────────────────────────────────────────────────

/// Deserialized layered pack (input).
#[derive(Debug, Deserialize)]
struct LayeredPack {
    #[serde(rename = "_format")]
    format: String,
    root_canonical: String,
    #[serde(default)]
    receipts: Vec<String>,
}

/// Walk status of one typed lineage edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EdgeStatus {
    /// The depended-on receipt was supplied, verifies, and its
    /// `payload_kind` matches the edge's committed `target_schema`.
    Resolved,
    /// The committed receipt was not supplied in the pack.
    Missing,
    /// The supplied receipt failed verification.
    Failed,
    /// The supplied receipt verifies but its `payload_kind` does not
    /// equal the edge's committed `target_schema`.
    SchemaMismatch,
    /// An untyped dependency edge appeared in a layered-family receipt.
    UntypedEdge,
}

/// Result of walking one root support-set member as a lineage edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeCheck {
    /// The committed target `event_hash` (or member reference).
    pub event_hash: String,
    /// The edge's committed role, when typed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// The edge's committed `target_schema`, when typed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_schema: Option<String>,
    /// Walk status.
    pub status: EdgeStatus,
    /// Failure detail, when any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Structured result of verifying a layered pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayeredPackVerificationResult {
    /// Overall status — `VALID` only when the root verifies, it is a
    /// layered-family receipt, and every lineage edge is `resolved`.
    pub status: VerificationStatus,
    /// Schema profile version used for envelope verification.
    pub schema_version: String,
    /// Full verification result for the root envelope.
    pub root_result: VerificationResult,
    /// The root's committed `payload_kind`, when parseable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_kind: Option<String>,
    /// Per-edge walk results, in committed support-set order.
    pub edge_checks: Vec<EdgeCheck>,
    /// Collected error messages (empty when valid).
    pub errors: Vec<String>,
}

impl LayeredPackVerificationResult {
    /// Serialize this result to JCS-canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns error if serialization or canonicalization fails.
    pub fn to_canon_bytes(&self) -> Result<Vec<u8>, VerifyError> {
        let value = serde_json::to_value(self).map_err(|e| VerifyError::Canon(format!("{e}")))?;
        crate::canon::typed_canon_bytes(&value)
    }

    /// Serialize this result to a JCS-canonical JSON string.
    ///
    /// # Errors
    ///
    /// Returns error if serialization or canonicalization fails.
    pub fn to_canon_string(&self) -> Result<String, VerifyError> {
        let value = serde_json::to_value(self).map_err(|e| VerifyError::Canon(format!("{e}")))?;
        crate::canon::typed_canon_string(&value)
    }
}

// ── Verification ───────────────────────────────────────────────────

/// A supplied receipt's verification outcome, keyed for edge resolution.
struct SuppliedReceipt {
    event_hash: String,
    payload_kind: String,
    status: VerificationStatus,
    detail: String,
}

/// Verify a layered pack from raw JSON bytes.
///
/// Fail-closed parsing, root-envelope verification, layered-family
/// payload admission, and the direct typed-edge walk. The result status is
/// `VALID` only when all checks pass.
#[must_use]
pub fn verify_layered_pack(raw_bytes: &[u8]) -> LayeredPackVerificationResult {
    let pack: LayeredPack = match serde_json::from_slice(raw_bytes) {
        Ok(p) => p,
        Err(e) => return invalid(format!("malformed pack JSON: {e}")),
    };

    if pack.format != EXPECTED_FORMAT {
        return invalid(format!(
            "unsupported pack format: expected \"{EXPECTED_FORMAT}\", got \"{}\"",
            pack.format
        ));
    }

    // 1. Verify the root envelope.
    let root_result = crate::verify_receipt(pack.root_canonical.as_bytes());
    let mut errors = Vec::new();
    if root_result.status != VerificationStatus::Valid {
        for e in &root_result.errors {
            errors.push(format!("root envelope: {e}"));
        }
    }

    // 2. Admit the root as a layered-family receipt.
    let (root_kind, support_set) = match extract_layered_payload(&pack.root_canonical) {
        Ok(parts) => parts,
        Err(e) => {
            errors.push(e);
            return LayeredPackVerificationResult {
                status: VerificationStatus::Invalid,
                schema_version: PROFILE_VERSION.to_string(),
                root_result,
                root_kind: None,
                edge_checks: Vec::new(),
                errors,
            };
        }
    };

    // 3. Verify and index every supplied receipt by its event_hash.
    let supplied: Vec<SuppliedReceipt> = pack
        .receipts
        .iter()
        .filter_map(|raw| index_supplied(raw))
        .collect();

    // 4. Walk the root's direct lineage edges.
    let mut edge_checks = Vec::new();
    for member in &support_set {
        if let Some(check) = walk_edge(member, &supplied) {
            if check.status != EdgeStatus::Resolved {
                errors.push(format!(
                    "lineage edge \"{}\" is OUT ({:?})",
                    check.event_hash, check.status
                ));
            }
            edge_checks.push(check);
        }
    }

    let all_edges_resolved = edge_checks.iter().all(|c| c.status == EdgeStatus::Resolved);
    let status = if root_result.status == VerificationStatus::Valid
        && errors.is_empty()
        && all_edges_resolved
    {
        VerificationStatus::Valid
    } else {
        VerificationStatus::Invalid
    };

    LayeredPackVerificationResult {
        status,
        schema_version: PROFILE_VERSION.to_string(),
        root_result,
        root_kind: Some(root_kind),
        edge_checks,
        errors,
    }
}

// ── Helpers ────────────────────────────────────────────────────────

/// Extract `(payload_kind, support_set)` from a layered root envelope,
/// rejecting any non-layered payload kind.
fn extract_layered_payload(
    envelope_json: &str,
) -> Result<(String, Vec<SupportMember>), String> {
    let value: serde_json::Value =
        serde_json::from_str(envelope_json).map_err(|e| format!("malformed envelope: {e}"))?;
    let payload = value
        .get("payload")
        .cloned()
        .ok_or_else(|| "layered root envelope has no payload".to_string())?;
    let kind = payload
        .get("payload_kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    if !LAYERED_KINDS.contains(&kind.as_str()) {
        return Err(format!(
            "root is not a layered-family receipt: payload_kind \"{kind}\" is not one of {LAYERED_KINDS:?}"
        ));
    }
    let support_set = payload
        .get("support_set")
        .cloned()
        .map_or_else(|| Ok(Vec::new()), serde_json::from_value)
        .map_err(|e| format!("malformed layered support_set: {e}"))?;
    Ok((kind, support_set))
}

/// Verify a supplied receipt and read its `event_hash` + `payload_kind`.
fn index_supplied(envelope_json: &str) -> Option<SuppliedReceipt> {
    let value: serde_json::Value = serde_json::from_str(envelope_json).ok()?;
    let event_hash = value.get("event_hash").and_then(serde_json::Value::as_str)?;
    let payload_kind = value
        .get("payload")
        .and_then(|p| p.get("payload_kind"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let result = crate::verify_receipt(envelope_json.as_bytes());
    Some(SuppliedReceipt {
        event_hash: event_hash.to_string(),
        payload_kind: payload_kind.to_string(),
        status: result.status,
        detail: result.errors.join("; "),
    })
}

/// Walk one root support-set member as a lineage edge.
///
/// Returns `None` for committed-assumption members (evidence/cited/
/// selector) — those are provider-level evidence, not lineage. Typed and
/// untyped dependency members produce an [`EdgeCheck`].
fn walk_edge(member: &SupportMember, supplied: &[SuppliedReceipt]) -> Option<EdgeCheck> {
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
            let found = supplied.iter().find(|s| &s.event_hash == event_hash);
            let (status, detail) = match found {
                None => (
                    EdgeStatus::Missing,
                    Some("committed receipt not supplied in pack".to_string()),
                ),
                Some(s) if s.status != VerificationStatus::Valid => (
                    EdgeStatus::Failed,
                    Some(format!("supplied receipt does not verify: {}", s.detail)),
                ),
                Some(s) if &s.payload_kind != target_schema => (
                    EdgeStatus::SchemaMismatch,
                    Some(format!(
                        "edge target_schema \"{target_schema}\" != supplied payload_kind \"{}\"",
                        s.payload_kind
                    )),
                ),
                Some(_) => (EdgeStatus::Resolved, None),
            };
            Some(EdgeCheck {
                event_hash: event_hash.clone(),
                role: role_label,
                target_schema: Some(target_schema.clone()),
                status,
                detail,
            })
        }
        SupportMember::DependedOnReceipt { event_hash } => Some(EdgeCheck {
            event_hash: event_hash.clone(),
            role: None,
            target_schema: None,
            status: EdgeStatus::UntypedEdge,
            detail: Some(
                "untyped depended_on_receipt edge in a layered-family receipt".to_string(),
            ),
        }),
        SupportMember::CitedLink { .. }
        | SupportMember::EvidenceDigest { .. }
        | SupportMember::SelectorValue { .. } => None,
    }
}

/// Construct an invalid pack result with a single error.
fn invalid(error: String) -> LayeredPackVerificationResult {
    LayeredPackVerificationResult {
        status: VerificationStatus::Invalid,
        schema_version: PROFILE_VERSION.to_string(),
        root_result: VerificationResult::invalid("pack-level error".to_string()),
        root_kind: None,
        edge_checks: Vec::new(),
        errors: vec![error],
    }
}

#[cfg(test)]
#[path = "layered_pack_tests.rs"]
mod tests;
