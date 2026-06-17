//! Decision pack verification — the support-set walk.
//!
//! Verifies a `vr-decision-pack/v1` artifact: a Decision Receipt envelope
//! (payload kind `decision.v0`, see
//! `vertrule_schemas::receipts::decision`) plus the depended-on receipts
//! its support set commits. Envelope-level verification proves the
//! decision's bytes; the walk proves every support-set member still
//! holds:
//!
//! - `depended_on_receipt` members **verify by replay** — the pack must
//!   supply a receipt whose recomputed `event_hash` equals the committed
//!   hash and which itself verifies. A missing or failing receipt puts
//!   the member OUT and the decision no longer holds — shown, never
//!   silently dropped.
//! - `evidence_digest` members are structural checks (well-formed
//!   committed digest); the evidence bytes are not transported in-pack.
//! - `cited_link` and `selector_value` members are committed assumptions
//!   (provenance-by-reference and consulted values respectively).
//!
//! ## Pack format
//!
//! ```json
//! {
//!   "_format": "vr-decision-pack/v1",
//!   "decision_canonical": "<JCS-canonical decision receipt envelope>",
//!   "depended_on": ["<JCS-canonical receipt envelope>", ...]
//! }
//! ```
//!
//! Canonical strings are fed directly to the receipt verifier without
//! re-serialization. Supplied receipts that no member references are
//! ignored (forward-compatible, mirroring bundle sidecar handling).

use serde::{Deserialize, Serialize};
use vertrule_schemas::receipts::DECISION_PAYLOAD_KIND;
use vertrule_schemas::{DecisionReceiptPayload, SupportMember};

use crate::error::VerifyError;
use crate::result::{VerificationResult, VerificationStatus};
use crate::schema_profile::PROFILE_VERSION;

/// Expected pack format identifier.
const EXPECTED_FORMAT: &str = "vr-decision-pack/v1";

// ── Types ──────────────────────────────────────────────────────────

/// Deserialized decision pack (input).
#[derive(Debug, Deserialize)]
struct DecisionPack {
    #[serde(rename = "_format")]
    format: String,
    decision_canonical: String,
    #[serde(default)]
    depended_on: Vec<String>,
}

/// Walk status of a single support-set member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemberStatus {
    /// Replay-verified: the depended-on receipt was supplied, verifies,
    /// and its `event_hash` equals the committed hash.
    Verified,
    /// A committed assumption (evidence digest, cited link, selector
    /// value) — structurally sound, not independently re-verified.
    Committed,
    /// The committed receipt was not supplied in the pack — the member
    /// is OUT.
    Missing,
    /// The supplied receipt failed verification or the committed value
    /// is malformed — the member is OUT.
    Failed,
}

/// Result of walking one support-set member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportMemberCheck {
    /// Member kind (`depended_on_receipt` / `evidence_digest` /
    /// `cited_link` / `selector_value`).
    pub member_kind: String,
    /// The member's committed reference (event hash, evidence id, claim
    /// id, or selector key).
    pub reference: String,
    /// Walk status.
    pub status: MemberStatus,
    /// Failure detail, when any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Structured result of verifying a decision pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionPackVerificationResult {
    /// Overall status — `VALID` only when the decision envelope verifies
    /// AND every support-set member is `verified` or `committed`.
    pub status: VerificationStatus,
    /// Schema profile version used for envelope verification.
    pub schema_version: String,
    /// Full verification result for the decision envelope.
    pub decision_result: VerificationResult,
    /// Verdict kind committed by the decision payload
    /// (`allow` / `deny` / `conditional` / `no_match`), when parseable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict_kind: Option<String>,
    /// Per-member walk results, in committed support-set order.
    pub member_checks: Vec<SupportMemberCheck>,
    /// Collected error messages (empty when valid).
    pub errors: Vec<String>,
}

impl DecisionPackVerificationResult {
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

/// Verify a decision pack from raw JSON bytes.
///
/// Performs fail-closed parsing, decision-envelope verification, payload
/// admission (`payload_kind` must be `decision.v0`), and the support-set
/// walk. The result status is `VALID` only when all checks pass.
#[must_use]
pub fn verify_decision_pack(raw_bytes: &[u8]) -> DecisionPackVerificationResult {
    let pack: DecisionPack = match serde_json::from_slice(raw_bytes) {
        Ok(p) => p,
        Err(e) => return invalid(format!("malformed pack JSON: {e}")),
    };

    if pack.format != EXPECTED_FORMAT {
        return invalid(format!(
            "unsupported pack format: expected \"{EXPECTED_FORMAT}\", got \"{}\"",
            pack.format
        ));
    }

    // 1. Verify the decision envelope.
    let decision_result = crate::verify_receipt(pack.decision_canonical.as_bytes());
    let mut errors = Vec::new();

    if decision_result.status != VerificationStatus::Valid {
        for e in &decision_result.errors {
            errors.push(format!("decision envelope: {e}"));
        }
    }

    // 2. Admit the decision payload.
    let payload = match extract_decision_payload(&pack.decision_canonical) {
        Ok(p) => p,
        Err(e) => {
            errors.push(e);
            return DecisionPackVerificationResult {
                status: VerificationStatus::Invalid,
                schema_version: PROFILE_VERSION.to_string(),
                decision_result,
                verdict_kind: None,
                member_checks: Vec::new(),
                errors,
            };
        }
    };
    let verdict_kind = Some(verdict_kind_label(&payload).to_string());

    // 3. Verify every supplied depended-on receipt once, keyed by its
    //    self-committed event hash. A supplied receipt that fails
    //    verification is recorded so the member walk reports `failed`
    //    rather than `missing`.
    let mut verified_hashes = Vec::new();
    let mut failed_hashes = Vec::new();
    for supplied in &pack.depended_on {
        let result = crate::verify_receipt(supplied.as_bytes());
        let hash = extract_event_hash(supplied);
        match (result.status, hash) {
            (VerificationStatus::Valid, Some(h)) => verified_hashes.push(h),
            (_, Some(h)) => {
                let detail = result.errors.join("; ");
                failed_hashes.push((h, detail));
            }
            (_, None) => errors
                .push("depended-on receipt has no readable event_hash and was ignored".to_string()),
        }
    }

    // 4. Walk the committed support set.
    let mut member_checks = Vec::new();
    for member in &payload.support_set {
        let check = walk_member(member, &verified_hashes, &failed_hashes);
        if matches!(check.status, MemberStatus::Missing | MemberStatus::Failed) {
            errors.push(format!(
                "support member {} \"{}\" is OUT ({:?})",
                check.member_kind, check.reference, check.status
            ));
        }
        member_checks.push(check);
    }

    let all_members_hold = member_checks
        .iter()
        .all(|c| matches!(c.status, MemberStatus::Verified | MemberStatus::Committed));
    let status = if decision_result.status == VerificationStatus::Valid
        && errors.is_empty()
        && all_members_hold
    {
        VerificationStatus::Valid
    } else {
        VerificationStatus::Invalid
    };

    DecisionPackVerificationResult {
        status,
        schema_version: PROFILE_VERSION.to_string(),
        decision_result,
        verdict_kind,
        member_checks,
        errors,
    }
}

// ── Helpers ────────────────────────────────────────────────────────

/// Extract and admit the decision payload from the canonical envelope.
fn extract_decision_payload(envelope_json: &str) -> Result<DecisionReceiptPayload, String> {
    let value: serde_json::Value =
        serde_json::from_str(envelope_json).map_err(|e| format!("malformed envelope: {e}"))?;
    let payload = value
        .get("payload")
        .cloned()
        .ok_or_else(|| "decision envelope has no payload".to_string())?;
    let kind = payload
        .get("payload_kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    if kind != DECISION_PAYLOAD_KIND {
        return Err(format!(
            "payload is not a decision payload: expected payload_kind \"{DECISION_PAYLOAD_KIND}\", got \"{kind}\""
        ));
    }
    serde_json::from_value(payload).map_err(|e| format!("malformed decision payload: {e}"))
}

/// Read the self-committed `event_hash` field from a canonical envelope.
fn extract_event_hash(envelope_json: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(envelope_json).ok()?;
    value
        .get("event_hash")
        .and_then(serde_json::Value::as_str)
        .map(String::from)
}

/// Verdict label matching the payload's serde `kind` tag.
const fn verdict_kind_label(payload: &DecisionReceiptPayload) -> &'static str {
    match payload.verdict {
        vertrule_schemas::DecisionVerdict::Allow => "allow",
        vertrule_schemas::DecisionVerdict::Deny { .. } => "deny",
        vertrule_schemas::DecisionVerdict::Conditional { .. } => "conditional",
        vertrule_schemas::DecisionVerdict::NoMatch => "no_match",
    }
}

/// Lowercase 64-char hex check for committed digests.
fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Walk one support-set member against the supplied receipts.
fn walk_member(
    member: &SupportMember,
    verified_hashes: &[String],
    failed_hashes: &[(String, String)],
) -> SupportMemberCheck {
    match member {
        SupportMember::DependedOnReceipt { event_hash } => {
            if verified_hashes.iter().any(|h| h == event_hash) {
                check(
                    "depended_on_receipt",
                    event_hash,
                    MemberStatus::Verified,
                    None,
                )
            } else if let Some((_, detail)) = failed_hashes.iter().find(|(h, _)| h == event_hash) {
                check(
                    "depended_on_receipt",
                    event_hash,
                    MemberStatus::Failed,
                    Some(format!("supplied receipt does not verify: {detail}")),
                )
            } else {
                check(
                    "depended_on_receipt",
                    event_hash,
                    MemberStatus::Missing,
                    Some("committed receipt not supplied in pack".to_string()),
                )
            }
        }
        SupportMember::EvidenceDigest { id, digest } => {
            if is_lower_hex_64(digest) {
                check("evidence_digest", id, MemberStatus::Committed, None)
            } else {
                check(
                    "evidence_digest",
                    id,
                    MemberStatus::Failed,
                    Some("committed digest is not 64 lowercase hex chars".to_string()),
                )
            }
        }
        SupportMember::CitedLink { id, url } => {
            if url.trim().is_empty() {
                check(
                    "cited_link",
                    id,
                    MemberStatus::Failed,
                    Some("committed link is empty".to_string()),
                )
            } else {
                check("cited_link", id, MemberStatus::Committed, None)
            }
        }
        SupportMember::SelectorValue { key, .. } => {
            check("selector_value", key, MemberStatus::Committed, None)
        }
        // Typed lineage edges (ADR-040) resolve by replay exactly like an
        // untyped depended-on receipt; the layered-family laws (target
        // schema match, untyped-edge rejection) are enforced by the
        // layered-pack verifier, not this one-level decision walk.
        SupportMember::TypedReceiptDependency { event_hash, .. } => {
            if verified_hashes.iter().any(|h| h == event_hash) {
                check(
                    "typed_receipt_dependency",
                    event_hash,
                    MemberStatus::Verified,
                    None,
                )
            } else if let Some((_, detail)) = failed_hashes.iter().find(|(h, _)| h == event_hash) {
                check(
                    "typed_receipt_dependency",
                    event_hash,
                    MemberStatus::Failed,
                    Some(format!("supplied receipt does not verify: {detail}")),
                )
            } else {
                check(
                    "typed_receipt_dependency",
                    event_hash,
                    MemberStatus::Missing,
                    Some("committed receipt not supplied in pack".to_string()),
                )
            }
        }
    }
}

fn check(
    member_kind: &str,
    reference: &str,
    status: MemberStatus,
    detail: Option<String>,
) -> SupportMemberCheck {
    SupportMemberCheck {
        member_kind: member_kind.to_string(),
        reference: reference.to_string(),
        status,
        detail,
    }
}

/// Construct an invalid pack result with a single error.
fn invalid(error: String) -> DecisionPackVerificationResult {
    DecisionPackVerificationResult {
        status: VerificationStatus::Invalid,
        schema_version: PROFILE_VERSION.to_string(),
        decision_result: VerificationResult::invalid("pack-level error".to_string()),
        verdict_kind: None,
        member_checks: Vec::new(),
        errors: vec![error],
    }
}

#[cfg(test)]
#[path = "decision_pack_tests.rs"]
mod tests;
