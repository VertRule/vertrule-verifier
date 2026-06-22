//! CLI entry point for the `vr-verify` binary.
//!
//! Usage:
//! ```text
//! vr-verify receipt  <file.json> [--max-bytes <N>]
//! vr-verify chain    <chain.json> [--max-bytes <N>] [--max-chain-length <N>]
//! vr-verify signed   <file.json> <sig.json> [--trust <trust.json>]
//! vr-verify external <receipt.json>
//! ```
//!
//! Exit codes:
//! - 0: VALID
//! - 1: INVALID or UNSIGNED
//! - 2: Usage error

use std::process::ExitCode;

use vertrule_verifier::result::VerificationStatus;
use vertrule_verifier::VerifierLimits;

/// CLI-only representation of the optional limit flags.
///
/// This is command-line syntax, not verifier-domain behavior: it records which
/// limits the operator supplied and resolves omitted fields from
/// [`VerifierLimits::default`]. An empty `LimitArgs` ([`LimitArgs::is_present`]
/// is `false`) means "no flags given" and the caller stays on the existing
/// default verification path.
#[derive(Debug, Clone, Copy, Default)]
struct LimitArgs {
    max_bytes: Option<usize>,
    max_chain_length: Option<usize>,
}

impl LimitArgs {
    /// Whether any limit flag was supplied (selects the hardened verifier).
    const fn is_present(self) -> bool {
        self.max_bytes.is_some() || self.max_chain_length.is_some()
    }

    /// Resolve to concrete limits, taking unspecified fields from the default.
    fn resolve(self) -> VerifierLimits {
        let mut limits = VerifierLimits::default();
        if let Some(max_bytes) = self.max_bytes {
            limits.max_bytes = max_bytes;
        }
        if let Some(max_chain_length) = self.max_chain_length {
            limits.max_chain_length = max_chain_length;
        }
        limits
    }
}

/// Parse a non-zero `usize` flag value, rejecting `0` (zero never means
/// "unlimited"; an explicit representation would be required for that).
fn parse_limit_value(flag: &str, raw: &str) -> Result<usize, String> {
    let value: usize = raw
        .parse()
        .map_err(|_| format!("{flag} expects a non-negative integer, got \"{raw}\""))?;
    if value == 0 {
        return Err(format!("{flag} must be greater than 0"));
    }
    Ok(value)
}

/// Parse trailing limit flags from `flags`.
///
/// `--max-chain-length` is only accepted when `allow_chain_length` is set
/// (it is meaningless for single-receipt verification).
fn parse_limit_args(flags: &[String], allow_chain_length: bool) -> Result<LimitArgs, String> {
    let mut parsed = LimitArgs::default();
    let mut iter = flags.iter();
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--max-bytes" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| "--max-bytes requires a value".to_string())?;
                parsed.max_bytes = Some(parse_limit_value("--max-bytes", raw)?);
            }
            "--max-chain-length" if allow_chain_length => {
                let raw = iter
                    .next()
                    .ok_or_else(|| "--max-chain-length requires a value".to_string())?;
                parsed.max_chain_length = Some(parse_limit_value("--max-chain-length", raw)?);
            }
            other => return Err(format!("unexpected argument \"{other}\"")),
        }
    }
    Ok(parsed)
}

/// Parse the optional `--trust <path>` flag for the `signed` subcommand.
fn parse_trust_arg(flags: &[String]) -> Result<Option<String>, String> {
    let mut trust = None;
    let mut iter = flags.iter();
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--trust" => {
                let path = iter
                    .next()
                    .ok_or_else(|| "--trust requires a path".to_string())?;
                trust = Some(path.clone());
            }
            other => return Err(format!("unexpected argument \"{other}\"")),
        }
    }
    Ok(trust)
}

const USAGE: &str = "\
Usage:
  vr-verify receipt <file.json> [--max-bytes <N>]
  vr-verify chain   <chain.json> [--max-bytes <N>] [--max-chain-length <N>]
  vr-verify signed  <file.json> <sig.json> [--trust <trust.json>]
  vr-verify bundle  <bundle.json>
  vr-verify layered <pack.json>
  vr-verify decision <pack.json>
  vr-verify closure <bundle.json>
  vr-verify external <receipt.json>

Options:
  --max-bytes <N>         Reject input larger than N bytes (must be > 0).
  --max-chain-length <N>  Reject chains with more than N envelopes (must be > 0).
  --trust <trust.json>    Evaluate the signing key against an authority set and
                          trust policy: {\"authority_set\": ..., \"trust_policy\": ...}.

Omitting the limit/trust flags preserves the default verification behavior.

Exit codes:
  0  VALID
  1  INVALID / UNSIGNED
  2  Usage error";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }

    let command = args[1].as_str();

    match command {
        "receipt" => match parse_limit_args(&args[3..], false) {
            Ok(limits) => run_receipt(&args[2], limits),
            Err(e) => {
                eprintln!("Error: {e}");
                eprintln!("{USAGE}");
                ExitCode::from(2)
            }
        },
        "chain" => match parse_limit_args(&args[3..], true) {
            Ok(limits) => run_chain(&args[2], limits),
            Err(e) => {
                eprintln!("Error: {e}");
                eprintln!("{USAGE}");
                ExitCode::from(2)
            }
        },
        "signed" => {
            if args.len() < 4 {
                eprintln!("Error: 'signed' expects at least two arguments");
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
            match parse_trust_arg(&args[4..]) {
                Ok(trust) => run_signed(&args[2], &args[3], trust.as_deref()),
                Err(e) => {
                    eprintln!("Error: {e}");
                    eprintln!("{USAGE}");
                    ExitCode::from(2)
                }
            }
        }
        "bundle" => {
            if args.len() != 3 {
                eprintln!("Error: 'bundle' expects exactly one argument");
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
            run_bundle(&args[2])
        }
        "layered" => {
            if args.len() != 3 {
                eprintln!("Error: 'layered' expects exactly one argument");
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
            run_layered(&args[2])
        }
        "decision" => {
            if args.len() != 3 {
                eprintln!("Error: 'decision' expects exactly one argument");
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
            run_decision(&args[2])
        }
        "closure" => {
            if args.len() != 3 {
                eprintln!("Error: 'closure' expects exactly one argument");
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
            run_closure(&args[2])
        }
        "external" => {
            if args.len() != 3 {
                eprintln!("Error: 'external' expects exactly one argument");
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
            run_external(&args[2])
        }
        _ => {
            eprintln!("Error: unknown command \"{command}\"");
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run_receipt(path: &str, limits: LimitArgs) -> ExitCode {
    let raw_bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading {path}: {e}");
            return ExitCode::from(2);
        }
    };

    let result = if limits.is_present() {
        vertrule_verifier::verify_receipt_with_limits(&raw_bytes, &limits.resolve())
    } else {
        vertrule_verifier::verify_receipt(&raw_bytes)
    };
    emit_result(&result)
}

fn run_chain(path: &str, limits: LimitArgs) -> ExitCode {
    let raw_bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading {path}: {e}");
            return ExitCode::from(2);
        }
    };

    let result = if limits.is_present() {
        vertrule_verifier::verify_receipt_chain_with_limits(&raw_bytes, &limits.resolve())
    } else {
        vertrule_verifier::verify_receipt_chain(&raw_bytes)
    };
    emit_result(&result)
}

fn run_signed(receipt_path: &str, sig_path: &str, trust_path: Option<&str>) -> ExitCode {
    let raw_bytes = match std::fs::read(receipt_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading {receipt_path}: {e}");
            return ExitCode::from(2);
        }
    };

    let sig_bytes = match std::fs::read(sig_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading {sig_path}: {e}");
            return ExitCode::from(2);
        }
    };

    let result = match trust_path {
        Some(path) => {
            let (authority_set, trust_policy) = match load_trust_config(path) {
                Ok(cfg) => cfg,
                Err(e) => {
                    eprintln!("Error loading trust config {path}: {e}");
                    return ExitCode::from(2);
                }
            };
            vertrule_verifier::verify_signed_receipt_with_trust(
                &raw_bytes,
                &sig_bytes,
                &authority_set,
                &trust_policy,
            )
        }
        None => vertrule_verifier::verify_signed_receipt(&raw_bytes, &sig_bytes),
    };
    emit_result(&result)
}

/// Load a trust config file shaped `{ "authority_set": ..., "trust_policy": ... }`.
///
/// Both members deserialize from the public `vertrule_verifier::trust` serde
/// types; either may be omitted to fall back to its default.
fn load_trust_config(
    path: &str,
) -> Result<
    (
        vertrule_verifier::AuthoritySet,
        vertrule_verifier::TrustPolicy,
    ),
    String,
> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let authority_set = match value.get("authority_set") {
        Some(v) => serde_json::from_value(v.clone()).map_err(|e| e.to_string())?,
        None => return Err("missing \"authority_set\"".to_string()),
    };
    let trust_policy = match value.get("trust_policy") {
        Some(v) => serde_json::from_value(v.clone()).map_err(|e| e.to_string())?,
        None => vertrule_verifier::TrustPolicy::default(),
    };
    Ok((authority_set, trust_policy))
}

fn run_bundle(path: &str) -> ExitCode {
    let raw_bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading {path}: {e}");
            return ExitCode::from(2);
        }
    };

    let result = vertrule_verifier::verify_bundle(&raw_bytes);

    match result.to_canon_bytes() {
        Ok(canon_bytes) => {
            if let Err(e) = std::io::Write::write_all(&mut std::io::stdout(), &canon_bytes) {
                eprintln!("Error writing result: {e}");
                return ExitCode::from(2);
            }
            let _ = std::io::Write::write_all(&mut std::io::stdout(), b"\n");
        }
        Err(e) => {
            eprintln!("Error canonicalizing result: {e}");
            return ExitCode::from(2);
        }
    }

    match result.status {
        VerificationStatus::Valid => ExitCode::SUCCESS,
        VerificationStatus::Invalid => ExitCode::from(1),
    }
}

fn run_layered(path: &str) -> ExitCode {
    let raw_bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading {path}: {e}");
            return ExitCode::from(2);
        }
    };

    let result = vertrule_verifier::verify_layered_pack(&raw_bytes);

    match result.to_canon_bytes() {
        Ok(canon_bytes) => {
            if let Err(e) = std::io::Write::write_all(&mut std::io::stdout(), &canon_bytes) {
                eprintln!("Error writing result: {e}");
                return ExitCode::from(2);
            }
            let _ = std::io::Write::write_all(&mut std::io::stdout(), b"\n");
        }
        Err(e) => {
            eprintln!("Error canonicalizing result: {e}");
            return ExitCode::from(2);
        }
    }

    match result.status {
        VerificationStatus::Valid => ExitCode::SUCCESS,
        VerificationStatus::Invalid => ExitCode::from(1),
    }
}

fn run_decision(path: &str) -> ExitCode {
    let raw_bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading {path}: {e}");
            return ExitCode::from(2);
        }
    };

    let result = vertrule_verifier::verify_decision_pack(&raw_bytes);

    match result.to_canon_bytes() {
        Ok(canon_bytes) => {
            if let Err(e) = std::io::Write::write_all(&mut std::io::stdout(), &canon_bytes) {
                eprintln!("Error writing result: {e}");
                return ExitCode::from(2);
            }
            let _ = std::io::Write::write_all(&mut std::io::stdout(), b"\n");
        }
        Err(e) => {
            eprintln!("Error canonicalizing result: {e}");
            return ExitCode::from(2);
        }
    }

    match result.status {
        VerificationStatus::Valid => ExitCode::SUCCESS,
        VerificationStatus::Invalid => ExitCode::from(1),
    }
}

fn run_closure(path: &str) -> ExitCode {
    let raw_bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading {path}: {e}");
            return ExitCode::from(2);
        }
    };

    let result = vertrule_verifier::verify_closure_bundle(&raw_bytes);

    match result.to_canon_bytes() {
        Ok(canon_bytes) => {
            if let Err(e) = std::io::Write::write_all(&mut std::io::stdout(), &canon_bytes) {
                eprintln!("Error writing result: {e}");
                return ExitCode::from(2);
            }
            let _ = std::io::Write::write_all(&mut std::io::stdout(), b"\n");
        }
        Err(e) => {
            eprintln!("Error canonicalizing result: {e}");
            return ExitCode::from(2);
        }
    }

    match result.status {
        VerificationStatus::Valid => ExitCode::SUCCESS,
        VerificationStatus::Invalid => ExitCode::from(1),
    }
}

fn run_external(path: &str) -> ExitCode {
    let raw_bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading {path}: {e}");
            return ExitCode::from(2);
        }
    };

    match vertrule_verifier::verify_external_receipt(&raw_bytes) {
        Ok(meta) => {
            let json = match serde_json::to_vec(&meta) {
                Ok(j) => j,
                Err(e) => {
                    eprintln!("Error serializing metadata: {e}");
                    return ExitCode::from(2);
                }
            };
            let canon = match vr_jcs::to_canon_bytes_from_slice(&json) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error canonicalizing metadata: {e}");
                    return ExitCode::from(2);
                }
            };
            if let Err(e) = std::io::Write::write_all(&mut std::io::stdout(), &canon) {
                eprintln!("Error writing result: {e}");
                return ExitCode::from(2);
            }
            let _ = std::io::Write::write_all(&mut std::io::stdout(), b"\n");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

fn emit_result(result: &vertrule_verifier::result::VerificationResult) -> ExitCode {
    // Stdout: JCS-canonical result JSON
    match result.to_canon_bytes() {
        Ok(canon_bytes) => {
            if let Err(e) = std::io::Write::write_all(&mut std::io::stdout(), &canon_bytes) {
                eprintln!("Error writing result: {e}");
                return ExitCode::from(2);
            }
            let _ = std::io::Write::write_all(&mut std::io::stdout(), b"\n");
        }
        Err(e) => {
            eprintln!("Error canonicalizing result: {e}");
            return ExitCode::from(2);
        }
    }

    // Stderr: result digest
    match result.digest() {
        Ok(d) => eprintln!("{d}"),
        Err(e) => eprintln!("digest error: {e}"),
    }

    match result.status {
        VerificationStatus::Valid => ExitCode::SUCCESS,
        VerificationStatus::Invalid => ExitCode::from(1),
    }
}
