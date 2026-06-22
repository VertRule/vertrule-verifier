//! CLI entry point for the `vr-verify` binary.
//!
//! Usage:
//! ```text
//! vr-verify receipt <file.json>
//! vr-verify chain   <chain.json>
//! vr-verify signed  <file.json> <sig.json>
//! ```
//!
//! Exit codes:
//! - 0: VALID
//! - 1: INVALID or UNSIGNED
//! - 2: Usage error

use std::process::ExitCode;

use vertrule_verifier::result::VerificationStatus;

const USAGE: &str = "\
Usage:
  vr-verify receipt <file.json>
  vr-verify chain   <chain.json>
  vr-verify signed  <file.json> <sig.json>
  vr-verify bundle  <bundle.json>
  vr-verify layered <pack.json>
  vr-verify decision <pack.json>
  vr-verify closure <bundle.json>

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
        "receipt" => {
            if args.len() != 3 {
                eprintln!("Error: 'receipt' expects exactly one argument");
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
            run_receipt(&args[2])
        }
        "chain" => {
            if args.len() != 3 {
                eprintln!("Error: 'chain' expects exactly one argument");
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
            run_chain(&args[2])
        }
        "signed" => {
            if args.len() != 4 {
                eprintln!("Error: 'signed' expects exactly two arguments");
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
            run_signed(&args[2], &args[3])
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
        _ => {
            eprintln!("Error: unknown command \"{command}\"");
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run_receipt(path: &str) -> ExitCode {
    let raw_bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading {path}: {e}");
            return ExitCode::from(2);
        }
    };

    let result = vertrule_verifier::verify_receipt(&raw_bytes);
    emit_result(&result)
}

fn run_chain(path: &str) -> ExitCode {
    let raw_bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading {path}: {e}");
            return ExitCode::from(2);
        }
    };

    let result = vertrule_verifier::verify_receipt_chain(&raw_bytes);
    emit_result(&result)
}

fn run_signed(receipt_path: &str, sig_path: &str) -> ExitCode {
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

    let result = vertrule_verifier::verify_signed_receipt(&raw_bytes, &sig_bytes);
    emit_result(&result)
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
