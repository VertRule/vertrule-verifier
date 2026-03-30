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

fn emit_result(result: &vertrule_verifier::result::VerificationResult) -> ExitCode {
    // Stdout: JCS-canonical result JSON
    match serde_json::to_value(result) {
        Ok(value) => match vr_jcs::to_canon_bytes(&value) {
            Ok(canon_bytes) => {
                // Write canonical bytes directly to stdout
                if let Err(e) = std::io::Write::write_all(&mut std::io::stdout(), &canon_bytes) {
                    eprintln!("Error writing result: {e}");
                    return ExitCode::from(2);
                }
                // Trailing newline for terminal friendliness
                let _ = std::io::Write::write_all(&mut std::io::stdout(), b"\n");
            }
            Err(e) => {
                eprintln!("Error canonicalizing result: {e}");
                return ExitCode::from(2);
            }
        },
        Err(e) => {
            eprintln!("Error serializing result: {e}");
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
