use super::*;
use serde_json::json;

fn tiny_limits() -> VerifierLimits {
    VerifierLimits {
        max_bytes: 100,
        max_depth: 3,
        max_node_count: 10,
        max_object_size: 3,
        max_array_size: 3,
        max_chain_length: 2,
    }
}

// ── Byte limits ────────────────────────────────────────────────────

#[test]
fn byte_limit_passes_under() {
    let data = b"short";
    assert!(check_byte_limit(data, &tiny_limits()).is_ok());
}

#[test]
fn byte_limit_fails_over() {
    let data = vec![b'x'; 101];
    let result = check_byte_limit(&data, &tiny_limits());
    assert_eq!(
        result,
        Err(LimitViolation::InputTooLarge {
            actual: 101,
            limit: 100,
        })
    );
}

// ── Depth limits ───────────────────────────────────────────────────

#[test]
fn depth_passes_at_limit() {
    let v = json!({"a": {"b": 1}}); // depth 2
    assert!(check_structure(&v, &tiny_limits()).is_ok());
}

#[test]
fn depth_fails_over() {
    let v = json!({"a": {"b": {"c": {"d": 1}}}}); // depth 4
    let result = check_structure(&v, &tiny_limits());
    assert!(matches!(result, Err(LimitViolation::DepthExceeded { .. })));
}

// ── Node count ─────────────────────────────────────────────────────

#[test]
fn node_count_passes_under() {
    let v = json!({"a": 1, "b": 2}); // 3 nodes
    assert!(check_structure(&v, &tiny_limits()).is_ok());
}

#[test]
fn node_count_fails_over() {
    let limits = VerifierLimits {
        max_node_count: 3,
        ..tiny_limits()
    };
    let v = json!({"a": 1, "b": 2, "c": 3}); // 4 nodes (1 obj + 3 values)
    let result = check_structure(&v, &limits);
    assert!(matches!(
        result,
        Err(LimitViolation::NodeCountExceeded { .. })
    ));
}

// ── Object size ────────────────────────────────────────────────────

#[test]
fn object_size_passes_at_limit() {
    let v = json!({"a": 1, "b": 2, "c": 3}); // 3 keys
    assert!(check_structure(&v, &tiny_limits()).is_ok());
}

#[test]
fn object_size_fails_over() {
    let v = json!({"a": 1, "b": 2, "c": 3, "d": 4}); // 4 keys > 3
    let result = check_structure(&v, &tiny_limits());
    assert!(matches!(result, Err(LimitViolation::ObjectTooLarge { .. })));
}

// ── Array size ─────────────────────────────────────────────────────

#[test]
fn array_size_passes_at_limit() {
    let v = json!([1, 2, 3]); // 3 elements
    assert!(check_structure(&v, &tiny_limits()).is_ok());
}

#[test]
fn array_size_fails_over() {
    let v = json!([1, 2, 3, 4]); // 4 elements > 3
    let result = check_structure(&v, &tiny_limits());
    assert!(matches!(result, Err(LimitViolation::ArrayTooLarge { .. })));
}

// ── Chain length ───────────────────────────────────────────────────

#[test]
fn chain_length_passes_at_limit() {
    assert!(check_chain_length(2, &tiny_limits()).is_ok());
}

#[test]
fn chain_length_fails_over() {
    let result = check_chain_length(3, &tiny_limits());
    assert_eq!(
        result,
        Err(LimitViolation::ChainTooLong {
            actual: 3,
            limit: 2,
        })
    );
}

// ── Default limits are generous ────────────────────────────────────

#[test]
fn default_limits_accept_typical_envelope() {
    let v = json!({
        "envelope_version": 2,
        "receipt_type": "governance",
        "context_digest": "a".repeat(64),
        "schema_digest": "b".repeat(64),
        "policy_digest": "c".repeat(64),
        "logical_time": 1,
        "event_hash": "d".repeat(64),
        "payload": {"action": "test", "nested": {"deep": true}}
    });
    assert!(check_structure(&v, &VerifierLimits::default()).is_ok());
}

// ── Display ────────────────────────────────────────────────────────

#[test]
fn display_messages_are_stable() {
    let cases = [
        (
            LimitViolation::InputTooLarge {
                actual: 200,
                limit: 100,
            },
            "input too large",
        ),
        (
            LimitViolation::DepthExceeded {
                actual: 10,
                limit: 5,
            },
            "depth exceeded",
        ),
        (
            LimitViolation::NodeCountExceeded {
                actual: 100,
                limit: 50,
            },
            "node count exceeded",
        ),
        (
            LimitViolation::ObjectTooLarge {
                actual: 10,
                limit: 5,
            },
            "object too large",
        ),
        (
            LimitViolation::ArrayTooLarge {
                actual: 10,
                limit: 5,
            },
            "array too large",
        ),
        (
            LimitViolation::ChainTooLong {
                actual: 10,
                limit: 5,
            },
            "chain too long",
        ),
    ];
    for (violation, expected_prefix) in cases {
        let msg = violation.to_string();
        assert!(
            msg.starts_with(expected_prefix),
            "expected \"{expected_prefix}...\", got \"{msg}\""
        );
    }
}
