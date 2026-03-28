//! Test helpers replacing `vr-kernel-testutils`.

/// Test macro — returns `Result`, no panics.
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

pub(crate) use vr_test;

/// Replacement for `need()` — unwraps an `Option` or returns an error.
pub(crate) fn need<T>(option: Option<T>, what: &'static str) -> anyhow::Result<T> {
    option.ok_or_else(|| anyhow::anyhow!(what))
}

/// Replacement for `ok_when()` — returns `Some(())` if condition is true, `None` otherwise.
pub(crate) const fn ok_when(condition: bool) -> Option<()> {
    if condition {
        Some(())
    } else {
        None
    }
}
