//! Test helpers replacing `vr-kernel-testutils`.

/// Replacement for `vr_test!` — wraps body in `anyhow::Result` block.
macro_rules! vr_test {
    ( $(#[$meta:meta])* fn $name:ident() $body:block ) => {
        $(#[$meta])*
        #[test]
        fn $name() {
            #[allow(clippy::redundant_closure_call)]
            let res: anyhow::Result<()> = (|| {
                $body
                Ok(())
            })();

            if let Err(e) = res {
                panic!("{e}");
            }
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
    if condition { Some(()) } else { None }
}
