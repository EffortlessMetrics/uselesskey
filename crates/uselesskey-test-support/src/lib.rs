#![forbid(unsafe_code)]
//! Fallible test helpers for the `uselesskey` workspace.
//!
//! Tests that return `Result<()>` instead of panicking on assertion failure
//! are easier to migrate to fully-panic-free code paths and surface failures
//! through the same error-handling channels as production callers.
//!
//! See `docs/NO_PANIC_POLICY.md` for the broader policy context.

use std::error::Error as StdError;
use std::fmt;

/// Error returned by the helpers in this crate. The error message preserves
/// caller-supplied context so test runners produce a useful failure line.
#[derive(Debug)]
pub struct TestError(pub String);

impl fmt::Display for TestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl StdError for TestError {}

/// Convenience alias: `Result<T, TestError>`.
pub type TestResult<T> = Result<T, TestError>;

/// Fail a fallible test with a formatted message when `cond` is false.
///
/// Idiomatic usage:
///
/// ```
/// use uselesskey_test_support::{ensure, TestResult};
///
/// fn check(x: i32) -> TestResult<()> {
///     ensure!(x > 0, "expected positive, got {x}");
///     Ok(())
/// }
/// assert!(check(1).is_ok());
/// assert!(check(0).is_err());
/// ```
#[macro_export]
macro_rules! ensure {
    ($cond:expr $(,)?) => {
        if !$cond {
            return ::std::result::Result::Err(
                $crate::TestError(::std::format!(
                    "ensure!({}) failed at {}:{}",
                    ::std::stringify!($cond),
                    ::std::file!(),
                    ::std::line!()
                ))
            );
        }
    };
    ($cond:expr, $($arg:tt)+) => {
        if !$cond {
            return ::std::result::Result::Err(
                $crate::TestError(::std::format!($($arg)+))
            );
        }
    };
}

/// Fail a fallible test with a formatted message when `left != right`.
///
/// ```
/// use uselesskey_test_support::{ensure_eq, TestResult};
///
/// fn check() -> TestResult<()> {
///     ensure_eq!(2 + 2, 4);
///     Ok(())
/// }
/// assert!(check().is_ok());
/// ```
#[macro_export]
macro_rules! ensure_eq {
    ($left:expr, $right:expr $(,)?) => {{
        let left_val = $left;
        let right_val = $right;
        if left_val != right_val {
            return ::std::result::Result::Err($crate::TestError(::std::format!(
                "ensure_eq!({} == {}) failed at {}:{}: left={:?} right={:?}",
                ::std::stringify!($left),
                ::std::stringify!($right),
                ::std::file!(),
                ::std::line!(),
                left_val,
                right_val
            )));
        }
    }};
}

/// Convert `Option<T>` to `TestResult<T>`, attaching a contextual message
/// when the value is `None`.
///
/// ```
/// use uselesskey_test_support::{require_some, TestResult};
///
/// fn first_word(s: &str) -> TestResult<&str> {
///     require_some(s.split_whitespace().next(), "input had no words")
/// }
/// assert_eq!(first_word("hello world").unwrap(), "hello");
/// assert!(first_word("").is_err());
/// ```
pub fn require_some<T>(option: Option<T>, msg: impl fmt::Display) -> TestResult<T> {
    option.ok_or_else(|| TestError(msg.to_string()))
}

/// Convert `Result<T, E>` to `TestResult<T>`, prefixing the original error
/// with a contextual message.
///
/// ```
/// use uselesskey_test_support::{require_ok, TestResult};
///
/// fn parse(s: &str) -> TestResult<i32> {
///     require_ok(s.parse::<i32>(), "parsing user input")
/// }
/// assert_eq!(parse("42").unwrap(), 42);
/// assert!(parse("nope").is_err());
/// ```
pub fn require_ok<T, E: StdError>(result: Result<T, E>, msg: impl fmt::Display) -> TestResult<T> {
    result.map_err(|e| TestError(format!("{msg}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_path() -> TestResult<()> {
        ensure!(true);
        ensure_eq!(1 + 1, 2);
        let v: Option<i32> = Some(7);
        let _ = require_some(v, "should be some")?;
        let r: Result<i32, std::num::ParseIntError> = Ok(7);
        let _ = require_ok(r, "should parse")?;
        Ok(())
    }

    fn ensure_fails() -> TestResult<()> {
        ensure!(1 == 2, "1 != 2");
        Ok(())
    }

    fn ensure_eq_fails() -> TestResult<()> {
        ensure_eq!(1, 2);
        Ok(())
    }

    #[test]
    fn happy_path_returns_ok() {
        assert!(ok_path().is_ok());
    }

    #[test]
    fn ensure_macro_returns_err_with_message() {
        let err = ensure_fails().unwrap_err();
        assert_eq!(err.to_string(), "1 != 2");
    }

    #[test]
    fn ensure_eq_macro_includes_values() {
        let err = ensure_eq_fails().unwrap_err();
        assert!(err.to_string().contains("left=1"));
        assert!(err.to_string().contains("right=2"));
    }

    #[test]
    fn require_some_with_none_returns_err() {
        let r: TestResult<i32> = require_some(None, "missing");
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().to_string(), "missing");
    }

    #[test]
    fn require_ok_prefixes_message() {
        let r: Result<i32, std::num::ParseIntError> = "x".parse();
        let err = require_ok(r, "parsing").unwrap_err();
        assert!(err.to_string().starts_with("parsing: "));
    }
}
