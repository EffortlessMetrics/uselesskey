use alloc::string::String;

use thiserror::Error;

/// Errors for `uselesskey-core`.
///
/// This crate is deliberately “test-first”: many operations are infallible by design.
/// We still surface IO and environment errors because those are common in test harnesses.
#[derive(Debug, Error)]
pub enum Error {
    #[error("environment variable `{var}` is not set")]
    MissingEnvVar { var: String },

    #[error("failed to parse seed from environment variable `{var}`: {message}")]
    InvalidSeed { var: String, message: String },

    #[cfg(feature = "std")]
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::Error;
    use std::error::Error as _;

    #[test]
    fn missing_env_var_message_is_readable() {
        let missing = Error::MissingEnvVar {
            var: "MY_VAR".to_string(),
        };
        assert_eq!(
            missing.to_string(),
            "environment variable `MY_VAR` is not set"
        );
        assert!(missing.source().is_none());
    }

    #[test]
    fn invalid_seed_message_is_readable() {
        let invalid = Error::InvalidSeed {
            var: "MY_VAR".to_string(),
            message: "bad seed".to_string(),
        };
        assert_eq!(
            invalid.to_string(),
            "failed to parse seed from environment variable `MY_VAR`: bad seed"
        );
        assert!(invalid.source().is_none());
    }

    #[test]
    fn io_error_variant_preserves_inner_error() {
        let inner = std::io::Error::other("io-fail");
        let io_err: Error = inner.into();

        assert_eq!(io_err.to_string(), "io-fail");
        assert!(io_err.source().is_none());
    }
}
