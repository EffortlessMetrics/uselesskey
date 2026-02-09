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

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn error_messages_are_readable() {
        let missing = Error::MissingEnvVar {
            var: "MY_VAR".to_string(),
        };
        assert_eq!(
            missing.to_string(),
            "environment variable `MY_VAR` is not set"
        );

        let invalid = Error::InvalidSeed {
            var: "MY_VAR".to_string(),
            message: "bad seed".to_string(),
        };
        assert_eq!(
            invalid.to_string(),
            "failed to parse seed from environment variable `MY_VAR`: bad seed"
        );

        let io_err: Error = std::io::Error::new(std::io::ErrorKind::Other, "io-fail").into();
        assert_eq!(io_err.to_string(), "io-fail");
    }
}
