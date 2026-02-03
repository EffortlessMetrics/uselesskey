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
