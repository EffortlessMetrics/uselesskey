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

        #[cfg(feature = "std")]
        {
            let io_err: Error = std::io::Error::other("io-fail").into();
            assert_eq!(io_err.to_string(), "io-fail");
        }
    }

    #[test]
    fn missing_env_var_message_includes_variable_name() {
        let err = Error::MissingEnvVar {
            var: "USELESSKEY_SEED".to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("USELESSKEY_SEED"),
            "message must include the variable name: {msg}"
        );
    }

    #[test]
    fn invalid_seed_message_includes_variable_and_reason() {
        let err = Error::InvalidSeed {
            var: "USELESSKEY_SEED".to_string(),
            message: "not valid hex".to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("USELESSKEY_SEED"),
            "message must include the variable name: {msg}"
        );
        assert!(
            msg.contains("not valid hex"),
            "message must include the reason: {msg}"
        );
    }

    #[test]
    fn io_error_transparent_delegates_display() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err: Error = io_err.into();
        assert_eq!(err.to_string(), "file missing");
    }

    #[test]
    fn variants_produce_distinguishable_messages() {
        let missing = Error::MissingEnvVar {
            var: "X".to_string(),
        };
        let invalid = Error::InvalidSeed {
            var: "X".to_string(),
            message: "bad".to_string(),
        };
        let io: Error = std::io::Error::other("fail").into();

        let msgs: [String; 3] = [missing.to_string(), invalid.to_string(), io.to_string()];
        // All three messages must be distinct.
        assert_ne!(msgs[0], msgs[1]);
        assert_ne!(msgs[0], msgs[2]);
        assert_ne!(msgs[1], msgs[2]);
    }

    #[test]
    fn missing_env_var_has_no_source() {
        use std::error::Error as StdError;

        let err = Error::MissingEnvVar {
            var: "X".to_string(),
        };
        assert!(err.source().is_none());
    }

    #[test]
    fn invalid_seed_has_no_source() {
        use std::error::Error as StdError;

        let err = Error::InvalidSeed {
            var: "X".to_string(),
            message: "bad".to_string(),
        };
        assert!(err.source().is_none());
    }

    #[test]
    fn debug_output_includes_variant_name() {
        let missing = Error::MissingEnvVar {
            var: "V".to_string(),
        };
        let dbg = format!("{missing:?}");
        assert!(
            dbg.contains("MissingEnvVar"),
            "Debug must include variant name: {dbg}"
        );

        let invalid = Error::InvalidSeed {
            var: "V".to_string(),
            message: "m".to_string(),
        };
        let dbg = format!("{invalid:?}");
        assert!(
            dbg.contains("InvalidSeed"),
            "Debug must include variant name: {dbg}"
        );
    }
}
