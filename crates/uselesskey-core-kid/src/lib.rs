#![forbid(unsafe_code)]

//! Deprecated compatibility shim for deterministic key-ID helpers.
//!
//! Prefer `uselesskey-jwk`; the canonical implementation now lives there.

pub use uselesskey_jwk::srp::kid::{
    DEFAULT_KID_PREFIX_BYTES, kid_from_bytes, kid_from_bytes_with_prefix,
};
