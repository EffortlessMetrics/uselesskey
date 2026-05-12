#![forbid(unsafe_code)]

//! Deprecated compatibility shim.
//!
//! Prefer `uselesskey-pgp` with the `native` feature for the supported
//! `PgpNativeExt` surface.

pub use uselesskey_pgp::native::*;
