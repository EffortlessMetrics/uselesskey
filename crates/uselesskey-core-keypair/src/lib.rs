//! Deprecated compatibility shim for shared keypair helpers.
//!
//! Prefer `uselesskey-core`; keypair helpers are now owned by
//! `uselesskey_core::srp::keypair`.

#![forbid(unsafe_code)]

pub use uselesskey_core::srp::keypair::Pkcs8SpkiKeyMaterial;
