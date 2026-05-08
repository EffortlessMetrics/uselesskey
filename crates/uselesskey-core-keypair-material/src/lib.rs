//! Deprecated compatibility shim for PKCS#8/SPKI key-material helpers.
//!
//! Prefer `uselesskey-core`; key-material helpers are now owned by
//! `uselesskey_core::srp::keypair_material`.

#![forbid(unsafe_code)]

pub use uselesskey_core::srp::keypair_material::Pkcs8SpkiKeyMaterial;
