#![forbid(unsafe_code)]

//! Compatibility facade for the historical `uselesskey-core-keypair` crate.
//!
//! The actual implementation lives in
//! [`uselesskey_core_keypair_material`]; this crate keeps the existing public path
//! stable for downstream users and internal integrations.

pub use uselesskey_core_keypair_material::Pkcs8SpkiKeyMaterial;
