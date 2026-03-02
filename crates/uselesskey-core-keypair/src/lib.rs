#![forbid(unsafe_code)]

//! Compatibility facade for the historical `uselesskey-core-keypair` crate.
//!
//! The actual implementation lives in
//! [`uselesskey_core_keypair_material`]; this crate keeps the existing public path
//! stable for downstream users and internal integrations.
//!
//! # Examples
//!
//! Create key material and access encodings:
//!
//! ```
//! use uselesskey_core_keypair::Pkcs8SpkiKeyMaterial;
//!
//! let material = Pkcs8SpkiKeyMaterial::new(
//!     vec![0x30, 0x82],                        // PKCS#8 DER (placeholder)
//!     "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n",
//!     vec![0x30, 0x59],                        // SPKI DER (placeholder)
//!     "-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n",
//! );
//!
//! assert_eq!(material.private_key_pkcs8_der(), &[0x30, 0x82]);
//! assert!(material.public_key_spki_pem().contains("PUBLIC KEY"));
//! // kid is deterministic from the SPKI bytes
//! assert_eq!(material.kid(), material.kid());
//! ```

pub use uselesskey_core_keypair_material::Pkcs8SpkiKeyMaterial;
