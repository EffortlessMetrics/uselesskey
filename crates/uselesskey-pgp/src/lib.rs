#![forbid(unsafe_code)]

//! OpenPGP fixtures built on `uselesskey-core`.
//!
//! The main entry point is [`PgpFactoryExt`], which adds `.pgp()` to
//! [`Factory`](uselesskey_core::Factory).
//!
//! # Quick start
//!
//! ```
//! use uselesskey_core::Factory;
//! use uselesskey_pgp::{PgpFactoryExt, PgpSpec};
//!
//! let fx = Factory::random();
//! let key = fx.pgp("deploy", PgpSpec::ed25519());
//!
//! assert!(key.private_key_armored().contains("BEGIN PGP PRIVATE KEY BLOCK"));
//! assert!(key.public_key_armored().contains("BEGIN PGP PUBLIC KEY BLOCK"));
//! assert!(!key.fingerprint().is_empty());
//! ```
//!
//! # Available specs
//!
//! | Constructor | Algorithm |
//! |---|---|
//! | [`PgpSpec::rsa_2048()`] | RSA 2048-bit |
//! | [`PgpSpec::rsa_3072()`] | RSA 3072-bit |
//! | [`PgpSpec::ed25519()`] | Ed25519 |
//!
//! # Negative fixtures
//!
//! ```
//! use uselesskey_core::Factory;
//! use uselesskey_core::negative::CorruptPem;
//! use uselesskey_pgp::{PgpFactoryExt, PgpSpec};
//!
//! let fx = Factory::random();
//! let key = fx.pgp("deploy", PgpSpec::ed25519());
//!
//! // Corrupt armored output
//! let bad = key.private_key_armored_corrupt(CorruptPem::BadBase64);
//! assert_ne!(bad, key.private_key_armored());
//!
//! // Mismatched public key (valid but wrong)
//! let wrong_pub = key.mismatched_public_key_armored();
//! assert_ne!(wrong_pub, key.public_key_armored());
//! ```

mod keypair;
mod spec;

pub use keypair::{DOMAIN_PGP_KEYPAIR, PgpFactoryExt, PgpKeyPair};
pub use spec::PgpSpec;
