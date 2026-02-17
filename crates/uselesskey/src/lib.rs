#![forbid(unsafe_code)]

//! `uselesskey` generates *runtime* key fixtures for tests.
//!
//! The point is operational, not cryptographic:
//! keep secrets-shaped blobs out of your git history while still testing against
//! "real-shaped" inputs (PKCS#8 PEM/DER, SPKI, etc.).
//!
//! > Not for production. Deterministic keys are predictable by design.
//!
//! For integration with third-party crypto crates, see the adapter crates:
//! `uselesskey-jsonwebtoken`, `uselesskey-rustls`, `uselesskey-ring`,
//! `uselesskey-rustcrypto`, and `uselesskey-aws-lc-rs`.
//!
//! # Quick Start
//!
//! Create a factory and generate RSA key fixtures:
//!
//! ```
//! # #[cfg(feature = "rsa")]
//! # fn main() {
//! use uselesskey::{Factory, RsaFactoryExt, RsaSpec};
//!
//! // Random mode: each run produces different keys (still cached per-process)
//! let fx = Factory::random();
//! let keypair = fx.rsa("my-service", RsaSpec::rs256());
//!
//! // Access keys in various formats
//! let pem = keypair.private_key_pkcs8_pem();
//! let der = keypair.private_key_pkcs8_der();
//! let pub_pem = keypair.public_key_spki_pem();
//!
//! assert!(pem.contains("-----BEGIN PRIVATE KEY-----"));
//! assert!(!der.is_empty());
//! # }
//! # #[cfg(not(feature = "rsa"))]
//! # fn main() {}
//! ```
//!
//! # Deterministic Mode
//!
//! For reproducible test fixtures, use deterministic mode with a seed:
//!
//! ```
//! # #[cfg(feature = "rsa")]
//! # fn main() {
//! use uselesskey::{Factory, RsaFactoryExt, RsaSpec, Seed};
//!
//! // Create a deterministic factory with a fixed seed
//! let seed = Seed::from_env_value("test-seed").unwrap();
//! let fx = Factory::deterministic(seed);
//!
//! // Same seed + same label + same spec = same key, regardless of call order
//! let key1 = fx.rsa("issuer", RsaSpec::rs256());
//! let key2 = fx.rsa("issuer", RsaSpec::rs256());
//!
//! assert_eq!(key1.private_key_pkcs8_pem(), key2.private_key_pkcs8_pem());
//! # }
//! # #[cfg(not(feature = "rsa"))]
//! # fn main() {}
//! ```
//!
//! # Environment-Based Seeds
//!
//! In CI, you often want to read the seed from an environment variable:
//!
//! ```
//! use uselesskey::Factory;
//!
//! // This reads from the environment variable and parses the seed
//! // Returns Err if the variable is not set
//! # unsafe { std::env::set_var("USELESSKEY_SEED", "ci-build-12345") };
//! let fx = Factory::deterministic_from_env("USELESSKEY_SEED").unwrap();
//! # unsafe { std::env::remove_var("USELESSKEY_SEED") };
//! ```
//!
//! # Negative Fixtures
//!
//! Test error handling with intentionally corrupted keys:
//!
//! ```
//! # #[cfg(feature = "rsa")]
//! # fn main() {
//! use uselesskey::{Factory, RsaFactoryExt, RsaSpec};
//! use uselesskey::negative::CorruptPem;
//!
//! let fx = Factory::random();
//! let keypair = fx.rsa("test", RsaSpec::rs256());
//!
//! // Get a PEM with a corrupted header
//! let bad_pem = keypair.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
//! assert!(bad_pem.contains("-----BEGIN CORRUPTED KEY-----"));
//!
//! // Get truncated DER bytes
//! let truncated = keypair.private_key_pkcs8_der_truncated(10);
//! assert_eq!(truncated.len(), 10);
//!
//! // Get a mismatched public key (valid but doesn't match the private key)
//! let mismatched = keypair.mismatched_public_key_spki_der();
//! assert!(!mismatched.is_empty());
//! # }
//! # #[cfg(not(feature = "rsa"))]
//! # fn main() {}
//! ```
//!
//! # Temporary Files
//!
//! Some libraries require file paths. Use `write_*` methods:
//!
//! ```
//! # #[cfg(feature = "rsa")]
//! # fn main() {
//! use uselesskey::{Factory, RsaFactoryExt, RsaSpec};
//!
//! let fx = Factory::random();
//! let keypair = fx.rsa("server", RsaSpec::rs256());
//!
//! // Write to a tempfile (auto-cleaned on drop)
//! let temp = keypair.write_private_key_pkcs8_pem().unwrap();
//! let path = temp.path();
//!
//! assert!(path.exists());
//! // Pass `path` to libraries that need file paths
//! # }
//! # #[cfg(not(feature = "rsa"))]
//! # fn main() {}
//! ```
//!
//! # JWK Support
//!
//! With the `jwk` feature, generate JSON Web Keys:
//!
//! ```
//! # #[cfg(all(feature = "jwk", feature = "rsa"))]
//! # fn main() {
//! use uselesskey::{Factory, RsaFactoryExt, RsaSpec};
//!
//! let fx = Factory::random();
//! let keypair = fx.rsa("auth", RsaSpec::rs256());
//!
//! // Get a stable key ID
//! let kid = keypair.kid();
//!
//! // Get the public JWK
//! let jwk = keypair.public_jwk();
//! let jwk_value = jwk.to_value();
//! assert_eq!(jwk_value["kty"], "RSA");
//! assert_eq!(jwk_value["alg"], "RS256");
//!
//! // Get a JWKS containing one key
//! let jwks = keypair.public_jwks();
//! let jwks_value = jwks.to_value();
//! assert!(jwks_value["keys"].is_array());
//! # }
//! # #[cfg(not(all(feature = "jwk", feature = "rsa")))]
//! # fn main() {}
//! ```

pub use uselesskey_core::{Error, Factory, Mode, Seed};

pub mod negative {
    pub use uselesskey_core::negative::*;
}

#[cfg(feature = "jwk")]
pub mod jwk {
    pub use uselesskey_jwk::*;
}

#[cfg(feature = "rsa")]
pub use uselesskey_rsa::{DOMAIN_RSA_KEYPAIR, RsaFactoryExt, RsaKeyPair, RsaSpec};

#[cfg(feature = "ecdsa")]
pub use uselesskey_ecdsa::{DOMAIN_ECDSA_KEYPAIR, EcdsaFactoryExt, EcdsaKeyPair, EcdsaSpec};

#[cfg(feature = "ed25519")]
pub use uselesskey_ed25519::{
    DOMAIN_ED25519_KEYPAIR, Ed25519FactoryExt, Ed25519KeyPair, Ed25519Spec,
};

#[cfg(feature = "hmac")]
pub use uselesskey_hmac::{DOMAIN_HMAC_SECRET, HmacFactoryExt, HmacSecret, HmacSpec};

#[cfg(feature = "token")]
pub use uselesskey_token::{DOMAIN_TOKEN_FIXTURE, TokenFactoryExt, TokenFixture, TokenSpec};

#[cfg(feature = "x509")]
pub use uselesskey_x509::{
    ChainNegative, ChainSpec, DOMAIN_X509_CERT, DOMAIN_X509_CHAIN, X509Cert, X509Chain,
    X509FactoryExt, X509Spec,
};

/// Common imports for tests.
///
/// Re-exports vary based on enabled features. With default features (rsa only):
/// ```
/// use uselesskey::prelude::*;
/// // Gives you: Factory, Mode, Seed, RsaFactoryExt, RsaSpec, RsaKeyPair, negative::*
/// ```
pub mod prelude {
    pub use crate::negative::*;
    pub use crate::{Factory, Mode, Seed};

    #[cfg(feature = "rsa")]
    pub use crate::{RsaFactoryExt, RsaKeyPair, RsaSpec};

    #[cfg(feature = "ecdsa")]
    pub use crate::{EcdsaFactoryExt, EcdsaKeyPair, EcdsaSpec};

    #[cfg(feature = "ed25519")]
    pub use crate::{Ed25519FactoryExt, Ed25519KeyPair, Ed25519Spec};

    #[cfg(feature = "hmac")]
    pub use crate::{HmacFactoryExt, HmacSecret, HmacSpec};

    #[cfg(feature = "token")]
    pub use crate::{TokenFactoryExt, TokenFixture, TokenSpec};

    #[cfg(feature = "x509")]
    pub use crate::{ChainSpec, X509Cert, X509Chain, X509FactoryExt, X509Spec};
}
