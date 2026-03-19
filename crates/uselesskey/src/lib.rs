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
//! `uselesskey-jsonwebtoken`, `uselesskey-rustls`, `uselesskey-tonic`,
//! `uselesskey-ring`, `uselesskey-rustcrypto`, and `uselesskey-aws-lc-rs`.
//!
//! # Feature Selection
//!
//! The facade default feature set is empty. A bare `uselesskey` dependency gives
//! you core types like [`Factory`], [`Mode`], and [`Seed`]; enable only the
//! fixture families you need.
//!
//! Token-only consumers can keep the facade lightweight:
//!
//! ```toml
//! [dev-dependencies]
//! uselesskey = { version = "0.4.1", default-features = false, features = ["token"] }
//! ```
//!
//! ```
//! # #[cfg(feature = "token")]
//! # fn main() {
//! use uselesskey::{Factory, TokenFactoryExt, TokenSpec};
//!
//! let fx = Factory::deterministic_from_str("api-key-fixtures");
//! let token = fx.token("svc-api", TokenSpec::api_key());
//! assert!(token.value().starts_with("uk_test_"));
//! # }
//! # #[cfg(not(feature = "token"))]
//! # fn main() {}
//! ```
//!
//! # Quick Start
//!
//! If you enable `rsa`, create a factory and generate RSA key fixtures:
//!
//! ```
//! # #[cfg(feature = "rsa")]
//! # fn main() {
//! use uselesskey::{Factory, RsaFactoryExt, RsaSpec};
//!
//! // Random mode: each run produces different keys (still cached per-factory)
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
//! use uselesskey::{Factory, RsaFactoryExt, RsaSpec};
//!
//! // Create a deterministic factory from stable text
//! let fx = Factory::deterministic_from_str("test-seed");
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
//! Some libraries require file paths. Use `write_*` methods which return
//! [`TempArtifact`]:
//!
//! ```
//! # #[cfg(feature = "rsa")]
//! # fn main() {
//! use uselesskey::{Factory, RsaFactoryExt, RsaSpec, TempArtifact};
//!
//! let fx = Factory::random();
//! let keypair = fx.rsa("server", RsaSpec::rs256());
//!
//! // Write to a tempfile (auto-cleaned on drop)
//! let temp: TempArtifact = keypair.write_private_key_pkcs8_pem().unwrap();
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
//!
//! # X.509 Certificates
//!
//! With the `x509` feature, generate self-signed certificates and certificate chains:
//!
//! ```
//! # #[cfg(feature = "x509")]
//! # fn main() {
//! use uselesskey::{Factory, X509FactoryExt, X509Spec};
//!
//! let fx = Factory::random();
//! let cert = fx.x509_self_signed("my-service", X509Spec::self_signed("localhost"));
//!
//! assert!(cert.cert_pem().contains("BEGIN CERTIFICATE"));
//! assert!(!cert.cert_der().is_empty());
//! assert!(!cert.private_key_pkcs8_der().is_empty());
//! # }
//! # #[cfg(not(feature = "x509"))]
//! # fn main() {}
//! ```
//!
//! # X.509 Certificate Chains
//!
//! With the `x509` feature, generate a TLS-style certificate chain and negative
//! variants for error-path tests:
//!
//! ```
//! # #[cfg(feature = "x509")]
//! # fn main() {
//! use uselesskey::{ChainSpec, Factory, X509FactoryExt};
//!
//! let fx = Factory::random();
//! let chain = fx.x509_chain("svc", ChainSpec::new("test.example.com"));
//!
//! assert!(chain.chain_pem().contains("BEGIN CERTIFICATE"));
//! assert!(chain.root_cert_pem().contains("BEGIN CERTIFICATE"));
//! assert!(chain.leaf_private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
//!
//! let revoked = chain.revoked_leaf();
//! assert!(revoked.crl_pem().is_some());
//! # }
//! # #[cfg(not(feature = "x509"))]
//! # fn main() {}
//! ```
//!
//! # Features
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `rsa` | RSA key fixtures |
//! | `ecdsa` | ECDSA P-256/P-384 key fixtures |
//! | `ed25519` | Ed25519 key fixtures |
//! | `hmac` | HMAC secret fixtures |
//! | `token` | API key/bearer token fixtures |
//! | `pgp` | OpenPGP key fixtures |
//! | `x509` | X.509 certificate and chain fixtures |
//! | `jwk` | JWK/JWKS output for all key types |
//! | `all-keys` | All key types (rsa + ecdsa + ed25519 + hmac + pgp) |
//! | `full` | Everything: all-keys + token + x509 + jwk |
//!
//! The default feature set is empty; opt into the algorithms or fixture families
//! your tests actually need.

// ---------------------------------------------------------------------------
// Core re-exports
// ---------------------------------------------------------------------------

pub use uselesskey_core::sink::TempArtifact;
pub use uselesskey_core::{
    ArtifactDomain, ArtifactId, DerivationVersion, Error, Factory, Mode, Seed,
};

/// Generic negative-fixture helpers (corrupt PEM, truncate DER, etc.).
pub mod negative {
    pub use uselesskey_core::negative::*;
}

// ---------------------------------------------------------------------------
// JWK support
// ---------------------------------------------------------------------------

#[cfg(feature = "jwk")]
pub mod jwk {
    //! JWK/JWKS types and builder.
    pub use uselesskey_jwk::*;
}

// ---------------------------------------------------------------------------
// Key type re-exports (feature-gated)
// ---------------------------------------------------------------------------

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

#[cfg(feature = "pgp")]
pub use uselesskey_pgp::{DOMAIN_PGP_KEYPAIR, PgpFactoryExt, PgpKeyPair, PgpSpec};

#[cfg(feature = "x509")]
pub use uselesskey_x509::{
    ChainNegative, ChainSpec, DOMAIN_X509_CERT, DOMAIN_X509_CHAIN, KeyUsage, NotBeforeOffset,
    X509Cert, X509Chain, X509FactoryExt, X509Negative, X509Spec,
};

/// Common imports for tests.
///
/// Re-exports vary based on enabled features. For example, with
/// `features = ["rsa"]`:
/// ```
/// use uselesskey::prelude::*;
/// // Gives you: Factory, Mode, Seed, TempArtifact, RsaFactoryExt, RsaSpec, RsaKeyPair, negative::*
/// ```
pub mod prelude {
    pub use crate::negative::*;
    pub use crate::{Factory, Mode, Seed, TempArtifact};

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

    #[cfg(feature = "pgp")]
    pub use crate::{PgpFactoryExt, PgpKeyPair, PgpSpec};

    #[cfg(feature = "x509")]
    pub use crate::{
        ChainNegative, ChainSpec, X509Cert, X509Chain, X509FactoryExt, X509Negative, X509Spec,
    };
}
