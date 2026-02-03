#![forbid(unsafe_code)]

//! `uselesskey` generates *runtime* key fixtures for tests.
//!
//! The point is operational, not cryptographic:
//! keep secrets-shaped blobs out of your git history while still testing against
//! “real-shaped” inputs (PKCS#8 PEM/DER, SPKI, etc.).
//!
//! > Not for production. Deterministic keys are predictable by design.

pub use uselesskey_core::{Error, Factory, Mode, Seed};

pub mod negative {
    pub use uselesskey_core::negative::*;
}

pub use uselesskey_rsa::{RsaFactoryExt, RsaKeyPair, RsaSpec, DOMAIN_RSA_KEYPAIR};

/// Common imports for tests.
pub mod prelude {
    pub use crate::negative::*;
    pub use crate::{Factory, Mode, RsaFactoryExt, RsaKeyPair, RsaSpec, Seed};
}
