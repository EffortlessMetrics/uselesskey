#![forbid(unsafe_code)]

//! Symmetric-key and AEAD fixtures built on `uselesskey-core`.

mod fixture;
mod vector;

pub use fixture::{DOMAIN_SYMMETRIC_FIXTURE, SymmetricFactoryExt, SymmetricFixture};
pub use uselesskey_core_symmetric_spec::{
    AadMode, AeadVectorSpec, NoncePolicy, PlaintextMode, SymmetricSpec,
};
pub use vector::{AeadVectorFactoryExt, AeadVectorFixture, DOMAIN_AEAD_VECTOR};
