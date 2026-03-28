#![forbid(unsafe_code)]

//! Symmetric-key and AEAD vector fixtures built on `uselesskey-core`.

mod fixture;
mod spec;

pub use fixture::{
    AeadVectorFixture, DOMAIN_AEAD_VECTOR, DOMAIN_SYMMETRIC, SymmetricFactoryExt, SymmetricFixture,
};
pub use spec::{AadMode, AeadVectorSpec, NoncePolicy, PlaintextMode, SymmetricSpec};
