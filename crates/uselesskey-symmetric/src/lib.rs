#![forbid(unsafe_code)]

//! Deterministic symmetric-key and AEAD test fixtures.

mod fixture;

pub use uselesskey_core_symmetric_spec::{
    AadMode, AeadVectorSpec, NoncePolicy, PlaintextMode, SymmetricSpec,
};

pub use fixture::{
    AeadVectorFixture, DOMAIN_SYMMETRIC_AEAD_VECTOR, DOMAIN_SYMMETRIC_KEY, SymmetricFactoryExt,
    SymmetricFixture,
};
