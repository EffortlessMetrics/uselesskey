#![forbid(unsafe_code)]

//! RSA fixtures built on `uselesskey-core`.
//!
//! This crate is used by the `uselesskey` facade crate.

mod keypair;
mod spec;

pub use keypair::{RsaFactoryExt, RsaKeyPair, DOMAIN_RSA_KEYPAIR};
pub use spec::RsaSpec;
