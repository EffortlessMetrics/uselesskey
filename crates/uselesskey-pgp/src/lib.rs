#![forbid(unsafe_code)]

//! OpenPGP fixtures built on `uselesskey-core`.
//!
//! The main entry point is [`PgpFactoryExt`], which adds `.pgp()` to
//! [`Factory`](uselesskey_core::Factory).

mod keypair;
mod spec;

pub use keypair::{DOMAIN_PGP_KEYPAIR, PgpFactoryExt, PgpKeyPair};
pub use spec::PgpSpec;
