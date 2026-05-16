//! Single-responsibility modules for the `jsonwebtoken` adapter.

mod jwt_key;

#[cfg(feature = "ecdsa")]
mod ecdsa;
#[cfg(feature = "ed25519")]
mod ed25519;
#[cfg(feature = "hmac")]
mod hmac;
#[cfg(feature = "rsa")]
mod rsa;

#[cfg(test)]
mod tests;

pub use jwt_key::JwtKeyExt;
