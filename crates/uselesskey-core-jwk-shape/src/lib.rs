#![forbid(unsafe_code)]

//! Deprecated compatibility shim for typed JWK and JWKS shape helpers.
//!
//! Prefer `uselesskey-jwk`; the canonical implementation now lives there.

pub use uselesskey_jwk::{
    AnyJwk, EcPrivateJwk, EcPublicJwk, Jwks, NegativeJwk, NegativeJwks, OctJwk, OkpPrivateJwk,
    OkpPublicJwk, PrivateJwk, PublicJwk, RsaPrivateJwk, RsaPublicJwk,
};
