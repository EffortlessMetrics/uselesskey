#![forbid(unsafe_code)]

//! Typed JWK and JWKS helpers for uselesskey test fixtures.
//!
//! Provides structured JWK types ([`RsaPublicJwk`], [`EcPublicJwk`], [`OkpPublicJwk`], etc.)
//! and a [`JwksBuilder`] for composing JWKS documents with stable key ordering.

use serde::Serialize;
use serde_json::Value;
use std::fmt;

#[derive(Clone, Serialize)]
pub struct Jwks {
    pub keys: Vec<AnyJwk>,
}

impl Jwks {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("serialize JWKS")
    }
}

impl fmt::Display for Jwks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => f.write_str(&s),
            Err(_) => Err(fmt::Error),
        }
    }
}

#[derive(Clone, Default)]
pub struct JwksBuilder {
    entries: Vec<Entry>,
}

#[derive(Clone)]
struct Entry {
    kid: String,
    index: usize,
    jwk: AnyJwk,
}

impl JwksBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_public(mut self, jwk: PublicJwk) -> Self {
        self.push_public(jwk);
        self
    }

    pub fn add_private(mut self, jwk: PrivateJwk) -> Self {
        self.push_private(jwk);
        self
    }

    pub fn add_any(mut self, jwk: AnyJwk) -> Self {
        self.push_any(jwk);
        self
    }

    pub fn push_public(&mut self, jwk: PublicJwk) -> &mut Self {
        self.push_any(AnyJwk::from(jwk))
    }

    pub fn push_private(&mut self, jwk: PrivateJwk) -> &mut Self {
        self.push_any(AnyJwk::from(jwk))
    }

    pub fn push_any(&mut self, jwk: AnyJwk) -> &mut Self {
        let index = self.entries.len();
        let kid = jwk.kid().to_string();
        self.entries.push(Entry { kid, index, jwk });
        self
    }

    pub fn build(mut self) -> Jwks {
        self.entries
            .sort_by(|a, b| a.kid.cmp(&b.kid).then(a.index.cmp(&b.index)));
        Jwks {
            keys: self.entries.into_iter().map(|e| e.jwk).collect(),
        }
    }
}

#[derive(Clone, Serialize)]
pub struct RsaPublicJwk {
    pub kty: &'static str,
    #[serde(rename = "use")]
    pub use_: &'static str,
    pub alg: &'static str,
    pub kid: String,
    pub n: String,
    pub e: String,
}

impl RsaPublicJwk {
    pub fn kid(&self) -> &str {
        &self.kid
    }
}

#[derive(Clone, Serialize)]
pub struct RsaPrivateJwk {
    pub kty: &'static str,
    #[serde(rename = "use")]
    pub use_: &'static str,
    pub alg: &'static str,
    pub kid: String,
    pub n: String,
    pub e: String,
    pub d: String,
    pub p: String,
    pub q: String,
    pub dp: String,
    pub dq: String,
    #[serde(rename = "qi")]
    pub qi: String,
}

impl RsaPrivateJwk {
    pub fn kid(&self) -> &str {
        &self.kid
    }
}

impl fmt::Debug for RsaPrivateJwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPrivateJwk")
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize)]
pub struct EcPublicJwk {
    pub kty: &'static str,
    #[serde(rename = "use")]
    pub use_: &'static str,
    pub alg: &'static str,
    pub crv: &'static str,
    pub kid: String,
    pub x: String,
    pub y: String,
}

impl EcPublicJwk {
    pub fn kid(&self) -> &str {
        &self.kid
    }
}

#[derive(Clone, Serialize)]
pub struct EcPrivateJwk {
    pub kty: &'static str,
    #[serde(rename = "use")]
    pub use_: &'static str,
    pub alg: &'static str,
    pub crv: &'static str,
    pub kid: String,
    pub x: String,
    pub y: String,
    pub d: String,
}

impl EcPrivateJwk {
    pub fn kid(&self) -> &str {
        &self.kid
    }
}

impl fmt::Debug for EcPrivateJwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcPrivateJwk")
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .field("crv", &self.crv)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize)]
pub struct OkpPublicJwk {
    pub kty: &'static str,
    #[serde(rename = "use")]
    pub use_: &'static str,
    pub alg: &'static str,
    pub crv: &'static str,
    pub kid: String,
    pub x: String,
}

impl OkpPublicJwk {
    pub fn kid(&self) -> &str {
        &self.kid
    }
}

#[derive(Clone, Serialize)]
pub struct OkpPrivateJwk {
    pub kty: &'static str,
    #[serde(rename = "use")]
    pub use_: &'static str,
    pub alg: &'static str,
    pub crv: &'static str,
    pub kid: String,
    pub x: String,
    pub d: String,
}

impl OkpPrivateJwk {
    pub fn kid(&self) -> &str {
        &self.kid
    }
}

impl fmt::Debug for OkpPrivateJwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OkpPrivateJwk")
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .field("crv", &self.crv)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize)]
pub struct OctJwk {
    pub kty: &'static str,
    #[serde(rename = "use")]
    pub use_: &'static str,
    pub alg: &'static str,
    pub kid: String,
    pub k: String,
}

impl OctJwk {
    pub fn kid(&self) -> &str {
        &self.kid
    }
}

impl fmt::Debug for OctJwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OctJwk")
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize)]
#[serde(untagged)]
pub enum PublicJwk {
    Rsa(RsaPublicJwk),
    Ec(EcPublicJwk),
    Okp(OkpPublicJwk),
}

impl PublicJwk {
    pub fn kid(&self) -> &str {
        match self {
            PublicJwk::Rsa(jwk) => jwk.kid(),
            PublicJwk::Ec(jwk) => jwk.kid(),
            PublicJwk::Okp(jwk) => jwk.kid(),
        }
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("serialize JWK")
    }
}

impl fmt::Display for PublicJwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => f.write_str(&s),
            Err(_) => Err(fmt::Error),
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(untagged)]
pub enum PrivateJwk {
    Rsa(RsaPrivateJwk),
    Ec(EcPrivateJwk),
    Okp(OkpPrivateJwk),
    Oct(OctJwk),
}

impl PrivateJwk {
    pub fn kid(&self) -> &str {
        match self {
            PrivateJwk::Rsa(jwk) => jwk.kid(),
            PrivateJwk::Ec(jwk) => jwk.kid(),
            PrivateJwk::Okp(jwk) => jwk.kid(),
            PrivateJwk::Oct(jwk) => jwk.kid(),
        }
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("serialize JWK")
    }
}

impl fmt::Display for PrivateJwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => f.write_str(&s),
            Err(_) => Err(fmt::Error),
        }
    }
}

impl fmt::Debug for PrivateJwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivateJwk::Rsa(jwk) => jwk.fmt(f),
            PrivateJwk::Ec(jwk) => jwk.fmt(f),
            PrivateJwk::Okp(jwk) => jwk.fmt(f),
            PrivateJwk::Oct(jwk) => jwk.fmt(f),
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(untagged)]
pub enum AnyJwk {
    Public(PublicJwk),
    Private(PrivateJwk),
}

impl AnyJwk {
    pub fn kid(&self) -> &str {
        match self {
            AnyJwk::Public(jwk) => jwk.kid(),
            AnyJwk::Private(jwk) => jwk.kid(),
        }
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("serialize JWK")
    }
}

impl fmt::Display for AnyJwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => f.write_str(&s),
            Err(_) => Err(fmt::Error),
        }
    }
}

impl From<PublicJwk> for AnyJwk {
    fn from(value: PublicJwk) -> Self {
        AnyJwk::Public(value)
    }
}

impl From<PrivateJwk> for AnyJwk {
    fn from(value: PrivateJwk) -> Self {
        AnyJwk::Private(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rsa_public(kid: &str, n: &str) -> PublicJwk {
        PublicJwk::Rsa(RsaPublicJwk {
            kty: "RSA",
            use_: "sig",
            alg: "RS256",
            kid: kid.to_string(),
            n: n.to_string(),
            e: "AQAB".to_string(),
        })
    }

    fn sample_oct_private(kid: &str, k: &str) -> PrivateJwk {
        PrivateJwk::Oct(OctJwk {
            kty: "oct",
            use_: "sig",
            alg: "HS256",
            kid: kid.to_string(),
            k: k.to_string(),
        })
    }

    #[test]
    fn jwks_builder_orders_by_kid() {
        let jwk1 = PublicJwk::Rsa(RsaPublicJwk {
            kty: "RSA",
            use_: "sig",
            alg: "RS256",
            kid: "b".to_string(),
            n: "n".to_string(),
            e: "e".to_string(),
        });
        let jwk2 = PublicJwk::Ec(EcPublicJwk {
            kty: "EC",
            use_: "sig",
            alg: "ES256",
            crv: "P-256",
            kid: "a".to_string(),
            x: "x".to_string(),
            y: "y".to_string(),
        });

        let jwks = JwksBuilder::new().add_public(jwk1).add_public(jwk2).build();

        assert_eq!(jwks.keys.len(), 2);
        assert_eq!(jwks.keys[0].kid(), "a");
        assert_eq!(jwks.keys[1].kid(), "b");
    }

    #[test]
    fn jwks_builder_stable_for_same_kid() {
        let jwk1 = PublicJwk::Rsa(RsaPublicJwk {
            kty: "RSA",
            use_: "sig",
            alg: "RS256",
            kid: "same".to_string(),
            n: "n1".to_string(),
            e: "e1".to_string(),
        });
        let jwk2 = PublicJwk::Rsa(RsaPublicJwk {
            kty: "RSA",
            use_: "sig",
            alg: "RS256",
            kid: "same".to_string(),
            n: "n2".to_string(),
            e: "e2".to_string(),
        });

        let jwks = JwksBuilder::new().add_public(jwk1).add_public(jwk2).build();

        assert_eq!(jwks.keys[0].kid(), "same");
        assert_eq!(jwks.keys[1].kid(), "same");
        let first = jwks.keys[0].to_value();
        let second = jwks.keys[1].to_value();
        assert_eq!(first["n"], "n1");
        assert_eq!(second["n"], "n2");
    }

    #[test]
    fn display_outputs_json() {
        let jwk = sample_rsa_public("kid-1", "n1");
        let json = jwk.to_string();
        let v: Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(v["kty"], "RSA");

        let private = sample_oct_private("kid-2", "secret");
        let json = private.to_string();
        let v: Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(v["kty"], "oct");
    }

    #[test]
    fn debug_omits_private_material() {
        let secret = "super-secret-value";
        let jwk = sample_oct_private("kid-3", secret);
        let dbg = format!("{:?}", jwk);
        assert!(dbg.contains("OctJwk"));
        assert!(!dbg.contains(secret));
    }

    #[test]
    fn any_jwk_from_conversions_work() {
        let pub_jwk = sample_rsa_public("kid-4", "n4");
        let any_pub = AnyJwk::from(pub_jwk.clone());
        assert_eq!(any_pub.kid(), pub_jwk.kid());

        let priv_jwk = sample_oct_private("kid-5", "k5");
        let any_priv = AnyJwk::from(priv_jwk.clone());
        assert_eq!(any_priv.kid(), priv_jwk.kid());
    }

    #[test]
    fn jwks_builder_push_methods_and_display() {
        let jwk_pub = sample_rsa_public("kid-b", "nb");
        let jwk_priv = sample_oct_private("kid-a", "ka");

        let mut builder = JwksBuilder::new();
        builder.push_public(jwk_pub.clone());
        builder.push_private(jwk_priv.clone());
        builder.push_any(AnyJwk::from(jwk_pub.clone()));

        let jwks = builder.build();
        let json = jwks.to_string();
        let v: Value = serde_json::from_str(&json).expect("valid JSON");

        let keys = v["keys"].as_array().expect("keys array");
        assert_eq!(keys.len(), 3);
        assert_eq!(jwks.keys.len(), 3);
    }

    #[test]
    fn jwks_to_value_contains_keys() {
        let jwks = JwksBuilder::new().add_public(sample_rsa_public("kid", "n")).build();
        let v = jwks.to_value();
        assert!(v["keys"].is_array());
        assert_eq!(v["keys"].as_array().unwrap().len(), 1);
    }
}
