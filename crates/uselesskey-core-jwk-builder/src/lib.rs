#![forbid(unsafe_code)]

//! JWKS composition with deterministic ordering semantics.
//!
//! This crate centralizes JWKS assembly behavior that is shared across JWK-producing
//! key fixtures. Entries are sorted by `kid` and preserve insertion order for duplicate
//! `kid` values.

use uselesskey_core_jwk::{AnyJwk, Jwks, PrivateJwk, PublicJwk};

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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rsa_public(kid: &str, n: &str) -> PublicJwk {
        PublicJwk::Rsa(uselesskey_core_jwk::RsaPublicJwk {
            kty: "RSA",
            use_: "sig",
            alg: "RS256",
            kid: kid.to_string(),
            n: n.to_string(),
            e: "AQAB".to_string(),
        })
    }

    fn sample_oct_private(kid: &str, k: &str) -> PrivateJwk {
        PrivateJwk::Oct(uselesskey_core_jwk::OctJwk {
            kty: "oct",
            use_: "sig",
            alg: "HS256",
            kid: kid.to_string(),
            k: k.to_string(),
        })
    }

    #[test]
    fn jwks_builder_orders_by_kid() {
        let jwk1 = PublicJwk::Rsa(uselesskey_core_jwk::RsaPublicJwk {
            kty: "RSA",
            use_: "sig",
            alg: "RS256",
            kid: "b".to_string(),
            n: "n".to_string(),
            e: "e".to_string(),
        });
        let jwk2 = PublicJwk::Ec(uselesskey_core_jwk::EcPublicJwk {
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
        let jwk1 = PublicJwk::Rsa(uselesskey_core_jwk::RsaPublicJwk {
            kty: "RSA",
            use_: "sig",
            alg: "RS256",
            kid: "same".to_string(),
            n: "n1".to_string(),
            e: "e1".to_string(),
        });
        let jwk2 = PublicJwk::Rsa(uselesskey_core_jwk::RsaPublicJwk {
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
    fn jwks_builder_push_methods_and_display() {
        let jwk_pub = sample_rsa_public("kid-b", "nb");
        let jwk_priv = sample_oct_private("kid-a", "ka");

        let mut builder = JwksBuilder::new();
        builder.push_public(jwk_pub.clone());
        builder.push_private(jwk_priv.clone());
        builder.push_any(AnyJwk::from(jwk_pub.clone()));

        let jwks = builder.build();
        let json = jwks.to_string();
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

        let keys = v["keys"].as_array().expect("keys array");
        assert_eq!(keys.len(), 3);
        assert_eq!(jwks.keys.len(), 3);
    }

    #[test]
    fn jwks_builder_add_methods_work() {
        let jwk_priv = sample_oct_private("kid-a", "ka");
        let jwk_any = AnyJwk::from(sample_rsa_public("kid-b", "nb"));

        let jwks = JwksBuilder::new()
            .add_private(jwk_priv)
            .add_any(jwk_any)
            .build();

        assert_eq!(jwks.keys.len(), 2);
    }
}
