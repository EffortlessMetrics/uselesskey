//! Insta snapshot tests for uselesskey-core-jwk.
//!
//! Verifies the facade re-exports and JwksBuilder integration
//! with key material redacted.

use serde::Serialize;
use uselesskey_core_jwk::{EcPublicJwk, JwksBuilder, OkpPublicJwk, PublicJwk, RsaPublicJwk};

fn rsa_pub(kid: &str) -> PublicJwk {
    PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.into(),
        n: "modulus-data".into(),
        e: "AQAB".into(),
    })
}

fn ec_pub(kid: &str) -> PublicJwk {
    PublicJwk::Ec(EcPublicJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.into(),
        x: "ec-x".into(),
        y: "ec-y".into(),
    })
}

fn okp_pub(kid: &str) -> PublicJwk {
    PublicJwk::Okp(OkpPublicJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.into(),
        x: "okp-x".into(),
    })
}

#[test]
fn snapshot_facade_jwks_builder_ordering() {
    #[derive(Serialize)]
    struct JwksInfo {
        key_count: usize,
        kids: Vec<String>,
    }

    let jwks = JwksBuilder::new()
        .add_public(rsa_pub("zulu"))
        .add_public(ec_pub("alpha"))
        .add_public(okp_pub("mike"))
        .build();

    let info = JwksInfo {
        key_count: jwks.keys.len(),
        kids: jwks.keys.iter().map(|k| k.kid().to_string()).collect(),
    };

    insta::assert_yaml_snapshot!("facade_jwks_builder_ordering", info);
}

#[test]
fn snapshot_facade_jwks_serialized() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_pub("key-1"))
        .add_public(okp_pub("key-2"))
        .build();

    let value = jwks.to_value();
    insta::assert_yaml_snapshot!("facade_jwks_serialized", value, {
        ".keys[].n" => "[REDACTED]",
        ".keys[].e" => "[REDACTED]",
        ".keys[].x" => "[REDACTED]",
    });
}

#[test]
fn snapshot_facade_public_jwk_to_value() {
    let jwk = rsa_pub("test-key");
    let value = jwk.to_value();
    insta::assert_yaml_snapshot!("facade_public_jwk_value", value, {
        ".n" => "[REDACTED]",
        ".e" => "[REDACTED]",
    });
}

#[test]
fn snapshot_facade_reexports_all_types() {
    #[derive(Serialize)]
    struct TypeCheck {
        rsa_kty: &'static str,
        ec_kty: &'static str,
        okp_kty: &'static str,
    }

    let check = TypeCheck {
        rsa_kty: RsaPublicJwk {
            kty: "RSA",
            use_: "sig",
            alg: "RS256",
            kid: "k".into(),
            n: "n".into(),
            e: "e".into(),
        }
        .kty,
        ec_kty: EcPublicJwk {
            kty: "EC",
            use_: "sig",
            alg: "ES256",
            crv: "P-256",
            kid: "k".into(),
            x: "x".into(),
            y: "y".into(),
        }
        .kty,
        okp_kty: OkpPublicJwk {
            kty: "OKP",
            use_: "sig",
            alg: "EdDSA",
            crv: "Ed25519",
            kid: "k".into(),
            x: "x".into(),
        }
        .kty,
    };

    insta::assert_yaml_snapshot!("facade_reexports_types", check);
}
