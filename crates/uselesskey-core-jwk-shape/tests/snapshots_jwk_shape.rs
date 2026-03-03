//! Insta snapshot tests for uselesskey-core-jwk-shape.
//!
//! Snapshot JWK struct serialization shapes with key material redacted.

use serde::Serialize;
use uselesskey_core_jwk_shape::{
    AnyJwk, EcPrivateJwk, EcPublicJwk, Jwks, OctJwk, OkpPrivateJwk, OkpPublicJwk, PrivateJwk,
    PublicJwk, RsaPrivateJwk, RsaPublicJwk,
};

fn rsa_public(kid: &str) -> RsaPublicJwk {
    RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.into(),
        n: "test-modulus".into(),
        e: "AQAB".into(),
    }
}

fn rsa_private(kid: &str) -> RsaPrivateJwk {
    RsaPrivateJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.into(),
        n: "test-modulus".into(),
        e: "AQAB".into(),
        d: "test-d".into(),
        p: "test-p".into(),
        q: "test-q".into(),
        dp: "test-dp".into(),
        dq: "test-dq".into(),
        qi: "test-qi".into(),
    }
}

fn ec_public(kid: &str) -> EcPublicJwk {
    EcPublicJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.into(),
        x: "test-x".into(),
        y: "test-y".into(),
    }
}

fn ec_private(kid: &str) -> EcPrivateJwk {
    EcPrivateJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.into(),
        x: "test-x".into(),
        y: "test-y".into(),
        d: "test-d".into(),
    }
}

fn okp_public(kid: &str) -> OkpPublicJwk {
    OkpPublicJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.into(),
        x: "test-x".into(),
    }
}

fn okp_private(kid: &str) -> OkpPrivateJwk {
    OkpPrivateJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.into(),
        x: "test-x".into(),
        d: "test-d".into(),
    }
}

fn oct_jwk(kid: &str) -> OctJwk {
    OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: kid.into(),
        k: "test-secret".into(),
    }
}

// --- RSA ---

#[test]
fn snapshot_rsa_public_jwk() {
    let jwk = rsa_public("rsa-pub-1");
    let value = serde_json::to_value(&jwk).unwrap();
    insta::assert_yaml_snapshot!("rsa_public_jwk_shape", value, {
        ".n" => "[REDACTED]",
        ".e" => "[REDACTED]",
    });
}

#[test]
fn snapshot_rsa_private_jwk() {
    let jwk = rsa_private("rsa-priv-1");
    let value = serde_json::to_value(&jwk).unwrap();
    insta::assert_yaml_snapshot!("rsa_private_jwk_shape", value, {
        ".n" => "[REDACTED]",
        ".e" => "[REDACTED]",
        ".d" => "[REDACTED]",
        ".p" => "[REDACTED]",
        ".q" => "[REDACTED]",
        ".dp" => "[REDACTED]",
        ".dq" => "[REDACTED]",
        ".qi" => "[REDACTED]",
    });
}

// --- EC ---

#[test]
fn snapshot_ec_public_jwk() {
    let jwk = ec_public("ec-pub-1");
    let value = serde_json::to_value(&jwk).unwrap();
    insta::assert_yaml_snapshot!("ec_public_jwk_shape", value, {
        ".x" => "[REDACTED]",
        ".y" => "[REDACTED]",
    });
}

#[test]
fn snapshot_ec_private_jwk() {
    let jwk = ec_private("ec-priv-1");
    let value = serde_json::to_value(&jwk).unwrap();
    insta::assert_yaml_snapshot!("ec_private_jwk_shape", value, {
        ".x" => "[REDACTED]",
        ".y" => "[REDACTED]",
        ".d" => "[REDACTED]",
    });
}

// --- OKP ---

#[test]
fn snapshot_okp_public_jwk() {
    let jwk = okp_public("okp-pub-1");
    let value = serde_json::to_value(&jwk).unwrap();
    insta::assert_yaml_snapshot!("okp_public_jwk_shape", value, {
        ".x" => "[REDACTED]",
    });
}

#[test]
fn snapshot_okp_private_jwk() {
    let jwk = okp_private("okp-priv-1");
    let value = serde_json::to_value(&jwk).unwrap();
    insta::assert_yaml_snapshot!("okp_private_jwk_shape", value, {
        ".x" => "[REDACTED]",
        ".d" => "[REDACTED]",
    });
}

// --- Oct ---

#[test]
fn snapshot_oct_jwk() {
    let jwk = oct_jwk("oct-1");
    let value = serde_json::to_value(&jwk).unwrap();
    insta::assert_yaml_snapshot!("oct_jwk_shape", value, {
        ".k" => "[REDACTED]",
    });
}

// --- Enums ---

#[test]
fn snapshot_public_jwk_enum_variants() {
    #[derive(Serialize)]
    struct VariantInfo {
        variant: &'static str,
        kid: String,
        kty: String,
    }

    let variants = [
        ("Rsa", PublicJwk::Rsa(rsa_public("rsa-1"))),
        ("Ec", PublicJwk::Ec(ec_public("ec-1"))),
        ("Okp", PublicJwk::Okp(okp_public("okp-1"))),
    ];

    let infos: Vec<VariantInfo> = variants
        .iter()
        .map(|(name, jwk)| VariantInfo {
            variant: name,
            kid: jwk.kid().to_string(),
            kty: jwk.to_value()["kty"].as_str().unwrap().to_string(),
        })
        .collect();

    insta::assert_yaml_snapshot!("public_jwk_enum_variants", infos);
}

#[test]
fn snapshot_private_jwk_enum_variants() {
    #[derive(Serialize)]
    struct VariantInfo {
        variant: &'static str,
        kid: String,
        kty: String,
    }

    let variants: [(&str, PrivateJwk); 4] = [
        ("Rsa", PrivateJwk::Rsa(rsa_private("rsa-p-1"))),
        ("Ec", PrivateJwk::Ec(ec_private("ec-p-1"))),
        ("Okp", PrivateJwk::Okp(okp_private("okp-p-1"))),
        ("Oct", PrivateJwk::Oct(oct_jwk("oct-p-1"))),
    ];

    let infos: Vec<VariantInfo> = variants
        .iter()
        .map(|(name, jwk)| VariantInfo {
            variant: name,
            kid: jwk.kid().to_string(),
            kty: jwk.to_value()["kty"].as_str().unwrap().to_string(),
        })
        .collect();

    insta::assert_yaml_snapshot!("private_jwk_enum_variants", infos);
}

// --- Debug redaction ---

#[test]
fn snapshot_private_debug_redaction() {
    #[derive(Serialize)]
    struct DebugInfo {
        variant: &'static str,
        debug_output: String,
        contains_secret: bool,
    }

    let secret = "SUPER-SECRET-VALUE";
    let variants: [(&str, String); 4] = [
        (
            "RsaPrivateJwk",
            format!(
                "{:?}",
                RsaPrivateJwk {
                    kty: "RSA",
                    use_: "sig",
                    alg: "RS256",
                    kid: "k".into(),
                    n: secret.into(),
                    e: secret.into(),
                    d: secret.into(),
                    p: secret.into(),
                    q: secret.into(),
                    dp: secret.into(),
                    dq: secret.into(),
                    qi: secret.into(),
                }
            ),
        ),
        (
            "EcPrivateJwk",
            format!(
                "{:?}",
                EcPrivateJwk {
                    kty: "EC",
                    use_: "sig",
                    alg: "ES256",
                    crv: "P-256",
                    kid: "k".into(),
                    x: secret.into(),
                    y: secret.into(),
                    d: secret.into(),
                }
            ),
        ),
        (
            "OkpPrivateJwk",
            format!(
                "{:?}",
                OkpPrivateJwk {
                    kty: "OKP",
                    use_: "sig",
                    alg: "EdDSA",
                    crv: "Ed25519",
                    kid: "k".into(),
                    x: secret.into(),
                    d: secret.into(),
                }
            ),
        ),
        (
            "OctJwk",
            format!(
                "{:?}",
                OctJwk {
                    kty: "oct",
                    use_: "sig",
                    alg: "HS256",
                    kid: "k".into(),
                    k: secret.into(),
                }
            ),
        ),
    ];

    let infos: Vec<DebugInfo> = variants
        .iter()
        .map(|(name, dbg)| DebugInfo {
            variant: name,
            debug_output: dbg.clone(),
            contains_secret: dbg.contains(secret),
        })
        .collect();

    insta::assert_yaml_snapshot!("private_debug_redaction", infos);
}

// --- JWKS ---

#[test]
fn snapshot_jwks_structure() {
    let jwks = Jwks {
        keys: vec![
            AnyJwk::Public(PublicJwk::Rsa(rsa_public("key-a"))),
            AnyJwk::Public(PublicJwk::Ec(ec_public("key-b"))),
            AnyJwk::Private(PrivateJwk::Oct(oct_jwk("key-c"))),
        ],
    };

    let value = jwks.to_value();
    insta::assert_yaml_snapshot!("jwks_structure", value, {
        ".keys[].n" => "[REDACTED]",
        ".keys[].e" => "[REDACTED]",
        ".keys[].x" => "[REDACTED]",
        ".keys[].y" => "[REDACTED]",
        ".keys[].k" => "[REDACTED]",
    });
}

#[test]
fn snapshot_jwks_display_is_valid_json() {
    let jwks = Jwks {
        keys: vec![AnyJwk::Public(PublicJwk::Okp(okp_public("disp-1")))],
    };

    let display = jwks.to_string();
    let parsed: serde_json::Value = serde_json::from_str(&display).unwrap();

    #[derive(Serialize)]
    struct DisplayCheck {
        has_keys_array: bool,
        key_count: usize,
    }

    let check = DisplayCheck {
        has_keys_array: parsed["keys"].is_array(),
        key_count: parsed["keys"].as_array().unwrap().len(),
    };

    insta::assert_yaml_snapshot!("jwks_display_check", check);
}
