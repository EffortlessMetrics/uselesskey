//! Integration tests for JWK shape types — covers all key type variants,
//! serialization, Debug safety, and Display/From conversions.

use serde_json::Value;
use uselesskey_core_jwk_shape::{
    AnyJwk, EcPrivateJwk, EcPublicJwk, Jwks, OctJwk, OkpPrivateJwk, OkpPublicJwk, PrivateJwk,
    PublicJwk, RsaPrivateJwk, RsaPublicJwk,
};

// ── EC public JWK serialization ──────────────────────────────────────

#[test]
fn ec_public_jwk_serializes_all_fields() {
    let jwk = PublicJwk::Ec(EcPublicJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: "ec-kid-1".to_string(),
        x: "x-coord".to_string(),
        y: "y-coord".to_string(),
    });

    let v = jwk.to_value();
    assert_eq!(v["kty"], "EC");
    assert_eq!(v["crv"], "P-256");
    assert_eq!(v["kid"], "ec-kid-1");
    assert_eq!(v["x"], "x-coord");
    assert_eq!(v["y"], "y-coord");
}

// ── OKP public JWK serialization ─────────────────────────────────────

#[test]
fn okp_public_jwk_serializes_all_fields() {
    let jwk = PublicJwk::Okp(OkpPublicJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: "okp-kid-1".to_string(),
        x: "public-x".to_string(),
    });

    let v = jwk.to_value();
    assert_eq!(v["kty"], "OKP");
    assert_eq!(v["crv"], "Ed25519");
    assert_eq!(v["kid"], "okp-kid-1");
    assert_eq!(v["x"], "public-x");
    assert!(v.get("y").is_none());
}

// ── RSA private JWK serialization ────────────────────────────────────

#[test]
fn rsa_private_jwk_serializes_all_crt_fields() {
    let jwk = RsaPrivateJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: "rsa-priv-1".to_string(),
        n: "n-val".to_string(),
        e: "AQAB".to_string(),
        d: "d-val".to_string(),
        p: "p-val".to_string(),
        q: "q-val".to_string(),
        dp: "dp-val".to_string(),
        dq: "dq-val".to_string(),
        qi: "qi-val".to_string(),
    };

    let v = serde_json::to_value(&jwk).unwrap();
    assert_eq!(v["kty"], "RSA");
    assert_eq!(v["d"], "d-val");
    assert_eq!(v["p"], "p-val");
    assert_eq!(v["qi"], "qi-val");
}

// ── EC private JWK serialization ─────────────────────────────────────

#[test]
fn ec_private_jwk_serializes_d_field() {
    let jwk = PrivateJwk::Ec(EcPrivateJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES384",
        crv: "P-384",
        kid: "ec-priv-1".to_string(),
        x: "x".to_string(),
        y: "y".to_string(),
        d: "private-d".to_string(),
    });

    let v = jwk.to_value();
    assert_eq!(v["crv"], "P-384");
    assert_eq!(v["d"], "private-d");
}

// ── OKP private JWK serialization ────────────────────────────────────

#[test]
fn okp_private_jwk_serializes_d_field() {
    let jwk = PrivateJwk::Okp(OkpPrivateJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: "okp-priv-1".to_string(),
        x: "pub-x".to_string(),
        d: "priv-d".to_string(),
    });

    let v = jwk.to_value();
    assert_eq!(v["kty"], "OKP");
    assert_eq!(v["d"], "priv-d");
}

// ── Debug never leaks private material ───────────────────────────────

#[test]
fn rsa_private_debug_omits_d_p_q() {
    let jwk = RsaPrivateJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: "rsa-dbg".to_string(),
        n: "n-secret".to_string(),
        e: "AQAB".to_string(),
        d: "SECRET-D".to_string(),
        p: "SECRET-P".to_string(),
        q: "SECRET-Q".to_string(),
        dp: "SECRET-DP".to_string(),
        dq: "SECRET-DQ".to_string(),
        qi: "SECRET-QI".to_string(),
    };

    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("RsaPrivateJwk"));
    assert!(!dbg.contains("SECRET-D"));
    assert!(!dbg.contains("SECRET-P"));
    assert!(!dbg.contains("SECRET-Q"));
}

#[test]
fn ec_private_debug_omits_d() {
    let jwk = EcPrivateJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: "ec-dbg".to_string(),
        x: "x".to_string(),
        y: "y".to_string(),
        d: "SUPER-SECRET".to_string(),
    };

    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("EcPrivateJwk"));
    assert!(!dbg.contains("SUPER-SECRET"));
}

#[test]
fn okp_private_debug_omits_d() {
    let jwk = OkpPrivateJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: "okp-dbg".to_string(),
        x: "x".to_string(),
        d: "HIDDEN-KEY".to_string(),
    };

    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("OkpPrivateJwk"));
    assert!(!dbg.contains("HIDDEN-KEY"));
}

#[test]
fn oct_debug_omits_k() {
    let jwk = OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: "oct-dbg".to_string(),
        k: "SECRET-HMAC-KEY".to_string(),
    };

    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("OctJwk"));
    assert!(!dbg.contains("SECRET-HMAC-KEY"));
}

// ── JWKS with mixed key types ────────────────────────────────────────

#[test]
fn jwks_with_all_public_key_types() {
    let jwks = Jwks {
        keys: vec![
            AnyJwk::Public(PublicJwk::Rsa(RsaPublicJwk {
                kty: "RSA",
                use_: "sig",
                alg: "RS256",
                kid: "rsa-1".to_string(),
                n: "n".to_string(),
                e: "AQAB".to_string(),
            })),
            AnyJwk::Public(PublicJwk::Ec(EcPublicJwk {
                kty: "EC",
                use_: "sig",
                alg: "ES256",
                crv: "P-256",
                kid: "ec-1".to_string(),
                x: "x".to_string(),
                y: "y".to_string(),
            })),
            AnyJwk::Public(PublicJwk::Okp(OkpPublicJwk {
                kty: "OKP",
                use_: "sig",
                alg: "EdDSA",
                crv: "Ed25519",
                kid: "okp-1".to_string(),
                x: "x".to_string(),
            })),
        ],
    };

    let v = jwks.to_value();
    let keys = v["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 3);
    assert_eq!(keys[0]["kty"], "RSA");
    assert_eq!(keys[1]["kty"], "EC");
    assert_eq!(keys[2]["kty"], "OKP");
}

#[test]
fn jwks_display_produces_valid_json() {
    let jwks = Jwks {
        keys: vec![AnyJwk::Public(PublicJwk::Rsa(RsaPublicJwk {
            kty: "RSA",
            use_: "sig",
            alg: "RS256",
            kid: "display-1".to_string(),
            n: "n".to_string(),
            e: "AQAB".to_string(),
        }))],
    };

    let json_str = jwks.to_string();
    let parsed: Value = serde_json::from_str(&json_str).expect("should be valid JSON");
    assert!(parsed["keys"].is_array());
}

// ── From conversions ─────────────────────────────────────────────────

#[test]
fn any_jwk_from_public_preserves_kid() {
    let public = PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: "from-pub".to_string(),
        n: "n".to_string(),
        e: "e".to_string(),
    });
    let any: AnyJwk = public.into();
    assert_eq!(any.kid(), "from-pub");
}

#[test]
fn any_jwk_from_private_preserves_kid() {
    let private = PrivateJwk::Oct(OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: "from-priv".to_string(),
        k: "secret".to_string(),
    });
    let any: AnyJwk = private.into();
    assert_eq!(any.kid(), "from-priv");
}

// ── Empty JWKS ───────────────────────────────────────────────────────

#[test]
fn empty_jwks_serializes_to_empty_keys_array() {
    let jwks = Jwks { keys: vec![] };
    let v = jwks.to_value();
    assert_eq!(v["keys"].as_array().unwrap().len(), 0);
}

// ── kid accessors on all public variants ─────────────────────────────

#[test]
fn public_jwk_kid_accessor_all_variants() {
    let rsa = PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: "rsa-kid".to_string(),
        n: "n".to_string(),
        e: "e".to_string(),
    });
    assert_eq!(rsa.kid(), "rsa-kid");

    let ec = PublicJwk::Ec(EcPublicJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: "ec-kid".to_string(),
        x: "x".to_string(),
        y: "y".to_string(),
    });
    assert_eq!(ec.kid(), "ec-kid");

    let okp = PublicJwk::Okp(OkpPublicJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: "okp-kid".to_string(),
        x: "x".to_string(),
    });
    assert_eq!(okp.kid(), "okp-kid");
}

// ── kid accessors on all private variants ────────────────────────────

#[test]
fn private_jwk_kid_accessor_all_variants() {
    let rsa = PrivateJwk::Rsa(RsaPrivateJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: "rsa-priv".to_string(),
        n: "n".to_string(),
        e: "e".to_string(),
        d: "d".to_string(),
        p: "p".to_string(),
        q: "q".to_string(),
        dp: "dp".to_string(),
        dq: "dq".to_string(),
        qi: "qi".to_string(),
    });
    assert_eq!(rsa.kid(), "rsa-priv");

    let ec = PrivateJwk::Ec(EcPrivateJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: "ec-priv".to_string(),
        x: "x".to_string(),
        y: "y".to_string(),
        d: "d".to_string(),
    });
    assert_eq!(ec.kid(), "ec-priv");

    let okp = PrivateJwk::Okp(OkpPrivateJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: "okp-priv".to_string(),
        x: "x".to_string(),
        d: "d".to_string(),
    });
    assert_eq!(okp.kid(), "okp-priv");

    let oct = PrivateJwk::Oct(OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: "oct-priv".to_string(),
        k: "k".to_string(),
    });
    assert_eq!(oct.kid(), "oct-priv");
}
