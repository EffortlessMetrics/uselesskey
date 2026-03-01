//! Property-based tests for JWK shape serialization invariants.

use proptest::prelude::*;
use serde_json::Value;
use uselesskey_core_jwk_shape::{
    AnyJwk, EcPrivateJwk, EcPublicJwk, Jwks, OctJwk, OkpPrivateJwk, OkpPublicJwk, PrivateJwk,
    PublicJwk, RsaPrivateJwk, RsaPublicJwk,
};

fn b64url() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_-]{1,64}"
}

fn kid_strategy() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9._-]{1,24}"
}

// ---------------------------------------------------------------------------
// Serialization roundtrip: to_value and Display parse to the same JSON
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn ec_public_roundtrip(kid in kid_strategy(), x in b64url(), y in b64url()) {
        let jwk = PublicJwk::Ec(EcPublicJwk {
            kty: "EC", use_: "sig", alg: "ES256", crv: "P-256",
            kid, x, y,
        });
        let value = jwk.to_value();
        let parsed: Value = serde_json::from_str(&jwk.to_string()).unwrap();
        prop_assert_eq!(&value, &parsed);
        prop_assert_eq!(value["kty"].as_str().unwrap(), "EC");
        prop_assert!(value.get("use").is_some());
    }

    #[test]
    fn okp_public_roundtrip(kid in kid_strategy(), x in b64url()) {
        let jwk = PublicJwk::Okp(OkpPublicJwk {
            kty: "OKP", use_: "sig", alg: "EdDSA", crv: "Ed25519",
            kid, x,
        });
        let value = jwk.to_value();
        let parsed: Value = serde_json::from_str(&jwk.to_string()).unwrap();
        prop_assert_eq!(&value, &parsed);
        prop_assert_eq!(value["kty"].as_str().unwrap(), "OKP");
    }

    #[test]
    fn rsa_private_roundtrip(
        kid in kid_strategy(),
        n in b64url(), e in b64url(), d in b64url(),
        p in b64url(), q in b64url(),
        dp in b64url(), dq in b64url(), qi in b64url(),
    ) {
        let jwk = PrivateJwk::Rsa(RsaPrivateJwk {
            kty: "RSA", use_: "sig", alg: "RS256",
            kid, n, e, d, p, q, dp, dq, qi,
        });
        let value = jwk.to_value();
        let parsed: Value = serde_json::from_str(&jwk.to_string()).unwrap();
        prop_assert_eq!(&value, &parsed);
        for field in ["kty", "use", "alg", "kid", "n", "e", "d", "p", "q", "dp", "dq", "qi"] {
            prop_assert!(value.get(field).is_some(), "missing field: {}", field);
        }
    }

    #[test]
    fn ec_private_roundtrip(kid in kid_strategy(), x in b64url(), y in b64url(), d in b64url()) {
        let jwk = PrivateJwk::Ec(EcPrivateJwk {
            kty: "EC", use_: "sig", alg: "ES256", crv: "P-256",
            kid, x, y, d,
        });
        let value = jwk.to_value();
        let parsed: Value = serde_json::from_str(&jwk.to_string()).unwrap();
        prop_assert_eq!(&value, &parsed);
        for field in ["kty", "use", "alg", "kid", "crv", "x", "y", "d"] {
            prop_assert!(value.get(field).is_some(), "missing field: {}", field);
        }
    }

    #[test]
    fn okp_private_roundtrip(kid in kid_strategy(), x in b64url(), d in b64url()) {
        let jwk = PrivateJwk::Okp(OkpPrivateJwk {
            kty: "OKP", use_: "sig", alg: "EdDSA", crv: "Ed25519",
            kid, x, d,
        });
        let value = jwk.to_value();
        let parsed: Value = serde_json::from_str(&jwk.to_string()).unwrap();
        prop_assert_eq!(&value, &parsed);
        for field in ["kty", "use", "alg", "kid", "crv", "x", "d"] {
            prop_assert!(value.get(field).is_some(), "missing field: {}", field);
        }
    }
}

// ---------------------------------------------------------------------------
// JWKS collection roundtrip
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn jwks_roundtrip(
        kids in prop::collection::vec(kid_strategy(), 0..8),
    ) {
        let keys: Vec<AnyJwk> = kids.iter().map(|kid| {
            AnyJwk::from(PublicJwk::Rsa(RsaPublicJwk {
                kty: "RSA", use_: "sig", alg: "RS256",
                kid: kid.clone(), n: "n".into(), e: "AQAB".into(),
            }))
        }).collect();

        let jwks = Jwks { keys };
        let value = jwks.to_value();
        let parsed: Value = serde_json::from_str(&jwks.to_string()).unwrap();
        prop_assert_eq!(&value, &parsed);

        let arr = value["keys"].as_array().unwrap();
        prop_assert_eq!(arr.len(), kids.len());
    }
}

// ---------------------------------------------------------------------------
// Debug never leaks private material
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn debug_never_leaks_rsa_private(secret in "[a-zA-Z0-9]{8,32}") {
        let jwk = RsaPrivateJwk {
            kty: "RSA", use_: "sig", alg: "RS256",
            kid: "k".into(),
            n: secret.clone(), e: secret.clone(),
            d: secret.clone(), p: secret.clone(), q: secret.clone(),
            dp: secret.clone(), dq: secret.clone(), qi: secret.clone(),
        };
        let dbg = format!("{jwk:?}");
        prop_assert!(!dbg.contains(&secret), "Debug leaked material: {}", dbg);
    }

    #[test]
    fn debug_never_leaks_ec_private(secret in "[a-zA-Z0-9]{8,32}") {
        let jwk = EcPrivateJwk {
            kty: "EC", use_: "sig", alg: "ES256", crv: "P-256",
            kid: "k".into(),
            x: secret.clone(), y: secret.clone(), d: secret.clone(),
        };
        let dbg = format!("{jwk:?}");
        prop_assert!(!dbg.contains(&secret), "Debug leaked material: {}", dbg);
    }

    #[test]
    fn debug_never_leaks_okp_private(secret in "[a-zA-Z0-9]{8,32}") {
        let jwk = OkpPrivateJwk {
            kty: "OKP", use_: "sig", alg: "EdDSA", crv: "Ed25519",
            kid: "k".into(),
            x: secret.clone(), d: secret.clone(),
        };
        let dbg = format!("{jwk:?}");
        prop_assert!(!dbg.contains(&secret), "Debug leaked material: {}", dbg);
    }

    #[test]
    fn debug_never_leaks_oct(secret in "[a-zA-Z0-9]{8,32}") {
        let jwk = OctJwk {
            kty: "oct", use_: "sig", alg: "HS256",
            kid: "k".into(),
            k: secret.clone(),
        };
        let dbg = format!("{jwk:?}");
        prop_assert!(!dbg.contains(&secret), "Debug leaked material: {}", dbg);
    }
}

// ---------------------------------------------------------------------------
// kid() is consistent through enum wrapping
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn kid_consistent_through_any_wrapping(kid in kid_strategy()) {
        let rsa = PublicJwk::Rsa(RsaPublicJwk {
            kty: "RSA", use_: "sig", alg: "RS256",
            kid: kid.clone(), n: "n".into(), e: "e".into(),
        });
        prop_assert_eq!(rsa.kid(), kid.as_str());
        let any = AnyJwk::from(rsa);
        prop_assert_eq!(any.kid(), kid.as_str());

        let oct = PrivateJwk::Oct(OctJwk {
            kty: "oct", use_: "sig", alg: "HS256",
            kid: kid.clone(), k: "k".into(),
        });
        prop_assert_eq!(oct.kid(), kid.as_str());
        let any = AnyJwk::from(oct);
        prop_assert_eq!(any.kid(), kid.as_str());
    }
}
