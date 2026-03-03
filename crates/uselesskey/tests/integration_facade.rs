//! Comprehensive integration tests for the `uselesskey` facade crate.
//!
//! These tests exercise the full **user-facing** public API as a crates.io
//! consumer would use it: `use uselesskey::*`.  Every feature-gated key type,
//! output format, negative fixture, and cross-cutting concern (determinism,
//! caching, thread-safety, Debug safety) is covered.

mod testutil;

use uselesskey::prelude::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn det(seed: &str) -> Factory {
    Factory::deterministic(Seed::from_env_value(seed).unwrap())
}

// ===========================================================================
// 1. Factory creation & core re-exports
// ===========================================================================

#[test]
fn factory_random_returns_random_mode() {
    let fx = Factory::random();
    assert!(matches!(fx.mode(), Mode::Random));
}

#[test]
fn factory_deterministic_returns_deterministic_mode() {
    let fx = det("int-facade-core-1");
    assert!(matches!(fx.mode(), Mode::Deterministic { .. }));
}

#[test]
fn factory_deterministic_from_env_works() {
    let var = "USELESSKEY_INT_FACADE_SEED_V1";
    unsafe { std::env::set_var(var, "ci-integration") };
    let fx = Factory::deterministic_from_env(var).unwrap();
    unsafe { std::env::remove_var(var) };
    assert!(matches!(fx.mode(), Mode::Deterministic { .. }));
}

#[test]
fn factory_deterministic_from_env_missing_var_is_err() {
    assert!(Factory::deterministic_from_env("USELESSKEY_DOES_NOT_EXIST_99").is_err());
}

#[test]
fn factory_clone_shares_cache() {
    let fx = Factory::random();
    let fx2 = fx.clone();
    // Both are usable; clone preserves mode.
    assert!(matches!(fx2.mode(), Mode::Random));
}

#[test]
fn seed_round_trips() {
    let seed = Seed::from_env_value("round-trip-v1").unwrap();
    let fx = Factory::deterministic(seed);
    assert!(matches!(fx.mode(), Mode::Deterministic { .. }));
}

#[test]
fn core_types_are_reexported() {
    // These must compile — they prove the re-exports exist.
    let _domain: uselesskey::ArtifactDomain = "test";
    let _version = uselesskey::DerivationVersion::V1;
    let _: fn() -> Result<(), uselesskey::Error> = || Ok(());
}

// ===========================================================================
// 2. RSA — full output format coverage
// ===========================================================================

#[cfg(feature = "rsa")]
mod rsa_formats {
    use super::*;

    fn kp() -> RsaKeyPair {
        testutil::fx().rsa("int-rsa-fmt", RsaSpec::rs256())
    }

    #[test]
    fn private_pem() {
        let pem = kp().private_key_pkcs8_pem().to_owned();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(pem.trim_end().ends_with("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn public_pem() {
        let pem = kp().public_key_spki_pem().to_owned();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.trim_end().ends_with("-----END PUBLIC KEY-----"));
    }

    #[test]
    fn private_der_is_valid_sequence() {
        let k = kp();
        let der = k.private_key_pkcs8_der();
        assert!(!der.is_empty());
        assert_eq!(der[0], 0x30, "PKCS#8 starts with ASN.1 SEQUENCE");
    }

    #[test]
    fn public_der_is_valid_sequence() {
        let k = kp();
        let der = k.public_key_spki_der();
        assert!(!der.is_empty());
        assert_eq!(der[0], 0x30, "SPKI starts with ASN.1 SEQUENCE");
    }

    #[test]
    fn private_and_public_der_differ() {
        let k = kp();
        assert_ne!(k.private_key_pkcs8_der(), k.public_key_spki_der());
    }

    #[test]
    fn tempfile_private_key() {
        let tmp = kp().write_private_key_pkcs8_pem().unwrap();
        assert!(tmp.path().exists());
        let content = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(content.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn tempfile_public_key() {
        let tmp = kp().write_public_key_spki_pem().unwrap();
        assert!(tmp.path().exists());
        let content = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(content.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn tempfile_cleaned_on_drop() {
        let path = {
            let tmp = kp().write_private_key_pkcs8_pem().unwrap();
            tmp.path().to_owned()
        };
        assert!(!path.exists(), "TempArtifact cleans up on drop");
    }
}

// ===========================================================================
// 3. ECDSA — P-256 and P-384
// ===========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_formats {
    use super::*;

    #[test]
    fn es256_all_formats() {
        let fx = testutil::fx();
        let kp = fx.ecdsa("int-ec256", EcdsaSpec::es256());

        assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(kp.public_key_spki_pem().contains("BEGIN PUBLIC KEY"));
        assert!(!kp.private_key_pkcs8_der().is_empty());
        assert!(!kp.public_key_spki_der().is_empty());
        assert_eq!(kp.private_key_pkcs8_der()[0], 0x30);
    }

    #[test]
    fn es384_all_formats() {
        let fx = testutil::fx();
        let kp = fx.ecdsa("int-ec384", EcdsaSpec::es384());

        assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(!kp.public_key_spki_der().is_empty());
    }

    #[test]
    fn es256_and_es384_differ() {
        let fx = det("int-ec-diff-v1");
        let p256 = fx.ecdsa("int-ec", EcdsaSpec::es256());
        let p384 = fx.ecdsa("int-ec", EcdsaSpec::es384());
        assert_ne!(p256.private_key_pkcs8_der(), p384.private_key_pkcs8_der());
    }

    #[test]
    fn tempfile_works() {
        let fx = testutil::fx();
        let kp = fx.ecdsa("int-ec-tmp", EcdsaSpec::es256());
        let tmp = kp.write_private_key_pkcs8_pem().unwrap();
        assert!(tmp.path().exists());
    }

    #[test]
    fn spec_accessor() {
        let fx = testutil::fx();
        let kp = fx.ecdsa("int-ec-spec", EcdsaSpec::es384());
        assert_eq!(kp.spec(), EcdsaSpec::es384());
    }
}

// ===========================================================================
// 4. Ed25519
// ===========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_formats {
    use super::*;

    #[test]
    fn all_formats() {
        let fx = testutil::fx();
        let kp = fx.ed25519("int-ed", Ed25519Spec::new());

        assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(kp.public_key_spki_pem().contains("BEGIN PUBLIC KEY"));
        assert!(!kp.private_key_pkcs8_der().is_empty());
        assert!(!kp.public_key_spki_der().is_empty());
    }

    #[test]
    fn tempfile_round_trip() {
        let fx = testutil::fx();
        let kp = fx.ed25519("int-ed-tmp", Ed25519Spec::new());

        let priv_tmp = kp.write_private_key_pkcs8_pem().unwrap();
        let pub_tmp = kp.write_public_key_spki_pem().unwrap();
        assert!(priv_tmp.path().exists());
        assert!(pub_tmp.path().exists());
    }
}

// ===========================================================================
// 5. HMAC — HS256, HS384, HS512
// ===========================================================================

#[cfg(feature = "hmac")]
mod hmac_tests {
    use super::*;

    #[test]
    fn hs256_byte_len() {
        let s = testutil::fx().hmac("int-hmac-256", HmacSpec::hs256());
        assert_eq!(s.secret_bytes().len(), 32);
    }

    #[test]
    fn hs384_byte_len() {
        let s = testutil::fx().hmac("int-hmac-384", HmacSpec::hs384());
        assert_eq!(s.secret_bytes().len(), 48);
    }

    #[test]
    fn hs512_byte_len() {
        let s = testutil::fx().hmac("int-hmac-512", HmacSpec::hs512());
        assert_eq!(s.secret_bytes().len(), 64);
    }

    #[test]
    fn different_specs_never_collide() {
        let fx = det("int-hmac-coll-v1");
        let a = fx.hmac("hmac", HmacSpec::hs256());
        let b = fx.hmac("hmac", HmacSpec::hs384());
        let c = fx.hmac("hmac", HmacSpec::hs512());
        assert_ne!(a.secret_bytes(), b.secret_bytes());
        assert_ne!(a.secret_bytes(), c.secret_bytes());
        assert_ne!(b.secret_bytes(), c.secret_bytes());
    }
}

// ===========================================================================
// 6. Token — API key, bearer, OAuth
// ===========================================================================

#[cfg(feature = "token")]
mod token_tests {
    use super::*;

    #[test]
    fn api_key_prefix_and_length() {
        let tok = testutil::fx().token("int-tok-api", TokenSpec::api_key());
        assert!(tok.value().starts_with("uk_test_"));
        let suffix = &tok.value()["uk_test_".len()..];
        assert_eq!(suffix.len(), 32);
        assert!(suffix.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn api_key_authorization_header() {
        let tok = testutil::fx().token("int-tok-api-hdr", TokenSpec::api_key());
        assert!(tok.authorization_header().starts_with("ApiKey "));
        assert!(tok.authorization_header().contains(tok.value()));
    }

    #[test]
    fn bearer_authorization_header() {
        let tok = testutil::fx().token("int-tok-bearer", TokenSpec::bearer());
        assert!(tok.authorization_header().starts_with("Bearer "));
        assert!(!tok.value().is_empty());
    }

    #[test]
    fn oauth_is_jwt_shaped() {
        let tok = testutil::fx().token("int-tok-oauth", TokenSpec::oauth_access_token());
        let parts: Vec<&str> = tok.value().split('.').collect();
        assert_eq!(parts.len(), 3, "OAuth token has 3 JWT segments");
        assert!(tok.authorization_header().starts_with("Bearer "));
    }

    #[test]
    fn different_specs_are_distinct() {
        let fx = det("int-tok-specs-v1");
        let api = fx.token("t", TokenSpec::api_key());
        let bearer = fx.token("t", TokenSpec::bearer());
        let oauth = fx.token("t", TokenSpec::oauth_access_token());
        assert_ne!(api.value(), bearer.value());
        assert_ne!(api.value(), oauth.value());
        assert_ne!(bearer.value(), oauth.value());
    }

    #[test]
    fn with_variant_produces_different_token() {
        let fx = det("int-tok-var-v1");
        let default = fx.token("tv", TokenSpec::api_key());
        let custom = fx.token_with_variant("tv", TokenSpec::api_key(), "v2");
        assert_ne!(default.value(), custom.value());
    }
}

// ===========================================================================
// 7. PGP key generation
// ===========================================================================

#[cfg(feature = "pgp")]
mod pgp_tests {
    use super::*;

    #[test]
    fn ed25519_armored() {
        let fx = testutil::fx();
        let kp = fx.pgp("int-pgp-ed", PgpSpec::ed25519());
        assert!(kp
            .private_key_armored()
            .contains("BEGIN PGP PRIVATE KEY BLOCK"));
        assert!(kp
            .public_key_armored()
            .contains("BEGIN PGP PUBLIC KEY BLOCK"));
    }

    #[test]
    fn binary_is_nonempty() {
        let fx = testutil::fx();
        let kp = fx.pgp("int-pgp-bin", PgpSpec::ed25519());
        assert!(!kp.private_key_binary().is_empty());
        assert!(!kp.public_key_binary().is_empty());
    }

    #[test]
    fn fingerprint_and_user_id() {
        let fx = testutil::fx();
        let kp = fx.pgp("int-pgp-meta", PgpSpec::ed25519());
        assert!(!kp.fingerprint().is_empty());
        assert!(!kp.user_id().is_empty());
    }

    #[test]
    fn tempfiles() {
        let fx = testutil::fx();
        let kp = fx.pgp("int-pgp-tmp", PgpSpec::ed25519());
        assert!(kp.write_private_key_armored().unwrap().path().exists());
        assert!(kp.write_public_key_armored().unwrap().path().exists());
    }

    #[test]
    fn corrupt_pem_bad_header() {
        let fx = testutil::fx();
        let kp = fx.pgp("int-pgp-neg", PgpSpec::ed25519());
        let bad = kp.private_key_armored_corrupt(CorruptPem::BadHeader);
        assert!(bad.contains("CORRUPTED"));
        assert!(!bad.contains("BEGIN PGP PRIVATE KEY BLOCK"));
    }

    #[test]
    fn truncated_binary() {
        let fx = testutil::fx();
        let kp = fx.pgp("int-pgp-trunc", PgpSpec::ed25519());
        let trunc = kp.private_key_binary_truncated(8);
        assert_eq!(trunc.len(), 8);
    }

    #[test]
    fn mismatched_public_key() {
        let fx = testutil::fx();
        let kp = fx.pgp("int-pgp-mm", PgpSpec::ed25519());
        let mm_bin = kp.mismatched_public_key_binary();
        assert_ne!(mm_bin.as_slice(), kp.public_key_binary());
        let mm_armor = kp.mismatched_public_key_armored();
        assert!(mm_armor.contains("BEGIN PGP PUBLIC KEY BLOCK"));
    }

    #[test]
    fn deterministic_corruption_stable() {
        let fx = testutil::fx();
        let kp = fx.pgp("int-pgp-det-c", PgpSpec::ed25519());
        let a = kp.private_key_armored_corrupt_deterministic("corrupt:pgp-v1");
        let b = kp.private_key_armored_corrupt_deterministic("corrupt:pgp-v1");
        assert_eq!(a, b);
        assert_ne!(a, kp.private_key_armored());
    }

    #[test]
    fn deterministic_across_factories() {
        let fx1 = det("int-pgp-det-v1");
        let fx2 = det("int-pgp-det-v1");
        let k1 = fx1.pgp("pgp-det", PgpSpec::ed25519());
        let k2 = fx2.pgp("pgp-det", PgpSpec::ed25519());
        assert_eq!(k1.private_key_binary(), k2.private_key_binary());
        assert_eq!(k1.fingerprint(), k2.fingerprint());
    }

    #[test]
    fn rsa_spec_works() {
        let fx = testutil::fx();
        let kp = fx.pgp("int-pgp-rsa", PgpSpec::Rsa2048);
        assert!(kp
            .private_key_armored()
            .contains("BEGIN PGP PRIVATE KEY BLOCK"));
    }

    #[test]
    fn debug_safety() {
        let fx = testutil::fx();
        let kp = fx.pgp("int-pgp-dbg", PgpSpec::ed25519());
        let dbg = format!("{kp:?}");
        assert!(dbg.contains("PgpKeyPair"));
        assert!(!dbg.contains("BEGIN PGP"));
    }

    #[test]
    fn cache_returns_same_pointer() {
        let fx = Factory::random();
        let k1 = fx.pgp("int-pgp-cache", PgpSpec::ed25519());
        let k2 = fx.pgp("int-pgp-cache", PgpSpec::ed25519());
        assert!(std::ptr::eq(
            k1.private_key_armored(),
            k2.private_key_armored()
        ));
    }

    #[test]
    fn different_labels_differ() {
        let fx = det("int-pgp-labels-v1");
        let a = fx.pgp("pgp-a", PgpSpec::ed25519());
        let b = fx.pgp("pgp-b", PgpSpec::ed25519());
        assert_ne!(a.private_key_binary(), b.private_key_binary());
    }
}

// ===========================================================================
// 8. JWK / JWKS building
// ===========================================================================

#[cfg(all(feature = "jwk", feature = "rsa"))]
mod jwk_rsa {
    use super::*;

    #[test]
    fn public_jwk_fields() {
        let kp = testutil::fx().rsa("int-jwk-rsa", RsaSpec::rs256());
        let v = kp.public_jwk().to_value();
        assert_eq!(v["kty"], "RSA");
        assert_eq!(v["alg"], "RS256");
        assert_eq!(v["use"], "sig");
        assert!(v["kid"].is_string());
        assert!(v["n"].is_string());
        assert!(v["e"].is_string());
    }

    #[test]
    fn private_jwk_fields() {
        let kp = testutil::fx().rsa("int-jwk-rsa-priv", RsaSpec::rs256());
        let v = kp.private_key_jwk_json();
        assert!(v["d"].is_string());
        assert!(v["p"].is_string());
        assert!(v["q"].is_string());
    }

    #[test]
    fn public_jwks_wraps_single_key() {
        let kp = testutil::fx().rsa("int-jwks-rsa", RsaSpec::rs256());
        let v = kp.public_jwks_json();
        let keys = v["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "RSA");
    }

    #[test]
    fn kid_is_nonempty_and_deterministic() {
        let fx1 = det("int-jwk-kid-v1");
        let fx2 = det("int-jwk-kid-v1");
        let kid1 = fx1.rsa("kid", RsaSpec::rs256()).kid();
        let kid2 = fx2.rsa("kid", RsaSpec::rs256()).kid();
        assert!(!kid1.is_empty());
        assert_eq!(kid1, kid2);
    }

    #[test]
    fn kid_differs_across_labels() {
        let fx = testutil::fx();
        let a = fx.rsa("kid-a", RsaSpec::rs256()).kid();
        let b = fx.rsa("kid-b", RsaSpec::rs256()).kid();
        assert_ne!(a, b);
    }
}

#[cfg(all(feature = "jwk", feature = "ecdsa"))]
mod jwk_ecdsa {
    use super::*;

    #[test]
    fn es256_jwk() {
        let kp = testutil::fx().ecdsa("int-jwk-ec256", EcdsaSpec::es256());
        let v = kp.public_jwk().to_value();
        assert_eq!(v["kty"], "EC");
        assert_eq!(v["crv"], "P-256");
        assert_eq!(v["alg"], "ES256");
        assert!(v["x"].is_string());
        assert!(v["y"].is_string());
    }

    #[test]
    fn es384_jwk_uses_p384() {
        let kp = testutil::fx().ecdsa("int-jwk-ec384", EcdsaSpec::es384());
        let v = kp.public_jwk().to_value();
        assert_eq!(v["crv"], "P-384");
        assert_eq!(v["alg"], "ES384");
    }

    #[test]
    fn ecdsa_private_jwk() {
        let kp = testutil::fx().ecdsa("int-jwk-ec-priv", EcdsaSpec::es256());
        let v = kp.private_key_jwk_json();
        assert!(v["d"].is_string());
    }

    #[test]
    fn ecdsa_jwks_wraps_single_key() {
        let kp = testutil::fx().ecdsa("int-jwks-ec", EcdsaSpec::es256());
        let v = kp.public_jwks_json();
        let keys = v["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "EC");
    }
}

#[cfg(all(feature = "jwk", feature = "ed25519"))]
mod jwk_ed25519 {
    use super::*;

    #[test]
    fn ed25519_jwk() {
        let kp = testutil::fx().ed25519("int-jwk-ed", Ed25519Spec::new());
        let v = kp.public_jwk().to_value();
        assert_eq!(v["kty"], "OKP");
        assert_eq!(v["crv"], "Ed25519");
        assert_eq!(v["alg"], "EdDSA");
        assert!(v["x"].is_string());
    }

    #[test]
    fn ed25519_private_jwk() {
        let kp = testutil::fx().ed25519("int-jwk-ed-priv", Ed25519Spec::new());
        let v = kp.private_key_jwk_json();
        assert!(v["d"].is_string());
    }

    #[test]
    fn ed25519_jwks_wraps_single_key() {
        let kp = testutil::fx().ed25519("int-jwks-ed", Ed25519Spec::new());
        let v = kp.public_jwks_json();
        let keys = v["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "OKP");
    }
}

#[cfg(all(feature = "jwk", feature = "hmac"))]
mod jwk_hmac {
    use super::*;

    #[test]
    fn hmac_jwk_fields() {
        let s = testutil::fx().hmac("int-jwk-hmac", HmacSpec::hs256());
        let v = s.jwk().to_value();
        assert_eq!(v["kty"], "oct");
        assert_eq!(v["alg"], "HS256");
        assert!(v["k"].is_string());
        assert!(v["kid"].is_string());
    }

    #[test]
    fn hmac_jwks_wraps_single_key() {
        let s = testutil::fx().hmac("int-jwks-hmac", HmacSpec::hs256());
        let v = s.jwks().to_value();
        let keys = v["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "oct");
    }

    #[test]
    fn hmac_kid_is_deterministic() {
        let fx1 = det("int-hmac-kid-v1");
        let fx2 = det("int-hmac-kid-v1");
        let kid1 = fx1.hmac("hk", HmacSpec::hs256()).kid();
        let kid2 = fx2.hmac("hk", HmacSpec::hs256()).kid();
        assert_eq!(kid1, kid2);
        assert!(!kid1.is_empty());
    }
}

#[cfg(all(
    feature = "jwk",
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519"
))]
mod jwks_builder {
    use super::*;
    use uselesskey::jwk::JwksBuilder;

    #[test]
    fn multi_key_jwks_via_add() {
        let fx = testutil::fx();
        let rsa = fx.rsa("int-builder", RsaSpec::rs256());
        let ec = fx.ecdsa("int-builder", EcdsaSpec::es256());
        let ed = fx.ed25519("int-builder", Ed25519Spec::new());

        let jwks = JwksBuilder::new()
            .add_public(rsa.public_jwk())
            .add_public(ec.public_jwk())
            .add_public(ed.public_jwk())
            .build();

        let keys = jwks.to_value()["keys"].as_array().unwrap().clone();
        assert_eq!(keys.len(), 3);

        let ktys: Vec<&str> = keys.iter().map(|k| k["kty"].as_str().unwrap()).collect();
        assert!(ktys.contains(&"RSA"));
        assert!(ktys.contains(&"EC"));
        assert!(ktys.contains(&"OKP"));
    }

    #[test]
    fn multi_key_jwks_via_push() {
        let fx = testutil::fx();
        let rsa = fx.rsa("int-push-builder", RsaSpec::rs256());
        let ec = fx.ecdsa("int-push-builder", EcdsaSpec::es256());

        let mut builder = JwksBuilder::new();
        builder.push_public(rsa.public_jwk());
        builder.push_public(ec.public_jwk());
        let jwks = builder.build();

        let keys = jwks.to_value()["keys"].as_array().unwrap().clone();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn builder_with_private_keys() {
        let fx = testutil::fx();
        let rsa = fx.rsa("int-priv-builder", RsaSpec::rs256());

        let jwks = JwksBuilder::new()
            .add_private(rsa.private_key_jwk())
            .build();

        let keys = jwks.to_value()["keys"].as_array().unwrap().clone();
        assert_eq!(keys.len(), 1);
        assert!(keys[0]["d"].is_string(), "private JWK has `d` parameter");
    }
}

// ===========================================================================
// 9. Negative fixtures
// ===========================================================================

#[cfg(feature = "rsa")]
mod rsa_negative {
    use super::*;

    fn kp() -> RsaKeyPair {
        testutil::fx().rsa("int-neg-rsa", RsaSpec::rs256())
    }

    #[test]
    fn corrupt_pem_all_variants() {
        let k = kp();
        let orig = k.private_key_pkcs8_pem();

        let variants = [
            k.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader),
            k.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter),
            k.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64),
            k.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 20 }),
            k.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(v, orig, "variant {i} must differ from original");
        }
    }

    #[test]
    fn truncated_der() {
        let k = kp();
        let trunc = k.private_key_pkcs8_der_truncated(10);
        assert_eq!(trunc.len(), 10);
        assert_eq!(&trunc[..], &k.private_key_pkcs8_der()[..10]);
    }

    #[test]
    fn truncated_der_zero() {
        assert!(kp().private_key_pkcs8_der_truncated(0).is_empty());
    }

    #[test]
    fn mismatch_spki_der() {
        let k = kp();
        let mm = k.mismatched_public_key_spki_der();
        assert_ne!(mm.as_slice(), k.public_key_spki_der());
        assert_eq!(mm[0], 0x30, "mismatched key is valid DER");
    }

    #[test]
    fn deterministic_pem_corruption_stable() {
        let k = kp();
        let a = k.private_key_pkcs8_pem_corrupt_deterministic("corrupt:int-v1");
        let b = k.private_key_pkcs8_pem_corrupt_deterministic("corrupt:int-v1");
        assert_eq!(a, b);
        assert_ne!(a, k.private_key_pkcs8_pem());
    }

    #[test]
    fn deterministic_der_corruption_stable() {
        let k = kp();
        let a = k.private_key_pkcs8_der_corrupt_deterministic("corrupt:int-der-v1");
        let b = k.private_key_pkcs8_der_corrupt_deterministic("corrupt:int-der-v1");
        assert_eq!(a, b);
        assert_ne!(a.as_slice(), k.private_key_pkcs8_der());
    }
}

#[cfg(feature = "ecdsa")]
mod ecdsa_negative {
    use super::*;

    #[test]
    fn mismatch_and_truncate() {
        let kp = testutil::fx().ecdsa("int-neg-ec", EcdsaSpec::es256());
        let mm = kp.mismatched_public_key_spki_der();
        assert_ne!(mm.as_slice(), kp.public_key_spki_der());

        let trunc = kp.private_key_pkcs8_der_truncated(8);
        assert_eq!(trunc.len(), 8);
    }
}

#[cfg(feature = "ed25519")]
mod ed25519_negative {
    use super::*;

    #[test]
    fn mismatch_and_truncate() {
        let kp = testutil::fx().ed25519("int-neg-ed", Ed25519Spec::new());
        let mm = kp.mismatched_public_key_spki_der();
        assert_ne!(mm.as_slice(), kp.public_key_spki_der());

        let trunc = kp.private_key_pkcs8_der_truncated(5);
        assert_eq!(trunc.len(), 5);
    }
}

// ===========================================================================
// 10. X.509 certificates
// ===========================================================================

#[cfg(feature = "x509")]
mod x509_tests {
    use uselesskey::{ChainSpec, X509FactoryExt, X509Negative, X509Spec};

    use super::*;

    #[test]
    fn self_signed_all_formats() {
        let fx = testutil::fx();
        let cert = fx.x509_self_signed("int-x509", X509Spec::self_signed("int.example.com"));

        assert!(cert.cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(cert.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(!cert.cert_der().is_empty());
        assert!(!cert.private_key_pkcs8_der().is_empty());
    }

    #[test]
    fn identity_pem_combines_cert_and_key() {
        let fx = testutil::fx();
        let cert = fx.x509_self_signed("int-x509-id", X509Spec::self_signed("id.example.com"));
        let id = cert.identity_pem();
        assert!(id.contains("BEGIN CERTIFICATE"));
        assert!(id.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn label_and_spec_accessors() {
        let fx = testutil::fx();
        let cert = fx.x509_self_signed("int-x509-acc", X509Spec::self_signed("acc.example.com"));
        assert_eq!(cert.label(), "int-x509-acc");
    }

    #[test]
    fn negative_via_enum() {
        let fx = testutil::fx();
        let cert = fx.x509_self_signed("int-x509-neg", X509Spec::self_signed("neg.example.com"));

        let expired = cert.negative(X509Negative::Expired);
        assert_ne!(cert.cert_der(), expired.cert_der());

        let nyv = cert.negative(X509Negative::NotYetValid);
        assert_ne!(cert.cert_der(), nyv.cert_der());

        let wku = cert.negative(X509Negative::WrongKeyUsage);
        assert_ne!(cert.cert_der(), wku.cert_der());
    }

    #[test]
    fn convenience_methods_match_enum() {
        let fx = testutil::fx();
        let cert = fx.x509_self_signed("int-x509-conv", X509Spec::self_signed("conv.example.com"));
        // Convenience methods should produce valid outputs.
        assert!(cert.expired().cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(cert
            .not_yet_valid()
            .cert_pem()
            .contains("BEGIN CERTIFICATE"));
        assert!(cert.wrong_key_usage().spec().is_ca);
    }

    #[test]
    fn corrupt_cert_pem_and_der() {
        let fx = testutil::fx();
        let cert = fx.x509_self_signed("int-x509-cpem", X509Spec::self_signed("cpem.example.com"));

        let bad = cert.corrupt_cert_pem(CorruptPem::BadHeader);
        assert!(bad.contains("CORRUPTED"));

        let trunc = cert.truncate_cert_der(10);
        assert_eq!(trunc.len(), 10);
    }

    #[test]
    fn self_signed_tempfiles() {
        let fx = testutil::fx();
        let cert = fx.x509_self_signed("int-x509-tmp", X509Spec::self_signed("tmp.example.com"));

        assert!(cert.write_cert_pem().unwrap().path().exists());
        assert!(cert.write_cert_der().unwrap().path().exists());
        assert!(cert.write_private_key_pem().unwrap().path().exists());
        assert!(cert.write_identity_pem().unwrap().path().exists());
    }

    #[test]
    fn chain_three_level_structure() {
        let fx = testutil::fx();
        let chain = fx.x509_chain("int-chain", ChainSpec::new("chain.example.com"));

        assert_eq!(chain.chain_pem().matches("BEGIN CERTIFICATE").count(), 2);
        assert_eq!(
            chain.full_chain_pem().matches("BEGIN CERTIFICATE").count(),
            3
        );

        assert!(!chain.root_cert_der().is_empty());
        assert!(!chain.intermediate_cert_der().is_empty());
        assert!(!chain.leaf_cert_der().is_empty());
        assert!(chain
            .root_private_key_pkcs8_pem()
            .contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn chain_label_accessor() {
        let fx = testutil::fx();
        let chain = fx.x509_chain("int-chain-lbl", ChainSpec::new("lbl.example.com"));
        assert_eq!(chain.label(), "int-chain-lbl");
    }

    #[test]
    fn chain_negative_variants() {
        let fx = testutil::fx();
        let chain = fx.x509_chain("int-chain-neg", ChainSpec::new("neg.example.com"));

        let exp_leaf = chain.expired_leaf();
        assert_ne!(chain.leaf_cert_der(), exp_leaf.leaf_cert_der());

        let exp_inter = chain.expired_intermediate();
        assert_ne!(
            chain.intermediate_cert_der(),
            exp_inter.intermediate_cert_der()
        );

        let mm = chain.hostname_mismatch("wrong.example.com");
        assert_ne!(chain.leaf_cert_der(), mm.leaf_cert_der());

        let uca = chain.unknown_ca();
        assert_ne!(chain.root_cert_der(), uca.root_cert_der());

        let rev = chain.revoked_leaf();
        assert!(rev.crl_der().is_some());
        assert!(rev.crl_pem().unwrap().contains("BEGIN X509 CRL"));
    }

    #[test]
    fn chain_good_has_no_crl() {
        let fx = testutil::fx();
        let chain = fx.x509_chain("int-chain-crl", ChainSpec::new("crl.example.com"));
        assert!(chain.crl_der().is_none());
        assert!(chain.crl_pem().is_none());
    }

    #[test]
    fn chain_tempfiles() {
        let fx = testutil::fx();
        let chain = fx.x509_chain("int-chain-tmp", ChainSpec::new("tmp.example.com"));

        assert!(chain.write_leaf_cert_pem().unwrap().path().exists());
        assert!(chain.write_leaf_cert_der().unwrap().path().exists());
        assert!(chain.write_leaf_private_key_pem().unwrap().path().exists());
        assert!(chain.write_chain_pem().unwrap().path().exists());
        assert!(chain.write_full_chain_pem().unwrap().path().exists());
        assert!(chain.write_root_cert_pem().unwrap().path().exists());
    }
}

// ===========================================================================
// 11. Determinism — same seed + label → same output
// ===========================================================================

mod determinism {
    use super::*;

    #[test]
    #[cfg(feature = "rsa")]
    fn rsa_same_seed_same_output() {
        let k1 = det("int-det-v1").rsa("d", RsaSpec::rs256());
        let k2 = det("int-det-v1").rsa("d", RsaSpec::rs256());
        assert_eq!(k1.private_key_pkcs8_pem(), k2.private_key_pkcs8_pem());
        assert_eq!(k1.private_key_pkcs8_der(), k2.private_key_pkcs8_der());
        assert_eq!(k1.public_key_spki_pem(), k2.public_key_spki_pem());
        assert_eq!(k1.public_key_spki_der(), k2.public_key_spki_der());
    }

    #[test]
    #[cfg(feature = "ecdsa")]
    fn ecdsa_same_seed_same_output() {
        let k1 = det("int-det-v1").ecdsa("d", EcdsaSpec::es256());
        let k2 = det("int-det-v1").ecdsa("d", EcdsaSpec::es256());
        assert_eq!(k1.private_key_pkcs8_der(), k2.private_key_pkcs8_der());
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn ed25519_same_seed_same_output() {
        let k1 = det("int-det-v1").ed25519("d", Ed25519Spec::new());
        let k2 = det("int-det-v1").ed25519("d", Ed25519Spec::new());
        assert_eq!(k1.private_key_pkcs8_der(), k2.private_key_pkcs8_der());
    }

    #[test]
    #[cfg(feature = "hmac")]
    fn hmac_same_seed_same_output() {
        let s1 = det("int-det-v1").hmac("d", HmacSpec::hs512());
        let s2 = det("int-det-v1").hmac("d", HmacSpec::hs512());
        assert_eq!(s1.secret_bytes(), s2.secret_bytes());
    }

    #[test]
    #[cfg(feature = "token")]
    fn token_same_seed_same_output() {
        let t1 = det("int-det-v1").token("d", TokenSpec::bearer());
        let t2 = det("int-det-v1").token("d", TokenSpec::bearer());
        assert_eq!(t1.value(), t2.value());
    }

    #[test]
    #[cfg(feature = "x509")]
    fn x509_same_seed_same_output() {
        use uselesskey::{X509FactoryExt, X509Spec};
        let c1 = det("int-det-v1").x509_self_signed("d", X509Spec::self_signed("d.example.com"));
        let c2 = det("int-det-v1").x509_self_signed("d", X509Spec::self_signed("d.example.com"));
        assert_eq!(c1.cert_pem(), c2.cert_pem());
    }

    #[test]
    #[cfg(feature = "rsa")]
    fn different_seeds_different_output() {
        let k1 = det("int-seed-a").rsa("s", RsaSpec::rs256());
        let k2 = det("int-seed-b").rsa("s", RsaSpec::rs256());
        assert_ne!(k1.private_key_pkcs8_der(), k2.private_key_pkcs8_der());
    }

    #[test]
    #[cfg(all(feature = "rsa", feature = "ecdsa", feature = "ed25519"))]
    fn order_independent_across_key_types() {
        let fx_abc = det("int-order-v1");
        let rsa_a = fx_abc.rsa("o", RsaSpec::rs256());
        let ec_a = fx_abc.ecdsa("o", EcdsaSpec::es256());
        let ed_a = fx_abc.ed25519("o", Ed25519Spec::new());

        let fx_cba = det("int-order-v1");
        let ed_b = fx_cba.ed25519("o", Ed25519Spec::new());
        let ec_b = fx_cba.ecdsa("o", EcdsaSpec::es256());
        let rsa_b = fx_cba.rsa("o", RsaSpec::rs256());

        assert_eq!(rsa_a.private_key_pkcs8_der(), rsa_b.private_key_pkcs8_der());
        assert_eq!(ec_a.private_key_pkcs8_der(), ec_b.private_key_pkcs8_der());
        assert_eq!(ed_a.private_key_pkcs8_der(), ed_b.private_key_pkcs8_der());
    }

    #[test]
    #[cfg(feature = "rsa")]
    fn determinism_survives_cache_clear() {
        let fx = det("int-clear-v1");
        let pem1 = fx
            .rsa("cl", RsaSpec::rs256())
            .private_key_pkcs8_pem()
            .to_owned();
        fx.clear_cache();
        let pem2 = fx
            .rsa("cl", RsaSpec::rs256())
            .private_key_pkcs8_pem()
            .to_owned();
        assert_eq!(pem1, pem2);
    }
}

// ===========================================================================
// 12. Cache — same identity returns same Arc/pointer
// ===========================================================================

mod cache {
    use super::*;

    #[test]
    #[cfg(feature = "rsa")]
    fn rsa_ptr_eq() {
        let fx = Factory::random();
        let k1 = fx.rsa("int-cache-rsa", RsaSpec::rs256());
        let k2 = fx.rsa("int-cache-rsa", RsaSpec::rs256());
        assert!(std::ptr::eq(
            k1.private_key_pkcs8_pem(),
            k2.private_key_pkcs8_pem()
        ));
    }

    #[test]
    #[cfg(feature = "ecdsa")]
    fn ecdsa_ptr_eq() {
        let fx = Factory::random();
        let k1 = fx.ecdsa("int-cache-ec", EcdsaSpec::es256());
        let k2 = fx.ecdsa("int-cache-ec", EcdsaSpec::es256());
        assert!(std::ptr::eq(
            k1.private_key_pkcs8_pem(),
            k2.private_key_pkcs8_pem()
        ));
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn ed25519_ptr_eq() {
        let fx = Factory::random();
        let k1 = fx.ed25519("int-cache-ed", Ed25519Spec::new());
        let k2 = fx.ed25519("int-cache-ed", Ed25519Spec::new());
        assert!(std::ptr::eq(
            k1.private_key_pkcs8_pem(),
            k2.private_key_pkcs8_pem()
        ));
    }

    #[test]
    #[cfg(feature = "hmac")]
    fn hmac_ptr_eq() {
        let fx = Factory::random();
        let s1 = fx.hmac("int-cache-hmac", HmacSpec::hs256());
        let s2 = fx.hmac("int-cache-hmac", HmacSpec::hs256());
        assert!(std::ptr::eq(s1.secret_bytes(), s2.secret_bytes()));
    }

    #[test]
    #[cfg(feature = "token")]
    fn token_ptr_eq() {
        let fx = Factory::random();
        let t1 = fx.token("int-cache-tok", TokenSpec::bearer());
        let t2 = fx.token("int-cache-tok", TokenSpec::bearer());
        assert!(std::ptr::eq(t1.value(), t2.value()));
    }

    #[test]
    #[cfg(feature = "rsa")]
    fn cache_invalidated_by_clear() {
        let fx = Factory::random();
        let pem1 = fx
            .rsa("int-cache-cl", RsaSpec::rs256())
            .private_key_pkcs8_pem() as *const str;
        fx.clear_cache();
        let pem2 = fx
            .rsa("int-cache-cl", RsaSpec::rs256())
            .private_key_pkcs8_pem() as *const str;
        assert!(!std::ptr::eq(pem1, pem2));
    }
}

// ===========================================================================
// 13. Different labels → different keys
// ===========================================================================

mod label_isolation {
    use super::*;

    #[test]
    #[cfg(feature = "rsa")]
    fn rsa_different_labels() {
        let fx = det("int-label-v1");
        let a = fx.rsa("alpha", RsaSpec::rs256());
        let b = fx.rsa("beta", RsaSpec::rs256());
        assert_ne!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
        assert_ne!(a.public_key_spki_der(), b.public_key_spki_der());
    }

    #[test]
    #[cfg(feature = "ecdsa")]
    fn ecdsa_different_labels() {
        let fx = det("int-label-v1");
        let a = fx.ecdsa("alpha", EcdsaSpec::es256());
        let b = fx.ecdsa("beta", EcdsaSpec::es256());
        assert_ne!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn ed25519_different_labels() {
        let fx = det("int-label-v1");
        let a = fx.ed25519("alpha", Ed25519Spec::new());
        let b = fx.ed25519("beta", Ed25519Spec::new());
        assert_ne!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
    }

    #[test]
    #[cfg(feature = "hmac")]
    fn hmac_different_labels() {
        let fx = det("int-label-v1");
        let a = fx.hmac("alpha", HmacSpec::hs256());
        let b = fx.hmac("beta", HmacSpec::hs256());
        assert_ne!(a.secret_bytes(), b.secret_bytes());
    }

    #[test]
    #[cfg(feature = "token")]
    fn token_different_labels() {
        let fx = det("int-label-v1");
        let a = fx.token("alpha", TokenSpec::api_key());
        let b = fx.token("beta", TokenSpec::api_key());
        assert_ne!(a.value(), b.value());
    }
}

// ===========================================================================
// 14. Debug safety — no key material in Debug output
// ===========================================================================

mod debug_safety {
    use super::*;

    #[test]
    #[cfg(feature = "rsa")]
    fn rsa() {
        let kp = testutil::fx().rsa("int-dbg-rsa", RsaSpec::rs256());
        let dbg = format!("{kp:?}");
        assert!(dbg.contains("RsaKeyPair"));
        assert!(!dbg.contains("BEGIN"));
        assert!(!dbg.contains("PRIVATE KEY"));
    }

    #[test]
    #[cfg(feature = "ecdsa")]
    fn ecdsa() {
        let kp = testutil::fx().ecdsa("int-dbg-ec", EcdsaSpec::es256());
        let dbg = format!("{kp:?}");
        assert!(dbg.contains("EcdsaKeyPair"));
        assert!(!dbg.contains("BEGIN"));
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn ed25519() {
        let kp = testutil::fx().ed25519("int-dbg-ed", Ed25519Spec::new());
        let dbg = format!("{kp:?}");
        assert!(dbg.contains("Ed25519KeyPair"));
        assert!(!dbg.contains("BEGIN"));
    }

    #[test]
    #[cfg(feature = "hmac")]
    fn hmac() {
        let s = testutil::fx().hmac("int-dbg-hmac", HmacSpec::hs256());
        let dbg = format!("{s:?}");
        assert!(dbg.contains("HmacSecret"));
    }

    #[test]
    #[cfg(feature = "token")]
    fn token() {
        let tok = testutil::fx().token("int-dbg-tok", TokenSpec::api_key());
        let dbg = format!("{tok:?}");
        assert!(dbg.contains("TokenFixture"));
        assert!(!dbg.contains(tok.value()));
    }

    #[test]
    #[cfg(feature = "x509")]
    fn x509() {
        use uselesskey::{X509FactoryExt, X509Spec};
        let cert = testutil::fx()
            .x509_self_signed("int-dbg-x509", X509Spec::self_signed("dbg.example.com"));
        let dbg = format!("{cert:?}");
        assert!(dbg.contains("X509Cert"));
        assert!(!dbg.contains("BEGIN"));
    }

    #[test]
    #[cfg(feature = "pgp")]
    fn pgp() {
        let kp = testutil::fx().pgp("int-dbg-pgp", PgpSpec::ed25519());
        let dbg = format!("{kp:?}");
        assert!(dbg.contains("PgpKeyPair"));
        assert!(!dbg.contains("BEGIN PGP"));
    }
}

// ===========================================================================
// 15. Thread safety — Factory is Send + Sync
// ===========================================================================

mod thread_safety {
    use super::*;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn factory_is_send_sync() {
        assert_send_sync::<Factory>();
    }

    #[test]
    #[cfg(feature = "rsa")]
    fn concurrent_rsa_generation() {
        let fx = Factory::random();
        std::thread::scope(|s| {
            let handles: Vec<_> = (0..4)
                .map(|i| {
                    let fx = fx.clone();
                    s.spawn(move || {
                        let label = format!("int-thread-{i}");
                        let kp = fx.rsa(&label, RsaSpec::rs256());
                        assert!(!kp.private_key_pkcs8_der().is_empty());
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }
        });
    }
}

// ===========================================================================
// 16. Prelude completeness
// ===========================================================================

#[test]
fn prelude_provides_factory_and_mode() {
    // These compile thanks to `use uselesskey::prelude::*` at the top.
    let fx = Factory::random();
    let _ = fx.mode();
    let _ = Seed::from_env_value("prelude-test").unwrap();
    fn _assert_type(_: &TempArtifact) {} // type exists
}

#[test]
fn prelude_provides_corrupt_pem() {
    let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
    let bad = corrupt_pem(pem, CorruptPem::BadHeader);
    assert!(bad.contains("CORRUPTED"));
}

// ===========================================================================
// 17. Cross-type independence — same label, different domains
// ===========================================================================

#[test]
#[cfg(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "hmac"
))]
fn same_label_different_types_independent() {
    let fx = det("int-cross-v1");
    let rsa = fx.rsa("svc", RsaSpec::rs256());
    let ec = fx.ecdsa("svc", EcdsaSpec::es256());
    let ed = fx.ed25519("svc", Ed25519Spec::new());
    let hmac = fx.hmac("svc", HmacSpec::hs256());

    // All produce non-empty, distinct outputs
    assert_ne!(rsa.private_key_pkcs8_der(), ec.private_key_pkcs8_der());
    assert_ne!(rsa.private_key_pkcs8_der(), ed.private_key_pkcs8_der());
    assert_ne!(ec.private_key_pkcs8_der(), ed.private_key_pkcs8_der());
    assert!(!hmac.secret_bytes().is_empty());
}

// ===========================================================================
// 18. Negative module re-export
// ===========================================================================

#[test]
fn negative_module_exports_corrupt_pem_enum() {
    use uselesskey::negative::CorruptPem;
    let _ = CorruptPem::BadHeader;
    let _ = CorruptPem::BadFooter;
    let _ = CorruptPem::BadBase64;
    let _ = CorruptPem::Truncate { bytes: 10 };
    let _ = CorruptPem::ExtraBlankLine;
}

#[test]
fn negative_module_exports_corrupt_pem_fn() {
    use uselesskey::negative::corrupt_pem;
    let pem = "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n";
    let bad = corrupt_pem(pem, uselesskey::negative::CorruptPem::BadBase64);
    assert!(bad.contains("THIS_IS_NOT_BASE64"));
}
