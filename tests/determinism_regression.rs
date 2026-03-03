//! Comprehensive determinism regression test suite.
//!
//! This is the most critical test suite for the project. Deterministic
//! derivation is the core contract: `seed + artifact_id → derived_seed → artifact`.
//! Every assertion here acts as a canary — if any snapshot changes, it signals
//! a derivation-stability break that must be reviewed before merge.
//!
//! Tests use `insta` snapshots to lock down metadata (lengths, PEM headers,
//! KIDs, algorithm names) while redacting actual key material.

#![cfg(feature = "determinism-regression")]

use uselesskey::jwk::JwksBuilder;
use uselesskey::prelude::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SEED_BYTES: [u8; 32] = [0xDE; 32];

fn fx() -> Factory {
    Factory::deterministic(Seed::new(SEED_BYTES))
}

/// Extract just the first line (PEM header) from a PEM string.
fn pem_header(pem: &str) -> &str {
    pem.lines().next().unwrap_or("")
}

// =========================================================================
// 1. Seed Stability — fixed seed → known metadata
// =========================================================================

#[test]
fn seed_stability_rsa_2048() {
    let kp = fx().rsa("regression-rsa2048", RsaSpec::rs256());
    insta::assert_yaml_snapshot!(
        "rsa2048_metadata",
        insta::internals::Content::Map(vec![
            (
                insta::internals::Content::from("private_der_len"),
                insta::internals::Content::from(kp.private_key_pkcs8_der().len() as u64)
            ),
            (
                insta::internals::Content::from("public_der_len"),
                insta::internals::Content::from(kp.public_key_spki_der().len() as u64)
            ),
            (
                insta::internals::Content::from("pem_header"),
                insta::internals::Content::from(pem_header(kp.private_key_pkcs8_pem()))
            ),
            (
                insta::internals::Content::from("pub_pem_header"),
                insta::internals::Content::from(pem_header(kp.public_key_spki_pem()))
            ),
        ])
    );
}

#[test]
fn seed_stability_rsa_4096() {
    let kp = fx().rsa("regression-rsa4096", RsaSpec::new(4096));
    insta::assert_yaml_snapshot!(
        "rsa4096_metadata",
        insta::internals::Content::Map(vec![
            (
                insta::internals::Content::from("private_der_len"),
                insta::internals::Content::from(kp.private_key_pkcs8_der().len() as u64)
            ),
            (
                insta::internals::Content::from("public_der_len"),
                insta::internals::Content::from(kp.public_key_spki_der().len() as u64)
            ),
            (
                insta::internals::Content::from("pem_header"),
                insta::internals::Content::from(pem_header(kp.private_key_pkcs8_pem()))
            ),
            (
                insta::internals::Content::from("pub_pem_header"),
                insta::internals::Content::from(pem_header(kp.public_key_spki_pem()))
            ),
        ])
    );
}

#[test]
fn seed_stability_ecdsa_p256() {
    let kp = fx().ecdsa("regression-p256", EcdsaSpec::es256());
    insta::assert_yaml_snapshot!(
        "ecdsa_p256_metadata",
        insta::internals::Content::Map(vec![
            (
                insta::internals::Content::from("private_der_len"),
                insta::internals::Content::from(kp.private_key_pkcs8_der().len() as u64)
            ),
            (
                insta::internals::Content::from("public_der_len"),
                insta::internals::Content::from(kp.public_key_spki_der().len() as u64)
            ),
            (
                insta::internals::Content::from("pem_header"),
                insta::internals::Content::from(pem_header(kp.private_key_pkcs8_pem()))
            ),
            (
                insta::internals::Content::from("pub_pem_header"),
                insta::internals::Content::from(pem_header(kp.public_key_spki_pem()))
            ),
        ])
    );
}

#[test]
fn seed_stability_ecdsa_p384() {
    let kp = fx().ecdsa("regression-p384", EcdsaSpec::es384());
    insta::assert_yaml_snapshot!(
        "ecdsa_p384_metadata",
        insta::internals::Content::Map(vec![
            (
                insta::internals::Content::from("private_der_len"),
                insta::internals::Content::from(kp.private_key_pkcs8_der().len() as u64)
            ),
            (
                insta::internals::Content::from("public_der_len"),
                insta::internals::Content::from(kp.public_key_spki_der().len() as u64)
            ),
            (
                insta::internals::Content::from("pem_header"),
                insta::internals::Content::from(pem_header(kp.private_key_pkcs8_pem()))
            ),
            (
                insta::internals::Content::from("pub_pem_header"),
                insta::internals::Content::from(pem_header(kp.public_key_spki_pem()))
            ),
        ])
    );
}

#[test]
fn seed_stability_ed25519() {
    let kp = fx().ed25519("regression-ed25519", Ed25519Spec::new());
    insta::assert_yaml_snapshot!(
        "ed25519_metadata",
        insta::internals::Content::Map(vec![
            (
                insta::internals::Content::from("private_der_len"),
                insta::internals::Content::from(kp.private_key_pkcs8_der().len() as u64)
            ),
            (
                insta::internals::Content::from("public_der_len"),
                insta::internals::Content::from(kp.public_key_spki_der().len() as u64)
            ),
            (
                insta::internals::Content::from("pem_header"),
                insta::internals::Content::from(pem_header(kp.private_key_pkcs8_pem()))
            ),
            (
                insta::internals::Content::from("pub_pem_header"),
                insta::internals::Content::from(pem_header(kp.public_key_spki_pem()))
            ),
        ])
    );
}

#[test]
fn seed_stability_hmac_hs256() {
    let secret = fx().hmac("regression-hs256", HmacSpec::hs256());
    insta::assert_yaml_snapshot!(
        "hmac_hs256_metadata",
        insta::internals::Content::Map(vec![(
            insta::internals::Content::from("secret_len"),
            insta::internals::Content::from(secret.secret_bytes().len() as u64)
        ),])
    );
}

#[test]
fn seed_stability_hmac_hs384() {
    let secret = fx().hmac("regression-hs384", HmacSpec::hs384());
    insta::assert_yaml_snapshot!(
        "hmac_hs384_metadata",
        insta::internals::Content::Map(vec![(
            insta::internals::Content::from("secret_len"),
            insta::internals::Content::from(secret.secret_bytes().len() as u64)
        ),])
    );
}

#[test]
fn seed_stability_hmac_hs512() {
    let secret = fx().hmac("regression-hs512", HmacSpec::hs512());
    insta::assert_yaml_snapshot!(
        "hmac_hs512_metadata",
        insta::internals::Content::Map(vec![(
            insta::internals::Content::from("secret_len"),
            insta::internals::Content::from(secret.secret_bytes().len() as u64)
        ),])
    );
}

#[test]
fn seed_stability_token_api_key() {
    let tok = fx().token("regression-apikey", TokenSpec::api_key());
    insta::assert_yaml_snapshot!(
        "token_api_key_metadata",
        insta::internals::Content::Map(vec![
            (
                insta::internals::Content::from("value_len"),
                insta::internals::Content::from(tok.value().len() as u64)
            ),
            (
                insta::internals::Content::from("starts_with"),
                insta::internals::Content::from(tok.value().starts_with("uk_test_"))
            ),
        ])
    );
}

#[test]
fn seed_stability_token_bearer() {
    let tok = fx().token("regression-bearer", TokenSpec::bearer());
    insta::assert_yaml_snapshot!(
        "token_bearer_metadata",
        insta::internals::Content::Map(vec![
            (
                insta::internals::Content::from("value_len"),
                insta::internals::Content::from(tok.value().len() as u64)
            ),
            (
                insta::internals::Content::from("is_nonempty"),
                insta::internals::Content::from(!tok.value().is_empty())
            ),
        ])
    );
}

#[test]
fn seed_stability_token_oauth() {
    let tok = fx().token("regression-oauth", TokenSpec::oauth_access_token());
    let segments = tok.value().split('.').count();
    insta::assert_yaml_snapshot!(
        "token_oauth_metadata",
        insta::internals::Content::Map(vec![
            (
                insta::internals::Content::from("segment_count"),
                insta::internals::Content::from(segments as u64)
            ),
            (
                insta::internals::Content::from("value_len"),
                insta::internals::Content::from(tok.value().len() as u64)
            ),
        ])
    );
}

// =========================================================================
// 2. Order Independence
// =========================================================================

#[test]
fn order_independence_asymmetric_keys() {
    let fx1 = fx();
    let rsa_a = fx1.rsa("oi-rsa", RsaSpec::rs256());
    let ec_a = fx1.ecdsa("oi-ec", EcdsaSpec::es256());
    let ed_a = fx1.ed25519("oi-ed", Ed25519Spec::new());

    // Reversed order
    let fx2 = fx();
    let ed_b = fx2.ed25519("oi-ed", Ed25519Spec::new());
    let ec_b = fx2.ecdsa("oi-ec", EcdsaSpec::es256());
    let rsa_b = fx2.rsa("oi-rsa", RsaSpec::rs256());

    assert_eq!(rsa_a.private_key_pkcs8_der(), rsa_b.private_key_pkcs8_der());
    assert_eq!(ec_a.private_key_pkcs8_der(), ec_b.private_key_pkcs8_der());
    assert_eq!(ed_a.private_key_pkcs8_der(), ed_b.private_key_pkcs8_der());
}

#[test]
fn order_independence_hmac() {
    let fx1 = fx();
    let h256_a = fx1.hmac("oi-h256", HmacSpec::hs256());
    let h512_a = fx1.hmac("oi-h512", HmacSpec::hs512());

    let fx2 = fx();
    let h512_b = fx2.hmac("oi-h512", HmacSpec::hs512());
    let h256_b = fx2.hmac("oi-h256", HmacSpec::hs256());

    assert_eq!(h256_a.secret_bytes(), h256_b.secret_bytes());
    assert_eq!(h512_a.secret_bytes(), h512_b.secret_bytes());
}

#[test]
fn order_independence_tokens() {
    let fx1 = fx();
    let api_a = fx1.token("oi-api", TokenSpec::api_key());
    let bearer_a = fx1.token("oi-bearer", TokenSpec::bearer());
    let oauth_a = fx1.token("oi-oauth", TokenSpec::oauth_access_token());

    let fx2 = fx();
    let oauth_b = fx2.token("oi-oauth", TokenSpec::oauth_access_token());
    let api_b = fx2.token("oi-api", TokenSpec::api_key());
    let bearer_b = fx2.token("oi-bearer", TokenSpec::bearer());

    assert_eq!(api_a.value(), api_b.value());
    assert_eq!(bearer_a.value(), bearer_b.value());
    assert_eq!(oauth_a.value(), oauth_b.value());
}

#[test]
fn order_independence_mixed_key_types() {
    let fx1 = fx();
    let rsa1 = fx1.rsa("oi-mix-rsa", RsaSpec::rs256());
    let hmac1 = fx1.hmac("oi-mix-hmac", HmacSpec::hs256());
    let tok1 = fx1.token("oi-mix-tok", TokenSpec::bearer());
    let cert1 = fx1.x509_self_signed("oi-mix-x509", X509Spec::self_signed("test.local"));

    let fx2 = fx();
    let cert2 = fx2.x509_self_signed("oi-mix-x509", X509Spec::self_signed("test.local"));
    let tok2 = fx2.token("oi-mix-tok", TokenSpec::bearer());
    let rsa2 = fx2.rsa("oi-mix-rsa", RsaSpec::rs256());
    let hmac2 = fx2.hmac("oi-mix-hmac", HmacSpec::hs256());

    assert_eq!(rsa1.private_key_pkcs8_der(), rsa2.private_key_pkcs8_der());
    assert_eq!(hmac1.secret_bytes(), hmac2.secret_bytes());
    assert_eq!(tok1.value(), tok2.value());
    assert_eq!(cert1.cert_der(), cert2.cert_der());
}

// =========================================================================
// 3. Cross-Factory Consistency
// =========================================================================

#[test]
fn cross_factory_rsa() {
    let results: Vec<_> = (0..3)
        .map(|_| {
            fx().rsa("cf-rsa", RsaSpec::rs256())
                .private_key_pkcs8_der()
                .to_vec()
        })
        .collect();
    assert_eq!(results[0], results[1]);
    assert_eq!(results[1], results[2]);
}

#[test]
fn cross_factory_ecdsa() {
    let results: Vec<_> = (0..3)
        .map(|_| {
            fx().ecdsa("cf-ec", EcdsaSpec::es256())
                .private_key_pkcs8_der()
                .to_vec()
        })
        .collect();
    assert_eq!(results[0], results[1]);
    assert_eq!(results[1], results[2]);
}

#[test]
fn cross_factory_ed25519() {
    let results: Vec<_> = (0..3)
        .map(|_| {
            fx().ed25519("cf-ed", Ed25519Spec::new())
                .private_key_pkcs8_der()
                .to_vec()
        })
        .collect();
    assert_eq!(results[0], results[1]);
    assert_eq!(results[1], results[2]);
}

#[test]
fn cross_factory_hmac() {
    let results: Vec<_> = (0..3)
        .map(|_| {
            fx().hmac("cf-hmac", HmacSpec::hs256())
                .secret_bytes()
                .to_vec()
        })
        .collect();
    assert_eq!(results[0], results[1]);
    assert_eq!(results[1], results[2]);
}

#[test]
fn cross_factory_token() {
    let results: Vec<_> = (0..3)
        .map(|_| {
            fx().token("cf-tok", TokenSpec::api_key())
                .value()
                .to_string()
        })
        .collect();
    assert_eq!(results[0], results[1]);
    assert_eq!(results[1], results[2]);
}

#[test]
fn cross_factory_x509() {
    let results: Vec<_> = (0..3)
        .map(|_| {
            fx().x509_self_signed("cf-x509", X509Spec::self_signed("cf.local"))
                .cert_der()
                .to_vec()
        })
        .collect();
    assert_eq!(results[0], results[1]);
    assert_eq!(results[1], results[2]);
}

// =========================================================================
// 4. KID Determinism
// =========================================================================

#[test]
fn kid_determinism_rsa() {
    let kid1 = fx().rsa("kid-rsa", RsaSpec::rs256()).kid();
    let kid2 = fx().rsa("kid-rsa", RsaSpec::rs256()).kid();
    assert_eq!(kid1, kid2);
    insta::assert_yaml_snapshot!("kid_rsa", kid1);
}

#[test]
fn kid_determinism_ecdsa() {
    let kid1 = fx().ecdsa("kid-ec", EcdsaSpec::es256()).kid();
    let kid2 = fx().ecdsa("kid-ec", EcdsaSpec::es256()).kid();
    assert_eq!(kid1, kid2);
    insta::assert_yaml_snapshot!("kid_ecdsa", kid1);
}

#[test]
fn kid_determinism_ed25519() {
    let kid1 = fx().ed25519("kid-ed", Ed25519Spec::new()).kid();
    let kid2 = fx().ed25519("kid-ed", Ed25519Spec::new()).kid();
    assert_eq!(kid1, kid2);
    insta::assert_yaml_snapshot!("kid_ed25519", kid1);
}

#[test]
fn kid_determinism_hmac() {
    let kid1 = fx().hmac("kid-hmac", HmacSpec::hs256()).kid();
    let kid2 = fx().hmac("kid-hmac", HmacSpec::hs256()).kid();
    assert_eq!(kid1, kid2);
    insta::assert_yaml_snapshot!("kid_hmac", kid1);
}

#[test]
fn kids_differ_across_key_types() {
    let f = fx();
    let rsa_kid = f.rsa("same-label", RsaSpec::rs256()).kid();
    let ec_kid = f.ecdsa("same-label", EcdsaSpec::es256()).kid();
    let ed_kid = f.ed25519("same-label", Ed25519Spec::new()).kid();
    let hmac_kid = f.hmac("same-label", HmacSpec::hs256()).kid();

    // All KIDs should be distinct because the domains differ
    let kids = [&rsa_kid, &ec_kid, &ed_kid, &hmac_kid];
    for i in 0..kids.len() {
        for j in (i + 1)..kids.len() {
            assert_ne!(kids[i], kids[j], "KIDs must differ across key types");
        }
    }
}

// =========================================================================
// 5. Negative Fixture Determinism
// =========================================================================

#[test]
fn negative_corrupt_pem_bad_header_is_deterministic() {
    let kp1 = fx().rsa("neg-pem", RsaSpec::rs256());
    let kp2 = fx().rsa("neg-pem", RsaSpec::rs256());

    let corrupt1 = kp1.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    let corrupt2 = kp2.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert_eq!(corrupt1, corrupt2);

    insta::assert_yaml_snapshot!(
        "neg_bad_header",
        insta::internals::Content::Map(vec![
            (
                insta::internals::Content::from("header_line"),
                insta::internals::Content::from(pem_header(&corrupt1))
            ),
            (
                insta::internals::Content::from("len"),
                insta::internals::Content::from(corrupt1.len() as u64)
            ),
        ])
    );
}

#[test]
fn negative_corrupt_pem_bad_footer_is_deterministic() {
    let kp1 = fx().rsa("neg-foot", RsaSpec::rs256());
    let kp2 = fx().rsa("neg-foot", RsaSpec::rs256());

    let corrupt1 = kp1.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
    let corrupt2 = kp2.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
    assert_eq!(corrupt1, corrupt2);
}

#[test]
fn negative_corrupt_pem_deterministic_variant_stable() {
    let kp1 = fx().rsa("neg-det", RsaSpec::rs256());
    let kp2 = fx().rsa("neg-det", RsaSpec::rs256());

    let c1 = kp1.private_key_pkcs8_pem_corrupt_deterministic("corrupt:v1");
    let c2 = kp2.private_key_pkcs8_pem_corrupt_deterministic("corrupt:v1");
    assert_eq!(c1, c2);

    // Different variant string must produce different corruption
    let c3 = kp1.private_key_pkcs8_pem_corrupt_deterministic("corrupt:v2");
    assert_ne!(c1, c3);
}

#[test]
fn negative_truncated_der_is_deterministic() {
    let kp1 = fx().rsa("neg-trunc", RsaSpec::rs256());
    let kp2 = fx().rsa("neg-trunc", RsaSpec::rs256());

    let trunc1 = kp1.private_key_pkcs8_der_truncated(20);
    let trunc2 = kp2.private_key_pkcs8_der_truncated(20);

    assert_eq!(trunc1, trunc2);
    assert_eq!(trunc1.len(), 20);
}

#[test]
fn negative_corrupt_der_deterministic_variant_stable() {
    let kp1 = fx().rsa("neg-der", RsaSpec::rs256());
    let kp2 = fx().rsa("neg-der", RsaSpec::rs256());

    let c1 = kp1.private_key_pkcs8_der_corrupt_deterministic("corrupt:v1");
    let c2 = kp2.private_key_pkcs8_der_corrupt_deterministic("corrupt:v1");
    assert_eq!(c1, c2);
}

#[test]
fn negative_mismatched_key_is_deterministic() {
    let kp1 = fx().rsa("neg-mismatch", RsaSpec::rs256());
    let kp2 = fx().rsa("neg-mismatch", RsaSpec::rs256());

    let m1 = kp1.mismatched_public_key_spki_der();
    let m2 = kp2.mismatched_public_key_spki_der();
    assert_eq!(m1, m2);

    // Mismatched key must differ from normal public key
    assert_ne!(kp1.public_key_spki_der(), &m1[..]);
}

#[test]
fn negative_ecdsa_corrupt_pem_deterministic() {
    let kp1 = fx().ecdsa("neg-ec", EcdsaSpec::es256());
    let kp2 = fx().ecdsa("neg-ec", EcdsaSpec::es256());

    let c1 = kp1.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    let c2 = kp2.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert_eq!(c1, c2);
}

#[test]
fn negative_ed25519_truncated_der_deterministic() {
    let kp1 = fx().ed25519("neg-ed", Ed25519Spec::new());
    let kp2 = fx().ed25519("neg-ed", Ed25519Spec::new());

    let t1 = kp1.private_key_pkcs8_der_truncated(16);
    let t2 = kp2.private_key_pkcs8_der_truncated(16);
    assert_eq!(t1, t2);
}

// =========================================================================
// 6. JWK / JWKS Determinism
// =========================================================================

#[test]
fn jwk_rsa_deterministic() {
    let jwk1 = fx().rsa("jwk-rsa", RsaSpec::rs256()).public_jwk();
    let jwk2 = fx().rsa("jwk-rsa", RsaSpec::rs256()).public_jwk();

    let v1 = jwk1.to_value();
    let v2 = jwk2.to_value();
    assert_eq!(v1, v2);

    insta::assert_yaml_snapshot!(
        "jwk_rsa_shape",
        insta::internals::Content::Map(vec![
            (
                insta::internals::Content::from("kty"),
                insta::internals::Content::from(v1["kty"].as_str().unwrap())
            ),
            (
                insta::internals::Content::from("alg"),
                insta::internals::Content::from(v1["alg"].as_str().unwrap())
            ),
            (
                insta::internals::Content::from("use"),
                insta::internals::Content::from(v1["use"].as_str().unwrap())
            ),
            (
                insta::internals::Content::from("kid"),
                insta::internals::Content::from(v1["kid"].as_str().unwrap())
            ),
        ])
    );
}

#[test]
fn jwk_ecdsa_deterministic() {
    let jwk1 = fx().ecdsa("jwk-ec", EcdsaSpec::es256()).public_jwk();
    let jwk2 = fx().ecdsa("jwk-ec", EcdsaSpec::es256()).public_jwk();

    let v1 = jwk1.to_value();
    let v2 = jwk2.to_value();
    assert_eq!(v1, v2);

    insta::assert_yaml_snapshot!(
        "jwk_ecdsa_shape",
        insta::internals::Content::Map(vec![
            (
                insta::internals::Content::from("kty"),
                insta::internals::Content::from(v1["kty"].as_str().unwrap())
            ),
            (
                insta::internals::Content::from("alg"),
                insta::internals::Content::from(v1["alg"].as_str().unwrap())
            ),
            (
                insta::internals::Content::from("crv"),
                insta::internals::Content::from(v1["crv"].as_str().unwrap())
            ),
            (
                insta::internals::Content::from("kid"),
                insta::internals::Content::from(v1["kid"].as_str().unwrap())
            ),
        ])
    );
}

#[test]
fn jwk_ed25519_deterministic() {
    let jwk1 = fx().ed25519("jwk-ed", Ed25519Spec::new()).public_jwk();
    let jwk2 = fx().ed25519("jwk-ed", Ed25519Spec::new()).public_jwk();

    let v1 = jwk1.to_value();
    let v2 = jwk2.to_value();
    assert_eq!(v1, v2);

    insta::assert_yaml_snapshot!(
        "jwk_ed25519_shape",
        insta::internals::Content::Map(vec![
            (
                insta::internals::Content::from("kty"),
                insta::internals::Content::from(v1["kty"].as_str().unwrap())
            ),
            (
                insta::internals::Content::from("alg"),
                insta::internals::Content::from(v1["alg"].as_str().unwrap())
            ),
            (
                insta::internals::Content::from("crv"),
                insta::internals::Content::from(v1["crv"].as_str().unwrap())
            ),
            (
                insta::internals::Content::from("kid"),
                insta::internals::Content::from(v1["kid"].as_str().unwrap())
            ),
        ])
    );
}

#[test]
fn jwks_multi_key_deterministic() {
    let f = fx();
    let rsa = f.rsa("jwks-rsa", RsaSpec::rs256());
    let ec = f.ecdsa("jwks-ec", EcdsaSpec::es256());
    let ed = f.ed25519("jwks-ed", Ed25519Spec::new());

    let build_jwks = |factory: &Factory| -> String {
        let rsa = factory.rsa("jwks-rsa", RsaSpec::rs256());
        let ec = factory.ecdsa("jwks-ec", EcdsaSpec::es256());
        let ed = factory.ed25519("jwks-ed", Ed25519Spec::new());
        let jwks = JwksBuilder::new()
            .add_public(rsa.public_jwk())
            .add_public(ec.public_jwk())
            .add_public(ed.public_jwk())
            .build();
        serde_json::to_string(&jwks.to_value()).unwrap()
    };

    let json1 = build_jwks(&fx());
    let json2 = build_jwks(&fx());
    assert_eq!(json1, json2);

    // Snapshot the structure (key count, KID ordering)
    let jwks = JwksBuilder::new()
        .add_public(rsa.public_jwk())
        .add_public(ec.public_jwk())
        .add_public(ed.public_jwk())
        .build();
    let val = jwks.to_value();
    let keys = val["keys"].as_array().unwrap();
    let kids: Vec<&str> = keys.iter().map(|k| k["kid"].as_str().unwrap()).collect();
    insta::assert_yaml_snapshot!(
        "jwks_multi_key",
        insta::internals::Content::Map(vec![
            (
                insta::internals::Content::from("key_count"),
                insta::internals::Content::from(keys.len() as u64)
            ),
            (
                insta::internals::Content::from("kid_0"),
                insta::internals::Content::from(kids[0])
            ),
            (
                insta::internals::Content::from("kid_1"),
                insta::internals::Content::from(kids[1])
            ),
            (
                insta::internals::Content::from("kid_2"),
                insta::internals::Content::from(kids[2])
            ),
        ])
    );
}

#[test]
fn jwks_single_rsa_deterministic() {
    let jwks1 = fx().rsa("jwks-single", RsaSpec::rs256()).public_jwks();
    let jwks2 = fx().rsa("jwks-single", RsaSpec::rs256()).public_jwks();
    assert_eq!(
        serde_json::to_string(&jwks1.to_value()).unwrap(),
        serde_json::to_string(&jwks2.to_value()).unwrap(),
    );
}

// =========================================================================
// 7. X.509 Determinism
// =========================================================================

#[test]
fn x509_self_signed_deterministic() {
    let c1 = fx().x509_self_signed("x509-det", X509Spec::self_signed("det.local"));
    let c2 = fx().x509_self_signed("x509-det", X509Spec::self_signed("det.local"));

    assert_eq!(c1.cert_der(), c2.cert_der());
    assert_eq!(c1.cert_pem(), c2.cert_pem());
    assert_eq!(c1.private_key_pkcs8_der(), c2.private_key_pkcs8_der());
}

#[test]
fn x509_metadata_snapshot() {
    let cert = fx().x509_self_signed("x509-snap", X509Spec::self_signed("snap.local"));
    insta::assert_yaml_snapshot!(
        "x509_self_signed_metadata",
        insta::internals::Content::Map(vec![
            (
                insta::internals::Content::from("cert_der_len"),
                insta::internals::Content::from(cert.cert_der().len() as u64)
            ),
            (
                insta::internals::Content::from("cert_pem_header"),
                insta::internals::Content::from(pem_header(cert.cert_pem()))
            ),
            (
                insta::internals::Content::from("key_der_len"),
                insta::internals::Content::from(cert.private_key_pkcs8_der().len() as u64)
            ),
            (
                insta::internals::Content::from("key_pem_header"),
                insta::internals::Content::from(pem_header(cert.private_key_pkcs8_pem()))
            ),
        ])
    );
}

#[test]
fn x509_negative_expired_deterministic() {
    let c1 = fx().x509_self_signed("x509-exp", X509Spec::self_signed("exp.local"));
    let c2 = fx().x509_self_signed("x509-exp", X509Spec::self_signed("exp.local"));

    let exp1 = c1.expired();
    let exp2 = c2.expired();
    assert_eq!(exp1.cert_der(), exp2.cert_der());
    assert_ne!(c1.cert_der(), exp1.cert_der());
}

#[test]
fn x509_negative_not_yet_valid_deterministic() {
    let cert = fx().x509_self_signed("x509-nyv", X509Spec::self_signed("nyv.local"));
    let cert2 = fx().x509_self_signed("x509-nyv", X509Spec::self_signed("nyv.local"));

    let nyv1 = cert.not_yet_valid();
    let nyv2 = cert2.not_yet_valid();
    assert_eq!(nyv1.cert_der(), nyv2.cert_der());
    assert_ne!(cert.cert_der(), nyv1.cert_der());
}

#[test]
fn x509_corrupt_pem_deterministic() {
    let c1 = fx().x509_self_signed("x509-corrupt", X509Spec::self_signed("corrupt.local"));
    let c2 = fx().x509_self_signed("x509-corrupt", X509Spec::self_signed("corrupt.local"));

    let bad1 = c1.corrupt_cert_pem(CorruptPem::BadHeader);
    let bad2 = c2.corrupt_cert_pem(CorruptPem::BadHeader);
    assert_eq!(bad1, bad2);
    assert!(bad1.starts_with("-----BEGIN CORRUPTED KEY-----"));
}

#[test]
fn x509_truncate_der_deterministic() {
    let c1 = fx().x509_self_signed("x509-trunc", X509Spec::self_signed("trunc.local"));
    let c2 = fx().x509_self_signed("x509-trunc", X509Spec::self_signed("trunc.local"));

    let t1 = c1.truncate_cert_der(32);
    let t2 = c2.truncate_cert_der(32);
    assert_eq!(t1, t2);
    assert_eq!(t1.len(), 32);
}

#[test]
fn x509_chain_deterministic() {
    let ch1 = fx().x509_chain("x509-chain", ChainSpec::new("chain.local"));
    let ch2 = fx().x509_chain("x509-chain", ChainSpec::new("chain.local"));

    assert_eq!(ch1.leaf_cert_pem(), ch2.leaf_cert_pem());
    assert_eq!(ch1.root_cert_pem(), ch2.root_cert_pem());
    assert_eq!(ch1.chain_pem(), ch2.chain_pem());
}

// =========================================================================
// 8. Cross-type KID uniqueness with snapshots
// =========================================================================

#[test]
fn kid_snapshot_all_key_types() {
    let f = fx();
    let rsa_kid = f.rsa("kid-all", RsaSpec::rs256()).kid();
    let ec_kid = f.ecdsa("kid-all", EcdsaSpec::es256()).kid();
    let ed_kid = f.ed25519("kid-all", Ed25519Spec::new()).kid();
    let hmac_kid = f.hmac("kid-all", HmacSpec::hs256()).kid();

    insta::assert_yaml_snapshot!(
        "kid_all_types",
        insta::internals::Content::Map(vec![
            (
                insta::internals::Content::from("rsa"),
                insta::internals::Content::from(rsa_kid.as_str())
            ),
            (
                insta::internals::Content::from("ecdsa"),
                insta::internals::Content::from(ec_kid.as_str())
            ),
            (
                insta::internals::Content::from("ed25519"),
                insta::internals::Content::from(ed_kid.as_str())
            ),
            (
                insta::internals::Content::from("hmac"),
                insta::internals::Content::from(hmac_kid.as_str())
            ),
        ])
    );
}
