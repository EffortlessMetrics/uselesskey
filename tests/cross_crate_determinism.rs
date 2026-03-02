//! Cross-crate determinism regression tests.
//!
//! Pins the exact output of `Factory::deterministic(Seed::new([42; 32]))` for
//! every key type.  Any change to derivation, encoding, or caching that alters
//! these values is a breaking change and must bump the derivation version.
//!
//! Coverage:
//!   1. Golden-output regression (pinned PEM/DER lengths, KID, JWK fields)
//!   2. Cross-key-type independence (generation order doesn't matter)
//!   3. Factory isolation (two factories with same seed → identical output)
//!   4. Version stability (derivation version pinned in outputs)

#![cfg(feature = "determinism")]

use uselesskey::prelude::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Canonical test factory: seed = [42; 32].
fn golden_factory() -> Factory {
    Factory::deterministic(Seed::new([42u8; 32]))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ===========================================================================
// 1. Golden-output regression — RSA
// ===========================================================================

#[test]
fn golden_rsa_pem_lengths() {
    let fx = golden_factory();
    let kp = fx.rsa("golden", RsaSpec::rs256());

    assert_eq!(kp.private_key_pkcs8_pem().len(), 1708);
    assert_eq!(kp.public_key_spki_pem().len(), 451);
}

#[test]
fn golden_rsa_der_lengths() {
    let fx = golden_factory();
    let kp = fx.rsa("golden", RsaSpec::rs256());

    assert_eq!(kp.private_key_pkcs8_der().len(), 1219);
    assert_eq!(kp.public_key_spki_der().len(), 294);
}

#[test]
fn golden_rsa_pem_headers() {
    let fx = golden_factory();
    let kp = fx.rsa("golden", RsaSpec::rs256());

    assert!(
        kp.private_key_pkcs8_pem()
            .starts_with("-----BEGIN PRIVATE KEY-----")
    );
    assert!(
        kp.public_key_spki_pem()
            .starts_with("-----BEGIN PUBLIC KEY-----")
    );
}

#[test]
fn golden_rsa_kid() {
    let fx = golden_factory();
    let kp = fx.rsa("golden", RsaSpec::rs256());

    assert_eq!(kp.kid(), "pR6634YGM4JvWOJ-");
}

#[test]
fn golden_rsa_jwk_structure() {
    let fx = golden_factory();
    let kp = fx.rsa("golden", RsaSpec::rs256());
    let jwk = kp.public_jwk_json();

    assert_eq!(jwk["alg"], "RS256");
    assert_eq!(jwk["kty"], "RSA");
    assert_eq!(jwk["use"], "sig");
    assert_eq!(jwk["kid"], "pR6634YGM4JvWOJ-");
}

// ===========================================================================
// 1. Golden-output regression — ECDSA P-256
// ===========================================================================

#[test]
fn golden_ecdsa_p256_pem_lengths() {
    let fx = golden_factory();
    let kp = fx.ecdsa("golden", EcdsaSpec::es256());

    assert_eq!(kp.private_key_pkcs8_pem().len(), 241);
    assert_eq!(kp.public_key_spki_pem().len(), 178);
}

#[test]
fn golden_ecdsa_p256_der_length() {
    let fx = golden_factory();
    let kp = fx.ecdsa("golden", EcdsaSpec::es256());

    assert_eq!(kp.private_key_pkcs8_der().len(), 138);
}

#[test]
fn golden_ecdsa_p256_kid() {
    let fx = golden_factory();
    let kp = fx.ecdsa("golden", EcdsaSpec::es256());

    assert_eq!(kp.kid(), "J5JHZDE4uPNfA9CA");
}

#[test]
fn golden_ecdsa_p256_pem_determinism() {
    let fx = golden_factory();
    let kp = fx.ecdsa("golden", EcdsaSpec::es256());

    // Verify deterministic PEM structure without embedding key material.
    let pem = kp.private_key_pkcs8_pem();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
    assert!(pem.ends_with("-----END PRIVATE KEY-----\n"));
    assert_eq!(pem.len(), 241);

    // Verify reproducibility: same factory + inputs → same output.
    let fx2 = golden_factory();
    let kp2 = fx2.ecdsa("golden", EcdsaSpec::es256());
    assert_eq!(kp.private_key_pkcs8_pem(), kp2.private_key_pkcs8_pem());
}

#[test]
fn golden_ecdsa_p256_jwk_structure() {
    let fx = golden_factory();
    let kp = fx.ecdsa("golden", EcdsaSpec::es256());
    let jwk = kp.public_jwk_json();

    assert_eq!(jwk["alg"], "ES256");
    assert_eq!(jwk["kty"], "EC");
    assert_eq!(jwk["crv"], "P-256");
    assert_eq!(jwk["kid"], "J5JHZDE4uPNfA9CA");
}

// ===========================================================================
// 1. Golden-output regression — ECDSA P-384
// ===========================================================================

#[test]
fn golden_ecdsa_p384_pem_length() {
    let fx = golden_factory();
    let kp = fx.ecdsa("golden", EcdsaSpec::es384());

    assert_eq!(kp.private_key_pkcs8_pem().len(), 306);
}

#[test]
fn golden_ecdsa_p384_kid() {
    let fx = golden_factory();
    let kp = fx.ecdsa("golden", EcdsaSpec::es384());

    assert_eq!(kp.kid(), "QUDzsh5HV27-Cq86");
}

// ===========================================================================
// 1. Golden-output regression — Ed25519
// ===========================================================================

#[test]
fn golden_ed25519_pem_lengths() {
    let fx = golden_factory();
    let kp = fx.ed25519("golden", Ed25519Spec::new());

    assert_eq!(kp.private_key_pkcs8_pem().len(), 168);
    assert_eq!(kp.public_key_spki_pem().len(), 113);
}

#[test]
fn golden_ed25519_der_length() {
    let fx = golden_factory();
    let kp = fx.ed25519("golden", Ed25519Spec::new());

    assert_eq!(kp.private_key_pkcs8_der().len(), 83);
}

#[test]
fn golden_ed25519_kid() {
    let fx = golden_factory();
    let kp = fx.ed25519("golden", Ed25519Spec::new());

    assert_eq!(kp.kid(), "w3HIeTbCFmGXPqe0");
}

#[test]
fn golden_ed25519_pem_determinism() {
    let fx = golden_factory();
    let kp = fx.ed25519("golden", Ed25519Spec::new());

    // Verify deterministic PEM structure without embedding key material.
    let priv_pem = kp.private_key_pkcs8_pem();
    assert!(priv_pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
    assert!(priv_pem.ends_with("-----END PRIVATE KEY-----\n"));
    assert_eq!(priv_pem.len(), 168);

    let pub_pem = kp.public_key_spki_pem();
    assert!(pub_pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
    assert!(pub_pem.ends_with("-----END PUBLIC KEY-----\n"));
    assert_eq!(pub_pem.len(), 113);

    // Verify reproducibility: same factory + inputs → same output.
    let fx2 = golden_factory();
    let kp2 = fx2.ed25519("golden", Ed25519Spec::new());
    assert_eq!(kp.private_key_pkcs8_pem(), kp2.private_key_pkcs8_pem());
    assert_eq!(kp.public_key_spki_pem(), kp2.public_key_spki_pem());
}

#[test]
fn golden_ed25519_jwk_structure() {
    let fx = golden_factory();
    let kp = fx.ed25519("golden", Ed25519Spec::new());
    let jwk = kp.public_jwk_json();

    assert_eq!(jwk["alg"], "EdDSA");
    assert_eq!(jwk["kty"], "OKP");
    assert_eq!(jwk["crv"], "Ed25519");
    assert_eq!(jwk["kid"], "w3HIeTbCFmGXPqe0");
}

// ===========================================================================
// 1. Golden-output regression — HMAC
// ===========================================================================

#[test]
fn golden_hmac_hs256() {
    let fx = golden_factory();
    let s = fx.hmac("golden", HmacSpec::hs256());

    assert_eq!(s.secret_bytes().len(), 32);
    assert_eq!(s.kid(), "lzN6I2PeLXUiA9R1");
    assert_eq!(
        hex(s.secret_bytes()),
        "29a39d37a34c90c0abaaac18e369730e366e4452f29635e763dc0e5a2b82de4b"
    );
}

#[test]
fn golden_hmac_hs384() {
    let fx = golden_factory();
    let s = fx.hmac("golden", HmacSpec::hs384());

    assert_eq!(s.secret_bytes().len(), 48);
    assert_eq!(s.kid(), "lA_W_vLUUMGoqtlb");
    assert_eq!(
        hex(s.secret_bytes()),
        "23c51da72f5a8fa09aa86cf44de849c54ef8e1e803a2e909abfd238060f652fd\
         63ba7276415d7d628801793a23ffff97"
    );
}

#[test]
fn golden_hmac_hs512() {
    let fx = golden_factory();
    let s = fx.hmac("golden", HmacSpec::hs512());

    assert_eq!(s.secret_bytes().len(), 64);
    assert_eq!(s.kid(), "ufG4xMq-lp6n5rPG");
    assert_eq!(
        hex(s.secret_bytes()),
        "0fe1c2f352188b8f472f75136b679c111046ed9fd891719c1de5a1b424b5f4fe\
         b9afb51bf321691ef449d0385368adca72df3451afebd2a0a8b4eba3a7fe0769"
    );
}

// ===========================================================================
// 1. Golden-output regression — Token
// ===========================================================================

#[test]
fn golden_token_api_key() {
    let fx = golden_factory();
    let t = fx.token("golden", TokenSpec::api_key());

    assert_eq!(t.value(), "uk_test_feYQiqwJB4DjLofxyQYzWxIvD6a6c4Pb");
}

#[test]
fn golden_token_bearer() {
    let fx = golden_factory();
    let t = fx.token("golden", TokenSpec::bearer());

    assert_eq!(t.value(), "Z9j-4fQ-GOkYn9eWgOlArIDeR9S224mrK_JUr_QBluc");
}

#[test]
fn golden_token_oauth() {
    let fx = golden_factory();
    let t = fx.token("golden", TokenSpec::oauth_access_token());

    // OAuth tokens have a JWT-like three-segment structure
    let val = t.value();
    assert_eq!(
        val.matches('.').count(),
        2,
        "OAuth token should have 3 segments"
    );
    assert!(
        val.starts_with("eyJ"),
        "OAuth token should be base64-encoded JSON"
    );
}

// ===========================================================================
// 2. Cross-key-type independence
// ===========================================================================

#[test]
fn cross_key_rsa_then_ecdsa_vs_ecdsa_then_rsa() {
    let fx1 = golden_factory();
    let rsa1 = fx1.rsa("svc", RsaSpec::rs256());
    let ec1 = fx1.ecdsa("svc", EcdsaSpec::es256());

    let fx2 = golden_factory();
    let ec2 = fx2.ecdsa("svc", EcdsaSpec::es256());
    let rsa2 = fx2.rsa("svc", RsaSpec::rs256());

    assert_eq!(rsa1.private_key_pkcs8_pem(), rsa2.private_key_pkcs8_pem());
    assert_eq!(ec1.private_key_pkcs8_pem(), ec2.private_key_pkcs8_pem());
    assert_eq!(rsa1.kid(), rsa2.kid());
    assert_eq!(ec1.kid(), ec2.kid());
}

#[test]
fn cross_key_all_types_order_independent() {
    let fx1 = golden_factory();
    let rsa1 = fx1.rsa("ind", RsaSpec::rs256());
    let ec1 = fx1.ecdsa("ind", EcdsaSpec::es256());
    let ed1 = fx1.ed25519("ind", Ed25519Spec::new());
    let hm1 = fx1.hmac("ind", HmacSpec::hs256());
    let tk1 = fx1.token("ind", TokenSpec::api_key());

    // Reverse order
    let fx2 = golden_factory();
    let tk2 = fx2.token("ind", TokenSpec::api_key());
    let hm2 = fx2.hmac("ind", HmacSpec::hs256());
    let ed2 = fx2.ed25519("ind", Ed25519Spec::new());
    let ec2 = fx2.ecdsa("ind", EcdsaSpec::es256());
    let rsa2 = fx2.rsa("ind", RsaSpec::rs256());

    assert_eq!(rsa1.private_key_pkcs8_pem(), rsa2.private_key_pkcs8_pem());
    assert_eq!(ec1.private_key_pkcs8_pem(), ec2.private_key_pkcs8_pem());
    assert_eq!(ed1.private_key_pkcs8_pem(), ed2.private_key_pkcs8_pem());
    assert_eq!(hm1.secret_bytes(), hm2.secret_bytes());
    assert_eq!(tk1.value(), tk2.value());
}

#[test]
fn cross_key_noise_does_not_perturb() {
    // Generate RSA alone
    let fx1 = golden_factory();
    let rsa_alone = fx1.rsa("target", RsaSpec::rs256());

    // Generate RSA after producing many other key types
    let fx2 = golden_factory();
    let _ec = fx2.ecdsa("noise-a", EcdsaSpec::es256());
    let _ec2 = fx2.ecdsa("noise-b", EcdsaSpec::es384());
    let _ed = fx2.ed25519("noise-c", Ed25519Spec::new());
    let _hm = fx2.hmac("noise-d", HmacSpec::hs512());
    let _tk = fx2.token("noise-e", TokenSpec::bearer());
    let rsa_after_noise = fx2.rsa("target", RsaSpec::rs256());

    assert_eq!(
        rsa_alone.private_key_pkcs8_pem(),
        rsa_after_noise.private_key_pkcs8_pem(),
        "generating unrelated key types must not perturb RSA output"
    );
}

// ===========================================================================
// 3. Factory isolation
// ===========================================================================

#[test]
fn factory_isolation_rsa() {
    let pems: Vec<String> = (0..3)
        .map(|_| {
            golden_factory()
                .rsa("iso-rsa", RsaSpec::rs256())
                .private_key_pkcs8_pem()
                .to_string()
        })
        .collect();

    assert_eq!(pems[0], pems[1]);
    assert_eq!(pems[1], pems[2]);
}

#[test]
fn factory_isolation_ecdsa() {
    let pems: Vec<String> = (0..3)
        .map(|_| {
            golden_factory()
                .ecdsa("iso-ec", EcdsaSpec::es256())
                .private_key_pkcs8_pem()
                .to_string()
        })
        .collect();

    assert_eq!(pems[0], pems[1]);
    assert_eq!(pems[1], pems[2]);
}

#[test]
fn factory_isolation_ed25519() {
    let pems: Vec<String> = (0..3)
        .map(|_| {
            golden_factory()
                .ed25519("iso-ed", Ed25519Spec::new())
                .private_key_pkcs8_pem()
                .to_string()
        })
        .collect();

    assert_eq!(pems[0], pems[1]);
    assert_eq!(pems[1], pems[2]);
}

#[test]
fn factory_isolation_hmac() {
    let secrets: Vec<Vec<u8>> = (0..3)
        .map(|_| {
            golden_factory()
                .hmac("iso-hm", HmacSpec::hs256())
                .secret_bytes()
                .to_vec()
        })
        .collect();

    assert_eq!(secrets[0], secrets[1]);
    assert_eq!(secrets[1], secrets[2]);
}

#[test]
fn factory_isolation_token() {
    let values: Vec<String> = (0..3)
        .map(|_| {
            golden_factory()
                .token("iso-tk", TokenSpec::api_key())
                .value()
                .to_string()
        })
        .collect();

    assert_eq!(values[0], values[1]);
    assert_eq!(values[1], values[2]);
}

#[test]
fn factory_isolation_kids_match_across_instances() {
    let fx1 = golden_factory();
    let fx2 = golden_factory();

    assert_eq!(
        fx1.rsa("kid-check", RsaSpec::rs256()).kid(),
        fx2.rsa("kid-check", RsaSpec::rs256()).kid(),
    );
    assert_eq!(
        fx1.ecdsa("kid-check", EcdsaSpec::es256()).kid(),
        fx2.ecdsa("kid-check", EcdsaSpec::es256()).kid(),
    );
    assert_eq!(
        fx1.ed25519("kid-check", Ed25519Spec::new()).kid(),
        fx2.ed25519("kid-check", Ed25519Spec::new()).kid(),
    );
    assert_eq!(
        fx1.hmac("kid-check", HmacSpec::hs256()).kid(),
        fx2.hmac("kid-check", HmacSpec::hs256()).kid(),
    );
}

// ===========================================================================
// 4. Version stability — derivation version pinned in outputs
// ===========================================================================

#[test]
fn version_stability_all_kids_pinned() {
    let fx = golden_factory();

    // These KIDs are derived from (seed, domain, label, spec, variant,
    // derivation_version).  If any component of the derivation pipeline
    // changes, at least one of these will break.
    assert_eq!(fx.rsa("golden", RsaSpec::rs256()).kid(), "pR6634YGM4JvWOJ-");
    assert_eq!(
        fx.ecdsa("golden", EcdsaSpec::es256()).kid(),
        "J5JHZDE4uPNfA9CA"
    );
    assert_eq!(
        fx.ecdsa("golden", EcdsaSpec::es384()).kid(),
        "QUDzsh5HV27-Cq86"
    );
    assert_eq!(
        fx.ed25519("golden", Ed25519Spec::new()).kid(),
        "w3HIeTbCFmGXPqe0"
    );
    assert_eq!(
        fx.hmac("golden", HmacSpec::hs256()).kid(),
        "lzN6I2PeLXUiA9R1"
    );
    assert_eq!(
        fx.hmac("golden", HmacSpec::hs384()).kid(),
        "lA_W_vLUUMGoqtlb"
    );
    assert_eq!(
        fx.hmac("golden", HmacSpec::hs512()).kid(),
        "ufG4xMq-lp6n5rPG"
    );
}

#[test]
fn version_stability_different_seeds_produce_different_kids() {
    let fx_a = Factory::deterministic(Seed::new([42u8; 32]));
    let fx_b = Factory::deterministic(Seed::new([99u8; 32]));

    assert_ne!(
        fx_a.ecdsa("same", EcdsaSpec::es256()).kid(),
        fx_b.ecdsa("same", EcdsaSpec::es256()).kid(),
    );
}

#[test]
fn version_stability_different_labels_produce_different_kids() {
    let fx = golden_factory();

    assert_ne!(
        fx.rsa("alpha", RsaSpec::rs256()).kid(),
        fx.rsa("bravo", RsaSpec::rs256()).kid(),
    );
}

#[test]
fn version_stability_different_specs_produce_different_kids() {
    let fx = golden_factory();

    assert_ne!(
        fx.ecdsa("same", EcdsaSpec::es256()).kid(),
        fx.ecdsa("same", EcdsaSpec::es384()).kid(),
    );
    assert_ne!(
        fx.hmac("same", HmacSpec::hs256()).kid(),
        fx.hmac("same", HmacSpec::hs512()).kid(),
    );
}

// ===========================================================================
// 5. JWK round-trip consistency
// ===========================================================================

#[test]
fn jwk_kid_matches_keypair_kid() {
    let fx = golden_factory();

    let rsa = fx.rsa("jwk-match", RsaSpec::rs256());
    assert_eq!(rsa.public_jwk_json()["kid"], rsa.kid());

    let ec = fx.ecdsa("jwk-match", EcdsaSpec::es256());
    assert_eq!(ec.public_jwk_json()["kid"], ec.kid());

    let ed = fx.ed25519("jwk-match", Ed25519Spec::new());
    assert_eq!(ed.public_jwk_json()["kid"], ed.kid());
}

#[test]
fn jwks_contains_single_key_with_correct_kid() {
    let fx = golden_factory();

    let rsa = fx.rsa("jwks-single", RsaSpec::rs256());
    let jwks = rsa.public_jwks_json();
    let keys = jwks["keys"]
        .as_array()
        .expect("JWKS should have keys array");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kid"], rsa.kid());
}
