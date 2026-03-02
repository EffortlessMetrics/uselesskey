//! End-to-end pipeline tests exercising the full lifecycle:
//! seed → factory → key generation → all output formats → verification.
//!
//! These tests validate format consistency across PEM/DER/JWK/JWKS outputs,
//! KID stability, JWKS aggregation, negative fixture unparsability,
//! tempfile round-trips, and token format properties.

mod testutil;

use uselesskey::prelude::*;

fn fx() -> Factory {
    testutil::fx()
}

fn deterministic_fx(seed_str: &str) -> Factory {
    let seed = Seed::from_env_value(seed_str).expect("test seed");
    Factory::deterministic(seed)
}

// =========================================================================
// 1. Full RSA pipeline
// =========================================================================

#[test]
#[cfg(all(feature = "rsa", feature = "jwk"))]
fn e2e_rsa_full_pipeline() {
    let fx = deterministic_fx("e2e-pipeline-v1");
    let kp = fx.rsa("e2e-rsa-pipeline", RsaSpec::rs256());

    // All format outputs
    let pem_priv = kp.private_key_pkcs8_pem();
    let pem_pub = kp.public_key_spki_pem();
    let der_priv = kp.private_key_pkcs8_der();
    let der_pub = kp.public_key_spki_der();
    let jwk = kp.public_jwk();
    let kid = kp.kid();
    let jwks = kp.public_jwks();

    // PEM format validity
    assert!(pem_priv.starts_with("-----BEGIN PRIVATE KEY-----\n"));
    assert!(pem_priv.trim_end().ends_with("-----END PRIVATE KEY-----"));
    assert!(pem_pub.starts_with("-----BEGIN PUBLIC KEY-----\n"));
    assert!(pem_pub.trim_end().ends_with("-----END PUBLIC KEY-----"));

    // DER validity (SEQUENCE tag)
    assert!(!der_priv.is_empty());
    assert_eq!(der_priv[0], 0x30);
    assert!(!der_pub.is_empty());
    assert_eq!(der_pub[0], 0x30);

    // PEM encodes the same key material as DER
    let parsed_priv = pem::parse(pem_priv).expect("private PEM should parse");
    assert_eq!(parsed_priv.contents(), der_priv);
    let parsed_pub = pem::parse(pem_pub).expect("public PEM should parse");
    assert_eq!(parsed_pub.contents(), der_pub);

    // JWK fields
    assert_eq!(jwk.kid(), kid.as_str());
    let jwk_val = jwk.to_value();
    assert_eq!(jwk_val["kty"], "RSA");
    assert_eq!(jwk_val["alg"], "RS256");
    assert!(jwk_val["n"].is_string());
    assert!(jwk_val["e"].is_string());

    // JWKS contains the key
    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(jwks.keys[0].kid(), kid.as_str());

    // Determinism: same seed reproduces identical output
    let fx2 = deterministic_fx("e2e-pipeline-v1");
    let kp2 = fx2.rsa("e2e-rsa-pipeline", RsaSpec::rs256());
    assert_eq!(kp.kid(), kp2.kid());
    // Use assert! (not assert_eq!) to avoid printing PEM/DER on failure
    assert!(
        kp.private_key_pkcs8_pem() == kp2.private_key_pkcs8_pem(),
        "private PEM must be deterministic"
    );
    assert!(
        kp.public_key_spki_pem() == kp2.public_key_spki_pem(),
        "public PEM must be deterministic"
    );
    assert_eq!(kp.private_key_pkcs8_der(), kp2.private_key_pkcs8_der());
    assert_eq!(kp.public_key_spki_der(), kp2.public_key_spki_der());
}

// =========================================================================
// 2. Full ECDSA pipeline (P-256 and P-384)
// =========================================================================

#[test]
#[cfg(all(feature = "ecdsa", feature = "jwk"))]
fn e2e_ecdsa_p256_full_pipeline() {
    let fx = deterministic_fx("e2e-pipeline-v1");
    let kp = fx.ecdsa("e2e-ecdsa-p256", EcdsaSpec::es256());

    let pem_priv = kp.private_key_pkcs8_pem();
    let pem_pub = kp.public_key_spki_pem();
    let der_priv = kp.private_key_pkcs8_der();
    let der_pub = kp.public_key_spki_der();
    let jwk = kp.public_jwk();
    let kid = kp.kid();
    let jwks = kp.public_jwks();

    // PEM format
    assert!(pem_priv.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(pem_pub.contains("-----BEGIN PUBLIC KEY-----"));

    // DER validity
    assert!(!der_priv.is_empty());
    assert_eq!(der_priv[0], 0x30);
    assert!(!der_pub.is_empty());
    assert_eq!(der_pub[0], 0x30);

    // PEM ↔ DER consistency
    let parsed_priv = pem::parse(pem_priv).expect("private PEM should parse");
    assert_eq!(parsed_priv.contents(), der_priv);
    let parsed_pub = pem::parse(pem_pub).expect("public PEM should parse");
    assert_eq!(parsed_pub.contents(), der_pub);

    // JWK fields
    assert_eq!(jwk.kid(), kid.as_str());
    let jwk_val = jwk.to_value();
    assert_eq!(jwk_val["kty"], "EC");
    assert_eq!(jwk_val["crv"], "P-256");
    assert_eq!(jwk_val["alg"], "ES256");

    // JWKS
    assert_eq!(jwks.keys.len(), 1);

    // Determinism
    let fx2 = deterministic_fx("e2e-pipeline-v1");
    let kp2 = fx2.ecdsa("e2e-ecdsa-p256", EcdsaSpec::es256());
    assert_eq!(kp.kid(), kp2.kid());
    assert_eq!(kp.private_key_pkcs8_der(), kp2.private_key_pkcs8_der());
}

#[test]
#[cfg(all(feature = "ecdsa", feature = "jwk"))]
fn e2e_ecdsa_p384_full_pipeline() {
    let fx = deterministic_fx("e2e-pipeline-v1");
    let kp = fx.ecdsa("e2e-ecdsa-p384", EcdsaSpec::es384());

    let pem_priv = kp.private_key_pkcs8_pem();
    let der_priv = kp.private_key_pkcs8_der();
    let jwk = kp.public_jwk();
    let kid = kp.kid();

    assert!(pem_priv.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(!der_priv.is_empty());
    assert_eq!(jwk.kid(), kid.as_str());

    let jwk_val = jwk.to_value();
    assert_eq!(jwk_val["kty"], "EC");
    assert_eq!(jwk_val["crv"], "P-384");
    assert_eq!(jwk_val["alg"], "ES384");

    // Determinism
    let fx2 = deterministic_fx("e2e-pipeline-v1");
    let kp2 = fx2.ecdsa("e2e-ecdsa-p384", EcdsaSpec::es384());
    assert_eq!(kp.kid(), kp2.kid());
    assert_eq!(kp.private_key_pkcs8_der(), kp2.private_key_pkcs8_der());
}

// =========================================================================
// 3. Full Ed25519 pipeline
// =========================================================================

#[test]
#[cfg(all(feature = "ed25519", feature = "jwk"))]
fn e2e_ed25519_full_pipeline() {
    let fx = deterministic_fx("e2e-pipeline-v1");
    let kp = fx.ed25519("e2e-ed25519", Ed25519Spec::new());

    let pem_priv = kp.private_key_pkcs8_pem();
    let pem_pub = kp.public_key_spki_pem();
    let der_priv = kp.private_key_pkcs8_der();
    let der_pub = kp.public_key_spki_der();
    let jwk = kp.public_jwk();
    let kid = kp.kid();
    let jwks = kp.public_jwks();

    // PEM format
    assert!(pem_priv.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(pem_pub.contains("-----BEGIN PUBLIC KEY-----"));

    // DER validity
    assert!(!der_priv.is_empty());
    assert_eq!(der_priv[0], 0x30);
    assert!(!der_pub.is_empty());
    assert_eq!(der_pub[0], 0x30);

    // PEM ↔ DER consistency
    let parsed_priv = pem::parse(pem_priv).expect("private PEM should parse");
    assert_eq!(parsed_priv.contents(), der_priv);
    let parsed_pub = pem::parse(pem_pub).expect("public PEM should parse");
    assert_eq!(parsed_pub.contents(), der_pub);

    // JWK fields
    assert_eq!(jwk.kid(), kid.as_str());
    let jwk_val = jwk.to_value();
    assert_eq!(jwk_val["kty"], "OKP");
    assert_eq!(jwk_val["crv"], "Ed25519");

    // JWKS
    assert_eq!(jwks.keys.len(), 1);

    // Determinism
    let fx2 = deterministic_fx("e2e-pipeline-v1");
    let kp2 = fx2.ed25519("e2e-ed25519", Ed25519Spec::new());
    assert_eq!(kp.kid(), kp2.kid());
    assert_eq!(kp.private_key_pkcs8_der(), kp2.private_key_pkcs8_der());
}

// =========================================================================
// 4. Multi-key JWKS aggregation
// =========================================================================

#[test]
#[cfg(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "jwk"
))]
fn e2e_jwks_aggregation() {
    use uselesskey::jwk::JwksBuilder;

    let fx = deterministic_fx("e2e-jwks-agg-v1");
    let rsa = fx.rsa("jwks-agg-rsa", RsaSpec::rs256());
    let ec256 = fx.ecdsa("jwks-agg-ec256", EcdsaSpec::es256());
    let ec384 = fx.ecdsa("jwks-agg-ec384", EcdsaSpec::es384());
    let ed = fx.ed25519("jwks-agg-ed", Ed25519Spec::new());

    // Build JWKS containing all keys
    let jwks = JwksBuilder::new()
        .add_public(rsa.public_jwk())
        .add_public(ec256.public_jwk())
        .add_public(ec384.public_jwk())
        .add_public(ed.public_jwk())
        .build();

    // Correct key count
    assert_eq!(jwks.keys.len(), 4);

    // All KIDs present and unique
    let kids: Vec<&str> = jwks.keys.iter().map(|k| k.kid()).collect();
    assert!(kids.contains(&rsa.kid().as_str()));
    assert!(kids.contains(&ec256.kid().as_str()));
    assert!(kids.contains(&ec384.kid().as_str()));
    assert!(kids.contains(&ed.kid().as_str()));

    let unique_kids: std::collections::HashSet<&&str> = kids.iter().collect();
    assert_eq!(unique_kids.len(), 4, "all KIDs must be unique");

    // Serialization round-trip
    let json = jwks.to_string();
    assert!(json.contains("\"keys\""));
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("JWKS JSON should parse");
    assert_eq!(parsed["keys"].as_array().unwrap().len(), 4);

    // Verify key types in JWKS
    let kty_set: std::collections::HashSet<String> = parsed["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kty"].as_str().unwrap().to_string())
        .collect();
    assert!(kty_set.contains("RSA"));
    assert!(kty_set.contains("EC"));
    assert!(kty_set.contains("OKP"));

    // Determinism: same seed → same JWKS JSON
    let fx2 = deterministic_fx("e2e-jwks-agg-v1");
    let rsa2 = fx2.rsa("jwks-agg-rsa", RsaSpec::rs256());
    let ec256_2 = fx2.ecdsa("jwks-agg-ec256", EcdsaSpec::es256());
    let ec384_2 = fx2.ecdsa("jwks-agg-ec384", EcdsaSpec::es384());
    let ed2 = fx2.ed25519("jwks-agg-ed", Ed25519Spec::new());
    let jwks2 = JwksBuilder::new()
        .add_public(rsa2.public_jwk())
        .add_public(ec256_2.public_jwk())
        .add_public(ec384_2.public_jwk())
        .add_public(ed2.public_jwk())
        .build();
    assert_eq!(jwks.to_string(), jwks2.to_string());
}

// =========================================================================
// 5. Negative fixture pipeline — verify corruption is unparseable
// =========================================================================

#[test]
#[cfg(feature = "rsa")]
fn e2e_negative_corrupt_pem_unparseable() {
    let kp = fx().rsa("e2e-neg-pem", RsaSpec::rs256());

    // BadHeader: standard PEM parser should reject
    let bad_header = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert!(
        pem::parse(&bad_header).is_err(),
        "corrupt PEM (BadHeader) must not parse as valid PEM"
    );

    // BadFooter: footer mismatch
    let bad_footer = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
    assert!(
        pem::parse(&bad_footer).is_err(),
        "corrupt PEM (BadFooter) must not parse as valid PEM"
    );

    // BadBase64: invalid base64 body
    let bad_b64 = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
    assert!(
        pem::parse(&bad_b64).is_err(),
        "corrupt PEM (BadBase64) must not parse as valid PEM"
    );
}

#[test]
#[cfg(feature = "rsa")]
fn e2e_negative_truncated_der_is_incomplete() {
    let kp = fx().rsa("e2e-neg-der", RsaSpec::rs256());
    let full_der = kp.private_key_pkcs8_der();
    let truncated = kp.private_key_pkcs8_der_truncated(10);

    assert_eq!(truncated.len(), 10);
    assert!(truncated.len() < full_der.len());
    // First bytes match (it's a prefix)
    assert_eq!(&truncated[..], &full_der[..10]);
}

#[test]
#[cfg(feature = "rsa")]
fn e2e_negative_mismatched_key_differs() {
    let kp = fx().rsa("e2e-neg-mismatch", RsaSpec::rs256());
    let original_pub = kp.public_key_spki_der();
    let mismatched_pub = kp.mismatched_public_key_spki_der();

    // Mismatched key is valid DER but different from the matching public key
    assert!(!mismatched_pub.is_empty());
    assert_eq!(mismatched_pub[0], 0x30);
    assert_ne!(
        original_pub,
        mismatched_pub.as_slice(),
        "mismatched public key must differ from the original"
    );
}

#[test]
#[cfg(feature = "ecdsa")]
fn e2e_negative_ecdsa_corrupt_pipeline() {
    let kp = fx().ecdsa("e2e-neg-ecdsa", EcdsaSpec::es256());

    // Corrupt PEM unparseable
    let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert!(pem::parse(&bad).is_err());

    // Truncated DER
    let truncated = kp.private_key_pkcs8_der_truncated(5);
    assert_eq!(truncated.len(), 5);

    // Mismatched key
    let mismatched = kp.mismatched_public_key_spki_der();
    assert_ne!(kp.public_key_spki_der(), mismatched.as_slice());
}

#[test]
#[cfg(feature = "ed25519")]
fn e2e_negative_ed25519_corrupt_pipeline() {
    let kp = fx().ed25519("e2e-neg-ed", Ed25519Spec::new());

    let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert!(pem::parse(&bad).is_err());

    let truncated = kp.private_key_pkcs8_der_truncated(5);
    assert_eq!(truncated.len(), 5);

    let mismatched = kp.mismatched_public_key_spki_der();
    assert_ne!(kp.public_key_spki_der(), mismatched.as_slice());
}

// =========================================================================
// 6. Tempfile sink pipeline
// =========================================================================

#[test]
#[cfg(feature = "rsa")]
fn e2e_tempfile_rsa_round_trip() {
    let kp = fx().rsa("e2e-sink-rsa", RsaSpec::rs256());

    // Write all formats to tempfiles and read back
    let priv_pem_tmp = kp.write_private_key_pkcs8_pem().unwrap();
    let pub_pem_tmp = kp.write_public_key_spki_pem().unwrap();

    assert!(priv_pem_tmp.path().exists());
    assert!(pub_pem_tmp.path().exists());

    // Content matches in-memory output (use assert! to avoid printing PEM on failure)
    assert!(
        priv_pem_tmp.read_to_string().unwrap() == kp.private_key_pkcs8_pem(),
        "tempfile private PEM must match in-memory output"
    );
    assert!(
        pub_pem_tmp.read_to_string().unwrap() == kp.public_key_spki_pem(),
        "tempfile public PEM must match in-memory output"
    );

    // Files are parseable PEM
    let priv_content = priv_pem_tmp.read_to_string().unwrap();
    assert!(pem::parse(&priv_content).is_ok());
    let pub_content = pub_pem_tmp.read_to_string().unwrap();
    assert!(pem::parse(&pub_content).is_ok());
}

#[test]
#[cfg(feature = "ecdsa")]
fn e2e_tempfile_ecdsa_round_trip() {
    let kp = fx().ecdsa("e2e-sink-ecdsa", EcdsaSpec::es256());

    let priv_tmp = kp.write_private_key_pkcs8_pem().unwrap();
    let pub_tmp = kp.write_public_key_spki_pem().unwrap();

    assert_eq!(
        priv_tmp.read_to_string().unwrap().len(),
        kp.private_key_pkcs8_pem().len(),
        "tempfile private PEM length must match"
    );
    assert_eq!(
        pub_tmp.read_to_string().unwrap().len(),
        kp.public_key_spki_pem().len(),
        "tempfile public PEM length must match"
    );
}

#[test]
#[cfg(feature = "ed25519")]
fn e2e_tempfile_ed25519_round_trip() {
    let kp = fx().ed25519("e2e-sink-ed", Ed25519Spec::new());

    let priv_tmp = kp.write_private_key_pkcs8_pem().unwrap();
    let pub_tmp = kp.write_public_key_spki_pem().unwrap();

    assert_eq!(
        priv_tmp.read_to_string().unwrap().len(),
        kp.private_key_pkcs8_pem().len(),
        "tempfile private PEM length must match"
    );
    assert_eq!(
        pub_tmp.read_to_string().unwrap().len(),
        kp.public_key_spki_pem().len(),
        "tempfile public PEM length must match"
    );
}

#[test]
#[cfg(feature = "rsa")]
fn e2e_tempfile_cleanup_on_drop() {
    let path = {
        let kp = fx().rsa("e2e-sink-drop", RsaSpec::rs256());
        let tmp = kp.write_private_key_pkcs8_pem().unwrap();
        let p = tmp.path().to_path_buf();
        assert!(p.exists());
        p
    };
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(!path.exists(), "tempfile must be cleaned up after drop");
}

// =========================================================================
// 7. Token pipeline
// =========================================================================

#[test]
#[cfg(feature = "token")]
fn e2e_token_api_key_pipeline() {
    let fx = deterministic_fx("e2e-token-v1");
    let tok = fx.token("e2e-api-key", TokenSpec::api_key());

    let val = tok.value();
    assert!(!val.is_empty());
    // API key prefix
    assert!(
        val.starts_with("uk_test_"),
        "API key should start with expected prefix"
    );

    // Determinism
    let fx2 = deterministic_fx("e2e-token-v1");
    let tok2 = fx2.token("e2e-api-key", TokenSpec::api_key());
    assert!(
        tok.value() == tok2.value(),
        "token must be deterministic for same seed+label"
    );

    // Different labels → different tokens
    let tok3 = fx.token("e2e-api-key-other", TokenSpec::api_key());
    assert!(
        tok.value() != tok3.value(),
        "different labels must produce different tokens"
    );
}

#[test]
#[cfg(feature = "token")]
fn e2e_token_bearer_pipeline() {
    let fx = deterministic_fx("e2e-token-v1");
    let tok = fx.token("e2e-bearer", TokenSpec::bearer());

    let val = tok.value();
    assert!(!val.is_empty());

    // Bearer authorization header
    let auth = tok.authorization_header();
    assert!(
        auth.starts_with("Bearer "),
        "authorization header should start with 'Bearer '"
    );
    assert!(
        auth.len() > "Bearer ".len(),
        "authorization header must contain a token value"
    );

    // Determinism
    let fx2 = deterministic_fx("e2e-token-v1");
    let tok2 = fx2.token("e2e-bearer", TokenSpec::bearer());
    assert!(
        tok.value() == tok2.value(),
        "bearer token must be deterministic for same seed+label"
    );
}

#[test]
#[cfg(feature = "token")]
fn e2e_token_oauth_pipeline() {
    let fx = deterministic_fx("e2e-token-v1");
    let tok = fx.token("e2e-oauth", TokenSpec::oauth_access_token());

    let val = tok.value();
    assert!(!val.is_empty());

    // Determinism
    let fx2 = deterministic_fx("e2e-token-v1");
    let tok2 = fx2.token("e2e-oauth", TokenSpec::oauth_access_token());
    assert!(
        tok.value() == tok2.value(),
        "OAuth token must be deterministic for same seed+label"
    );
}

#[test]
#[cfg(feature = "token")]
fn e2e_token_all_types_differ() {
    let fx = deterministic_fx("e2e-token-v1");
    let api = fx.token("e2e-multi", TokenSpec::api_key());
    let bearer = fx.token("e2e-multi", TokenSpec::bearer());
    let oauth = fx.token("e2e-multi", TokenSpec::oauth_access_token());

    // Different specs produce different tokens even with the same label
    let values: std::collections::HashSet<&str> =
        [api.value(), bearer.value(), oauth.value()].into();
    assert_eq!(
        values.len(),
        3,
        "all token types must produce distinct values"
    );
}

// =========================================================================
// 8. HMAC pipeline
// =========================================================================

#[test]
#[cfg(all(feature = "hmac", feature = "jwk"))]
fn e2e_hmac_full_pipeline() {
    let fx = deterministic_fx("e2e-hmac-v1");

    for (label, spec, expected_len) in [
        ("e2e-hs256", HmacSpec::hs256(), 32),
        ("e2e-hs384", HmacSpec::hs384(), 48),
        ("e2e-hs512", HmacSpec::hs512(), 64),
    ] {
        let secret = fx.hmac(label, spec);
        assert_eq!(
            secret.secret_bytes().len(),
            expected_len,
            "HMAC secret length for {label}"
        );

        // KID is non-empty
        let kid = secret.kid();
        assert!(!kid.is_empty());

        // JWK fields
        let jwk = secret.jwk();
        let jwk_val = jwk.to_value();
        assert_eq!(jwk_val["kty"], "oct");

        // JWKS wrapping
        let jwks = secret.jwks();
        assert_eq!(jwks.keys.len(), 1);

        // Determinism
        let fx2 = deterministic_fx("e2e-hmac-v1");
        let secret2 = fx2.hmac(label, spec);
        assert!(
            secret.secret_bytes() == secret2.secret_bytes(),
            "HMAC secret must be deterministic for {label}"
        );
        assert_eq!(secret.kid(), secret2.kid());
    }
}

// =========================================================================
// 9. Cross-type KID uniqueness
// =========================================================================

#[test]
#[cfg(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "jwk"
))]
fn e2e_kid_uniqueness_across_types() {
    let fx = deterministic_fx("e2e-kid-unique-v1");

    let rsa_kid = fx.rsa("e2e-kid", RsaSpec::rs256()).kid();
    let ec_kid = fx.ecdsa("e2e-kid", EcdsaSpec::es256()).kid();
    let ed_kid = fx.ed25519("e2e-kid", Ed25519Spec::new()).kid();

    // Same label but different key types → different KIDs
    let kids: std::collections::HashSet<String> = [rsa_kid, ec_kid, ed_kid].into();
    assert_eq!(kids.len(), 3, "KIDs must be unique across key types");
}
