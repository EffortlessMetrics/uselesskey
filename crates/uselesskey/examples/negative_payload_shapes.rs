#![forbid(unsafe_code)]

//! Scanner-safe negative JWK/JWKS and token payload shapes.
//!
//! Demonstrates negative fixtures for downstream parser and validator tests
//! without printing secret-shaped material.
//!
//! Run with: cargo run -p uselesskey --example negative_payload_shapes --features "rsa,jwk,token"

#[cfg(all(feature = "rsa", feature = "jwk", feature = "token"))]
fn main() {
    use uselesskey::jwk::{NegativeJwk, NegativeJwks};
    use uselesskey::{
        Factory, NegativeToken, RsaFactoryExt, RsaSpec, Seed, TokenFactoryExt, TokenSpec,
    };

    let fx = Factory::deterministic(Seed::from_env_value("negative-payload-demo").unwrap());

    // -------------------------------------------------------------------------
    // JWK negatives: keep the object realistic, but make one validation rule fail.
    // -------------------------------------------------------------------------
    let signing_key = fx.rsa("issuer", RsaSpec::rs256());
    let public_jwk = signing_key.public_jwk();

    let missing_kid = public_jwk.negative_value(NegativeJwk::MissingKid);
    assert!(missing_kid.get("kid").is_none());
    assert_eq!(missing_kid["kty"], "RSA");

    let unsupported_alg = public_jwk.negative_value(NegativeJwk::UnsupportedAlg);
    assert_eq!(unsupported_alg["alg"], "UK-UNSUPPORTED");

    let malformed_field = public_jwk.negative_value(NegativeJwk::MalformedField);
    assert!(
        malformed_field["n"]
            .as_str()
            .expect("RSA modulus should stay present")
            .contains('!'),
        "malformed material should be scanner-safe invalid base64url"
    );

    println!("JWK negatives: missing kid, unsupported alg, malformed material");

    // -------------------------------------------------------------------------
    // JWKS negatives: exercise key-set validation, not individual keygen.
    // -------------------------------------------------------------------------
    let jwks = signing_key.public_jwks();

    let duplicate_kid = jwks.negative_value(NegativeJwks::DuplicateKid);
    let duplicate_kid_keys = duplicate_kid["keys"].as_array().expect("keys array");
    assert_eq!(duplicate_kid_keys.len(), 2);
    assert_eq!(duplicate_kid_keys[0]["kid"], duplicate_kid_keys[1]["kid"]);
    assert_ne!(duplicate_kid_keys[0], duplicate_kid_keys[1]);

    let empty = jwks.negative_value(NegativeJwks::EmptyKeys);
    assert!(empty["keys"].as_array().expect("keys array").is_empty());

    println!("JWKS negatives: duplicate kid, empty keys");

    // -------------------------------------------------------------------------
    // Token negatives: JWT/API-key/bearer near-misses that stay scanner-safe.
    // -------------------------------------------------------------------------
    let oauth = fx.token("auth-service", TokenSpec::oauth_access_token());

    let malformed_jwt = oauth.negative_value(NegativeToken::MalformedJwtSegmentCount);
    assert_eq!(malformed_jwt.matches('.').count(), 1);
    assert_ne!(malformed_jwt, oauth.value());

    let bad_base64url = oauth.negative_value(NegativeToken::BadBase64UrlSegment);
    assert_eq!(bad_base64url.matches('.').count(), 2);
    assert!(bad_base64url.contains('!'));

    let alg_none = oauth.negative_value(NegativeToken::AlgNone);
    assert_eq!(alg_none.matches('.').count(), 2);
    assert_ne!(alg_none, oauth.value());

    let bearer = fx.token("session", TokenSpec::bearer());
    let malformed_bearer = bearer.negative_value(NegativeToken::MalformedBearer);
    assert!(malformed_bearer.contains('!'));
    assert_ne!(malformed_bearer, bearer.value());

    let api_key = fx.token("billing", TokenSpec::api_key());
    let near_miss = api_key.negative_value(NegativeToken::NearMissApiKey);
    assert!(near_miss.starts_with("uk_tset_"));
    assert!(!near_miss.starts_with("uk_test_"));

    println!("Token negatives: malformed JWT, alg none, malformed bearer, API-key near miss");
    println!("All negative payload shape checks passed");
}

#[cfg(not(all(feature = "rsa", feature = "jwk", feature = "token")))]
fn main() {
    eprintln!("Enable rsa, jwk, and token features:");
    eprintln!(
        "  cargo run -p uselesskey --example negative_payload_shapes --features \"rsa,jwk,token\""
    );
}
