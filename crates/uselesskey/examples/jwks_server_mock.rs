//! Mock JWKS endpoint for JWT validation testing.
//!
//! This example demonstrates how to generate a JWKS (JSON Web Key Set) response
//! body suitable for serving from a mock `/.well-known/jwks.json` endpoint.
//!
//! Common use cases:
//! - Mock an OAuth2/OIDC provider's JWKS endpoint in integration tests
//! - Test JWT validation against multiple key types (RSA, ECDSA, Ed25519)
//! - Simulate key rotation by building JWKS with old and new keys
//! - Verify your code handles multi-algorithm JWKS correctly
//!
//! Run with: cargo run -p uselesskey --example jwks_server_mock --features "rsa,ecdsa,ed25519,jwk"

#[cfg(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "jwk"
))]
fn main() {
    use uselesskey::jwk::JwksBuilder;
    use uselesskey::{
        EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory, RsaFactoryExt,
        RsaSpec, Seed,
    };

    // Use a deterministic factory so the JWKS is stable across test runs.
    let seed = Seed::from_env_value("jwks-mock-demo").unwrap();
    let fx = Factory::deterministic(seed);

    // =========================================================================
    // 1. Single-key JWKS (simplest case)
    // =========================================================================
    println!("=== Single-Key JWKS (RS256) ===\n");

    let rsa_key = fx.rsa("auth-service", RsaSpec::rs256());

    // Each key fixture has a stable `kid` derived from the public key material.
    println!("Key ID (kid): {}", rsa_key.kid());

    // public_jwks() returns a JWKS containing just this key's public JWK.
    let single_jwks = rsa_key.public_jwks();
    println!("JWKS response body:");
    println!("{single_jwks}");

    // Verify the structure matches what /.well-known/jwks.json should return.
    let value = single_jwks.to_value();
    assert!(value["keys"].is_array());
    assert_eq!(value["keys"].as_array().unwrap().len(), 1);
    assert_eq!(value["keys"][0]["kty"], "RSA");
    assert_eq!(value["keys"][0]["alg"], "RS256");
    assert_eq!(value["keys"][0]["use"], "sig");

    // =========================================================================
    // 2. Multi-algorithm JWKS (RSA + ECDSA + Ed25519)
    // =========================================================================
    println!("\n=== Multi-Algorithm JWKS ===\n");

    let ecdsa_key = fx.ecdsa("auth-service", EcdsaSpec::es256());
    let ed25519_key = fx.ed25519("auth-service", Ed25519Spec::default());

    // Use JwksBuilder to combine public JWKs from different key types.
    let multi_jwks = JwksBuilder::new()
        .add_public(rsa_key.public_jwk())
        .add_public(ecdsa_key.public_jwk())
        .add_public(ed25519_key.public_jwk())
        .build();

    println!("Combined JWKS with 3 key types:");
    println!("{multi_jwks}");

    let multi_value = multi_jwks.to_value();
    let keys = multi_value["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 3);

    // JwksBuilder sorts keys by kid for deterministic ordering.
    println!("\nKey summary:");
    for key in keys {
        println!(
            "  kid={}, kty={}, alg={}",
            key["kid"].as_str().unwrap_or("?"),
            key["kty"].as_str().unwrap_or("?"),
            key["alg"].as_str().unwrap_or("?"),
        );
    }

    // =========================================================================
    // 3. Key rotation scenario (old key + new key)
    // =========================================================================
    println!("\n=== Key Rotation Scenario ===\n");

    // Simulate an auth service that has rotated its signing key.
    // During the transition window, both keys must be in the JWKS
    // so tokens signed with either key can be verified.
    let old_key = fx.rsa("auth-v1", RsaSpec::rs256());
    let new_key = fx.rsa("auth-v2", RsaSpec::rs256());

    println!("Old key kid: {}", old_key.kid());
    println!("New key kid: {}", new_key.kid());
    assert_ne!(
        old_key.kid(),
        new_key.kid(),
        "different labels → different kids"
    );

    let rotation_jwks = JwksBuilder::new()
        .add_public(old_key.public_jwk())
        .add_public(new_key.public_jwk())
        .build();

    println!("\nRotation JWKS (both keys present):");
    println!("{rotation_jwks}");

    let rotation_value = rotation_jwks.to_value();
    assert_eq!(rotation_value["keys"].as_array().unwrap().len(), 2);

    // =========================================================================
    // 4. Using the JWKS JSON in a mock server
    // =========================================================================
    println!("\n=== Mock Server Integration Pattern ===\n");

    // In a real test, you'd serve this JSON from an HTTP mock server.
    // Here's how you'd get the JSON string for the response body:
    let jwks_json = multi_jwks.to_string();

    println!("Response body for GET /.well-known/jwks.json:");
    println!("  Content-Type: application/json");
    println!("  Content-Length: {}", jwks_json.len());
    println!("  Body: {} bytes of JSON", jwks_json.len());

    // You can also get a serde_json::Value for programmatic access.
    let jwks_value = multi_jwks.to_value();
    assert!(jwks_value.is_object());
    assert!(jwks_value["keys"].is_array());

    // =========================================================================
    // 5. Per-key JWKS and individual JWK access
    // =========================================================================
    println!("\n=== Individual JWK Access ===\n");

    // Each key type can produce its own single-key JWKS.
    println!(
        "RSA JWKS:     {} keys",
        rsa_key.public_jwks().to_value()["keys"]
            .as_array()
            .unwrap()
            .len()
    );
    println!(
        "ECDSA JWKS:   {} keys",
        ecdsa_key.public_jwks().to_value()["keys"]
            .as_array()
            .unwrap()
            .len()
    );
    println!(
        "Ed25519 JWKS: {} keys",
        ed25519_key.public_jwks().to_value()["keys"]
            .as_array()
            .unwrap()
            .len()
    );

    // Access individual JWK values for assertion in tests.
    let rsa_jwk_value = rsa_key.public_jwk().to_value();
    assert_eq!(rsa_jwk_value["kty"], "RSA");
    assert!(
        rsa_jwk_value["n"].is_string(),
        "RSA JWK must have modulus 'n'"
    );
    assert!(
        rsa_jwk_value["e"].is_string(),
        "RSA JWK must have exponent 'e'"
    );

    let ec_jwk_value = ecdsa_key.public_jwk().to_value();
    assert_eq!(ec_jwk_value["kty"], "EC");
    assert_eq!(ec_jwk_value["crv"], "P-256");
    assert!(
        ec_jwk_value["x"].is_string(),
        "EC JWK must have 'x' coordinate"
    );
    assert!(
        ec_jwk_value["y"].is_string(),
        "EC JWK must have 'y' coordinate"
    );

    let okp_jwk_value = ed25519_key.public_jwk().to_value();
    assert_eq!(okp_jwk_value["kty"], "OKP");
    assert_eq!(okp_jwk_value["crv"], "Ed25519");

    // =========================================================================
    // 6. Determinism verification
    // =========================================================================
    println!("\n=== Determinism Verification ===\n");

    // Recreate the factory with the same seed — output must be identical.
    let fx2 = Factory::deterministic(Seed::from_env_value("jwks-mock-demo").unwrap());
    let rsa_key2 = fx2.rsa("auth-service", RsaSpec::rs256());

    assert_eq!(rsa_key.kid(), rsa_key2.kid());
    assert_eq!(
        rsa_key.public_jwks().to_string(),
        rsa_key2.public_jwks().to_string(),
    );
    println!("Verified: same seed → identical JWKS output");
    println!("This means your mock server returns stable keys across test runs.");

    println!("\n=== All JWKS mock examples completed successfully ===");
}

#[cfg(not(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "jwk"
)))]
fn main() {
    eprintln!("Enable required features to run this example:");
    eprintln!(
        "  cargo run -p uselesskey --example jwks_server_mock --features \"rsa,ecdsa,ed25519,jwk\""
    );
}
