//! JWK and JWKS generation with multiple key types.
//!
//! Demonstrates building individual JWKs, combining them into a JWKS using
//! `JwksBuilder`, and inspecting key metadata — without printing key material.
//!
//! Run with: cargo run -p uselesskey --example jwk_generation --features "ecdsa,ed25519,hmac,rsa,jwk"

#[cfg(all(
    feature = "jwk",
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "hmac"
))]
fn main() {
    use uselesskey::jwk::JwksBuilder;
    use uselesskey::{
        EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory, HmacFactoryExt,
        HmacSpec, RsaFactoryExt, RsaSpec, Seed,
    };

    let fx = Factory::deterministic(Seed::from_env_value("jwk-generation-demo").unwrap());

    // =========================================================================
    // 1. Generate individual JWKs from each key type
    // =========================================================================
    println!("=== Individual JWKs ===\n");

    // RSA (RS256)
    let rsa = fx.rsa("api-auth", RsaSpec::rs256());
    let rsa_jwk = rsa.public_jwk().to_value();
    println!(
        "RSA      : kty={}, alg={}, kid={}",
        rsa_jwk["kty"],
        rsa_jwk["alg"],
        rsa.kid()
    );

    // ECDSA P-256 (ES256)
    let ec256 = fx.ecdsa("token-ec", EcdsaSpec::es256());
    let ec256_jwk = ec256.public_jwk().to_value();
    println!(
        "ECDSA    : kty={}, crv={}, alg={}, kid={}",
        ec256_jwk["kty"],
        ec256_jwk["crv"],
        ec256_jwk["alg"],
        ec256.kid()
    );

    // Ed25519 (EdDSA)
    let ed = fx.ed25519("signing-ed", Ed25519Spec::default());
    let ed_jwk = ed.public_jwk().to_value();
    println!(
        "Ed25519  : kty={}, crv={}, alg={}, kid={}",
        ed_jwk["kty"],
        ed_jwk["crv"],
        ed_jwk["alg"],
        ed.kid()
    );

    // HMAC (HS256) — symmetric, so no "public" vs "private" distinction
    let hmac = fx.hmac("session-mac", HmacSpec::hs256());
    let hmac_jwk = hmac.jwk().to_value();
    println!(
        "HMAC     : kty={}, alg={}, kid={}",
        hmac_jwk["kty"],
        hmac_jwk["alg"],
        hmac.kid()
    );

    // =========================================================================
    // 2. Build a multi-key JWKS with JwksBuilder (public keys only)
    // =========================================================================
    println!("\n=== Multi-Key JWKS (Public Keys) ===\n");

    // JwksBuilder collects public JWKs and sorts them by kid for stable output.
    let jwks = JwksBuilder::new()
        .add_public(rsa.public_jwk())
        .add_public(ec256.public_jwk())
        .add_public(ed.public_jwk())
        .build();

    let jwks_val = jwks.to_value();
    let keys = jwks_val["keys"].as_array().unwrap();
    println!("JWKS contains {} public keys:", keys.len());
    for key in keys {
        println!(
            "  kid={:<20} kty={:<4} alg={}",
            key["kid"].as_str().unwrap_or("?"),
            key["kty"].as_str().unwrap_or("?"),
            key["alg"].as_str().unwrap_or("?"),
        );
    }

    // Verify deterministic ordering: keys are sorted by kid.
    let kids: Vec<&str> = keys.iter().filter_map(|k| k["kid"].as_str()).collect();
    let mut sorted = kids.clone();
    sorted.sort();
    assert_eq!(kids, sorted, "JWKS keys must be sorted by kid");
    println!("\n✓ Keys are sorted by kid (deterministic ordering)");

    // =========================================================================
    // 3. Per-key JWKS (single-key sets)
    // =========================================================================
    println!("\n=== Per-Key JWKS ===\n");

    println!(
        "RSA JWKS     : {} key(s)",
        rsa.public_jwks().to_value()["keys"]
            .as_array()
            .unwrap()
            .len()
    );
    println!(
        "ECDSA JWKS   : {} key(s)",
        ec256.public_jwks().to_value()["keys"]
            .as_array()
            .unwrap()
            .len()
    );
    println!(
        "Ed25519 JWKS : {} key(s)",
        ed.public_jwks().to_value()["keys"]
            .as_array()
            .unwrap()
            .len()
    );
    println!(
        "HMAC JWKS    : {} key(s)",
        hmac.jwks().to_value()["keys"].as_array().unwrap().len()
    );

    // =========================================================================
    // 4. Serialize JWKS as JSON (for mock OIDC/JWKS endpoints)
    // =========================================================================
    println!("\n=== JWKS JSON for Mock Servers ===\n");

    let json_str = jwks.to_string();
    println!("JSON length    : {} bytes", json_str.len());
    println!("Content-Type   : application/json");
    println!("Serve at       : GET /.well-known/jwks.json");

    println!("\n=== All JWK generation checks passed ===");
}

#[cfg(not(all(
    feature = "jwk",
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "hmac"
)))]
fn main() {
    eprintln!("Enable required features:");
    eprintln!(
        "  cargo run -p uselesskey --example jwk_generation --features \"ecdsa,ed25519,hmac,rsa,jwk\""
    );
}
