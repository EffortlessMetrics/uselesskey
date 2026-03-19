//! Basic HMAC secret generation for HS256, HS384, and HS512.
//!
//! Demonstrates generating HMAC secrets of different sizes and
//! accessing them as raw bytes and (with `jwk` feature) as JWK/JWKS.
//!
//! Run with: cargo run -p uselesskey --example basic_hmac --features "hmac,jwk"

#[cfg(all(feature = "hmac", feature = "jwk"))]
fn main() {
    use uselesskey::{Factory, HmacFactoryExt, HmacSpec};

    let fx = Factory::random();

    // =========================================================================
    // 1. HS256 — 32-byte secret
    // =========================================================================
    println!("=== HMAC HS256 (32 bytes) ===");
    let hs256 = fx.hmac("jwt-signer", HmacSpec::hs256());
    println!("  Secret length : {} bytes", hs256.secret_bytes().len());
    assert_eq!(hs256.secret_bytes().len(), 32);

    let jwk256 = hs256.jwk().to_value();
    println!("  JWK kty : {}", jwk256["kty"]);
    println!("  JWK alg : {}", jwk256["alg"]);
    println!("  kid     : {}", hs256.kid());

    // =========================================================================
    // 2. HS384 — 48-byte secret
    // =========================================================================
    println!("\n=== HMAC HS384 (48 bytes) ===");
    let hs384 = fx.hmac("jwt-signer", HmacSpec::hs384());
    println!("  Secret length : {} bytes", hs384.secret_bytes().len());
    assert_eq!(hs384.secret_bytes().len(), 48);

    let jwk384 = hs384.jwk().to_value();
    println!("  JWK alg : {}", jwk384["alg"]);
    println!("  kid     : {}", hs384.kid());

    // =========================================================================
    // 3. HS512 — 64-byte secret
    // =========================================================================
    println!("\n=== HMAC HS512 (64 bytes) ===");
    let hs512 = fx.hmac("jwt-signer", HmacSpec::hs512());
    println!("  Secret length : {} bytes", hs512.secret_bytes().len());
    assert_eq!(hs512.secret_bytes().len(), 64);

    let jwk512 = hs512.jwk().to_value();
    println!("  JWK alg : {}", jwk512["alg"]);
    println!("  kid     : {}", hs512.kid());

    // =========================================================================
    // 4. JWKS (single-key set)
    // =========================================================================
    println!("\n=== HMAC JWKS ===");
    let jwks = hs256.jwks().to_value();
    let key_count = jwks["keys"].as_array().map_or(0, |a| a.len());
    println!("  Key count : {key_count}");

    // =========================================================================
    // 5. Caching: same label + spec → same secret
    // =========================================================================
    let again = fx.hmac("jwt-signer", HmacSpec::hs256());
    assert_eq!(hs256.secret_bytes(), again.secret_bytes());
    println!("\n✓ Cache hit verified: same label + spec → same secret");
}

#[cfg(not(all(feature = "hmac", feature = "jwk")))]
fn main() {
    eprintln!("Enable 'hmac' and 'jwk' features:");
    eprintln!("  cargo run -p uselesskey --example basic_hmac --features \"hmac,jwk\"");
}
