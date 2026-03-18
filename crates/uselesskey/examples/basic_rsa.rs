//! Basic RSA key fixture generation.
//!
//! Demonstrates generating RSA keypairs and accessing them in
//! PEM, DER, and JWK formats — without printing actual key material.
//!
//! Run with: cargo run -p uselesskey --example basic_rsa --features "rsa,jwk"

#[cfg(all(feature = "rsa", feature = "jwk"))]
fn main() {
    use uselesskey::{Factory, RsaFactoryExt, RsaSpec};

    let fx = Factory::random();

    // Generate an RSA-2048 keypair configured for RS256 signing.
    let keypair = fx.rsa("my-service", RsaSpec::rs256());

    // --- PKCS#8 PEM (private key) ---
    let priv_pem = keypair.private_key_pkcs8_pem();
    let first_line = priv_pem.lines().next().unwrap_or("");
    println!("=== RSA Private Key (PKCS#8 PEM) ===");
    println!("  Header : {first_line}");
    println!("  Length : {} bytes", priv_pem.len());

    // --- PKCS#8 DER (private key) ---
    let priv_der = keypair.private_key_pkcs8_der();
    println!("\n=== RSA Private Key (PKCS#8 DER) ===");
    println!("  Length : {} bytes", priv_der.len());

    // --- SPKI PEM (public key) ---
    let pub_pem = keypair.public_key_spki_pem();
    let pub_first_line = pub_pem.lines().next().unwrap_or("");
    println!("\n=== RSA Public Key (SPKI PEM) ===");
    println!("  Header : {pub_first_line}");
    println!("  Length : {} bytes", pub_pem.len());

    // --- SPKI DER (public key) ---
    let pub_der = keypair.public_key_spki_der();
    println!("\n=== RSA Public Key (SPKI DER) ===");
    println!("  Length : {} bytes", pub_der.len());

    // --- JWK (public) ---
    let jwk = keypair.public_jwk();
    let jwk_val = jwk.to_value();
    println!("\n=== RSA Public JWK ===");
    println!("  kty : {}", jwk_val["kty"]);
    println!("  alg : {}", jwk_val["alg"]);
    println!("  use : {}", jwk_val["use"]);
    println!("  kid : {}", keypair.kid());

    // --- JWKS ---
    let jwks = keypair.public_jwks();
    let jwks_val = jwks.to_value();
    let key_count = jwks_val["keys"].as_array().map_or(0, |a| a.len());
    println!("\n=== RSA Public JWKS ===");
    println!("  Key count : {key_count}");

    // --- Tempfile output ---
    let temp = keypair
        .write_private_key_pkcs8_pem()
        .expect("write tempfile");
    println!("\n=== Tempfile ===");
    println!("  Path   : {}", temp.path().display());
    println!("  Exists : {}", temp.path().exists());

    // Caching: requesting the same label + spec returns the cached keypair.
    let same = fx.rsa("my-service", RsaSpec::rs256());
    assert_eq!(
        keypair.private_key_pkcs8_pem(),
        same.private_key_pkcs8_pem()
    );
    println!("\n✓ Cache hit verified: same label + spec → same key");
}

#[cfg(not(all(feature = "rsa", feature = "jwk")))]
fn main() {
    eprintln!("Enable 'rsa' and 'jwk' features:");
    eprintln!("  cargo run -p uselesskey --example basic_rsa --features \"rsa,jwk\"");
}
