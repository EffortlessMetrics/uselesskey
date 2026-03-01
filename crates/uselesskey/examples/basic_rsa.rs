//! Generate RSA key fixtures in various formats.
//!
//! Run with: `cargo run -p uselesskey --example basic_rsa --features "rsa jwk"`

use uselesskey::{Factory, RsaFactoryExt, RsaSpec, Seed};

fn main() {
    // --- Random mode ---
    let fx = Factory::random();
    let kp = fx.rsa("my-service", RsaSpec::rs256());

    println!("=== Random RSA-2048 (RS256) ===");
    #[cfg(feature = "jwk")]
    println!("KID:  {}", kp.kid());
    println!(
        "PEM:  {} bytes ({} lines)",
        kp.private_key_pkcs8_pem().len(),
        kp.private_key_pkcs8_pem().lines().count()
    );
    println!("DER:  {} bytes", kp.private_key_pkcs8_der().len());
    println!("SPKI: {} bytes", kp.public_key_spki_der().len());

    // --- Deterministic mode ---
    let seed = Seed::from_env_value("example-seed").unwrap();
    let fx = Factory::deterministic(seed);
    let kp1 = fx.rsa("issuer", RsaSpec::rs256());
    let kp2 = fx.rsa("issuer", RsaSpec::rs256());

    println!("\n=== Deterministic: same seed + label = same key ===");
    assert_eq!(kp1.private_key_pkcs8_pem(), kp2.private_key_pkcs8_pem());
    println!("✓ kp1 == kp2");

    // Order-independent: adding another fixture doesn't change existing ones
    let _extra = fx.rsa("audience", RsaSpec::rs256());
    let kp3 = fx.rsa("issuer", RsaSpec::rs256());
    assert_eq!(kp1.private_key_pkcs8_pem(), kp3.private_key_pkcs8_pem());
    println!("✓ kp1 == kp3 (order-independent)");

    // --- Tempfiles ---
    let tmp = kp1.write_private_key_pkcs8_pem().unwrap();
    println!("\n=== Tempfile ===");
    println!("Path: {:?}", tmp.path());
    println!("Exists: {}", tmp.path().exists());
}
