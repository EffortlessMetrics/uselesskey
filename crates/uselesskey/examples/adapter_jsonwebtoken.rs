//! Adapter example: uselesskey + jsonwebtoken crate.
//!
//! Demonstrates signing and verifying JWTs using uselesskey fixtures
//! with the popular `jsonwebtoken` crate via `uselesskey-jsonwebtoken`.
//!
//! Run with: cargo run -p uselesskey --example adapter_jsonwebtoken --features full

#[cfg(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "hmac"
))]
fn main() {
    use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
    use serde::{Deserialize, Serialize};
    use uselesskey::{
        EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory, HmacFactoryExt,
        HmacSpec, RsaFactoryExt, RsaSpec,
    };
    use uselesskey_jsonwebtoken::JwtKeyExt;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Claims {
        sub: String,
        exp: usize,
    }

    let fx = Factory::random();
    let claims = Claims {
        sub: "user-42".to_string(),
        exp: 2_000_000_000,
    };

    // =========================================================================
    // 1. RSA (RS256) — sign and verify
    // =========================================================================
    println!("=== RSA RS256 ===\n");

    let rsa = fx.rsa("jwt-issuer", RsaSpec::rs256());
    let token = encode(&Header::new(Algorithm::RS256), &claims, &rsa.encoding_key()).unwrap();

    let decoded = decode::<Claims>(
        &token,
        &rsa.decoding_key(),
        &Validation::new(Algorithm::RS256),
    )
    .unwrap();

    assert_eq!(decoded.claims, claims);
    println!("  Token length : {} chars", token.len());
    println!("  Verified     : ✓");

    // =========================================================================
    // 2. ECDSA (ES256) — sign and verify
    // =========================================================================
    println!("\n=== ECDSA ES256 ===\n");

    let ec = fx.ecdsa("jwt-issuer-ec", EcdsaSpec::es256());
    let ec_token = encode(&Header::new(Algorithm::ES256), &claims, &ec.encoding_key()).unwrap();

    let ec_decoded = decode::<Claims>(
        &ec_token,
        &ec.decoding_key(),
        &Validation::new(Algorithm::ES256),
    )
    .unwrap();

    assert_eq!(ec_decoded.claims, claims);
    println!("  Token length : {} chars", ec_token.len());
    println!("  Verified     : ✓");

    // =========================================================================
    // 3. Ed25519 (EdDSA) — sign and verify
    // =========================================================================
    println!("\n=== Ed25519 EdDSA ===\n");

    let ed = fx.ed25519("jwt-issuer-ed", Ed25519Spec::default());
    let ed_token = encode(&Header::new(Algorithm::EdDSA), &claims, &ed.encoding_key()).unwrap();

    let ed_decoded = decode::<Claims>(
        &ed_token,
        &ed.decoding_key(),
        &Validation::new(Algorithm::EdDSA),
    )
    .unwrap();

    assert_eq!(ed_decoded.claims, claims);
    println!("  Token length : {} chars", ed_token.len());
    println!("  Verified     : ✓");

    // =========================================================================
    // 4. HMAC (HS256) — sign and verify
    // =========================================================================
    println!("\n=== HMAC HS256 ===\n");

    let hmac = fx.hmac("jwt-secret", HmacSpec::hs256());
    let hmac_token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &hmac.encoding_key(),
    )
    .unwrap();

    let hmac_decoded = decode::<Claims>(
        &hmac_token,
        &hmac.decoding_key(),
        &Validation::new(Algorithm::HS256),
    )
    .unwrap();

    assert_eq!(hmac_decoded.claims, claims);
    println!("  Token length : {} chars", hmac_token.len());
    println!("  Verified     : ✓");

    // =========================================================================
    // 5. Cross-key verification failure (proves keys are distinct)
    // =========================================================================
    println!("\n=== Cross-Key Verification ===\n");

    let other_rsa = fx.rsa("different-issuer", RsaSpec::rs256());
    let result = decode::<Claims>(
        &token,
        &other_rsa.decoding_key(),
        &Validation::new(Algorithm::RS256),
    );
    assert!(result.is_err());
    println!("  Wrong key → verification fails : ✓");

    // =========================================================================
    // 6. Token size comparison across algorithms
    // =========================================================================
    println!("\n=== Token Size Comparison ===\n");
    println!("  RS256  : {} chars", token.len());
    println!("  ES256  : {} chars", ec_token.len());
    println!("  EdDSA  : {} chars", ed_token.len());
    println!("  HS256  : {} chars", hmac_token.len());

    println!("\n=== All jsonwebtoken adapter examples passed ===");
}

#[cfg(not(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "hmac"
)))]
fn main() {
    eprintln!("Enable all key type features:");
    eprintln!("  cargo run -p uselesskey --example adapter_jsonwebtoken --features full");
}
