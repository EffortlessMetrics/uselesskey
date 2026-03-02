//! Token fixture generation: API keys, bearer tokens, OAuth tokens.
//!
//! Demonstrates generating realistic test-token shapes that look like
//! real secrets but are deterministic and safe for version control.
//!
//! Run with: cargo run -p uselesskey --example token_generation --features full

#[cfg(feature = "token")]
fn main() {
    use uselesskey::{Factory, Seed, TokenFactoryExt, TokenSpec};

    let fx = Factory::deterministic(Seed::from_env_value("token-demo").unwrap());

    // =========================================================================
    // 1. API Key — prefixed base62 token (e.g. uk_test_<base62>)
    // =========================================================================
    println!("=== API Key Token ===\n");

    let api_key = fx.token("billing-service", TokenSpec::api_key());
    let val = api_key.value();
    println!("  Kind   : {}", TokenSpec::api_key().kind_name());
    println!("  Length : {} chars", val.len());
    println!("  Prefix : {}", &val[..val.len().min(8)]);
    assert!(!val.is_empty());

    // =========================================================================
    // 2. Bearer Token — opaque base64url
    // =========================================================================
    println!("\n=== Bearer Token ===\n");

    let bearer = fx.token("session-service", TokenSpec::bearer());
    let bval = bearer.value();
    println!("  Kind   : {}", TokenSpec::bearer().kind_name());
    println!("  Length : {} chars", bval.len());
    assert!(!bval.is_empty());

    // =========================================================================
    // 3. OAuth Access Token — JWT-shaped (header.payload.signature)
    // =========================================================================
    println!("\n=== OAuth Access Token (JWT shape) ===\n");

    let oauth = fx.token("auth-service", TokenSpec::oauth_access_token());
    let oval = oauth.value();
    let dot_count = oval.chars().filter(|&c| c == '.').count();
    println!(
        "  Kind       : {}",
        TokenSpec::oauth_access_token().kind_name()
    );
    println!("  Length     : {} chars", oval.len());
    println!("  Dot count  : {} (expect 2 for JWT shape)", dot_count);
    assert_eq!(dot_count, 2, "JWT-shaped token must have exactly 2 dots");

    // =========================================================================
    // 4. Determinism: same seed + label + spec → same token
    // =========================================================================
    println!("\n=== Determinism ===\n");

    let api_key2 = fx.token("billing-service", TokenSpec::api_key());
    assert_eq!(api_key.value(), api_key2.value());
    println!("  Same seed + label → identical token : ✓");

    // Different label → different token.
    let api_key3 = fx.token("other-service", TokenSpec::api_key());
    assert_ne!(api_key.value(), api_key3.value());
    println!("  Different label → different token   : ✓");

    // =========================================================================
    // 5. All three side by side
    // =========================================================================
    println!("\n=== Summary ===\n");
    println!("  API Key  : {} chars", api_key.value().len());
    println!("  Bearer   : {} chars", bearer.value().len());
    println!("  OAuth    : {} chars", oauth.value().len());

    println!("\n=== All token examples passed ===");
}

#[cfg(not(feature = "token"))]
fn main() {
    eprintln!("Enable 'token' feature:");
    eprintln!("  cargo run -p uselesskey --example token_generation --features full");
}
