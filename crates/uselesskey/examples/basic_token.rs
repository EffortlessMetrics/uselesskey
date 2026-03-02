//! Token fixtures: API key, bearer, and OAuth access-token shapes.
//!
//! Demonstrates generating test tokens in common formats without
//! committing real secrets to version control.
//!
//! Run with: cargo run -p uselesskey --example basic_token --features token

#[cfg(feature = "token")]
fn main() {
    use uselesskey::{Factory, Seed, TokenFactoryExt, TokenSpec};

    // Use a deterministic factory so output is reproducible.
    let fx = Factory::deterministic(Seed::from_env_value("token-demo").unwrap());

    // =========================================================================
    // 1. API key — `uk_test_<base62>` format
    // =========================================================================
    println!("=== API Key ===\n");
    let api_key = fx.token("my-api", TokenSpec::api_key());
    println!("  Value  : {}", api_key.value());
    println!("  Header : {}", api_key.authorization_header());
    assert!(api_key.value().starts_with("uk_test_"));

    // =========================================================================
    // 2. Bearer token — base64url-encoded opaque blob
    // =========================================================================
    println!("\n=== Bearer Token ===\n");
    let bearer = fx.token("session", TokenSpec::bearer());
    println!("  Value  : {}", bearer.value());
    println!("  Header : {}", bearer.authorization_header());
    println!("  Length : {} chars", bearer.value().len());

    // =========================================================================
    // 3. OAuth / JWT-shaped access token
    // =========================================================================
    println!("\n=== OAuth Access Token ===\n");
    let oauth = fx.token("oauth-provider", TokenSpec::oauth_access_token());
    println!("  Value  : {}", oauth.value());
    println!("  Header : {}", oauth.authorization_header());
    // JWT-shaped tokens have three dot-separated segments.
    let dot_count = oauth.value().matches('.').count();
    println!("  Segments: {} (JWT-shaped)", dot_count + 1);

    // =========================================================================
    // 4. Variant support — multiple tokens from the same label
    // =========================================================================
    println!("\n=== Token Variants ===\n");
    let admin_key = fx.token_with_variant("my-api", TokenSpec::api_key(), "admin");
    let readonly_key = fx.token_with_variant("my-api", TokenSpec::api_key(), "readonly");
    assert_ne!(admin_key.value(), readonly_key.value());
    println!("  admin   : {}", admin_key.value());
    println!("  readonly: {}", readonly_key.value());

    // =========================================================================
    // 5. Caching
    // =========================================================================
    let again = fx.token("my-api", TokenSpec::api_key());
    assert_eq!(api_key.value(), again.value());
    println!("\n✓ Cache hit verified: same label + spec → same token");
}

#[cfg(not(feature = "token"))]
fn main() {
    eprintln!("Enable 'token' feature:");
    eprintln!("  cargo run -p uselesskey --example basic_token --features token");
}
