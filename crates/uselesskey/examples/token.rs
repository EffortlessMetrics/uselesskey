//! Token fixture generation: API keys, bearer tokens, and OAuth access tokens.
//!
//! Demonstrates generating realistic token shapes for testing without
//! committing secret-looking strings to version control.
//!
//! Run with:
//! ```sh
//! cargo run -p uselesskey --example token --features token
//! ```

#[cfg(feature = "token")]
fn main() {
    use uselesskey::prelude::*;

    let fx = Factory::deterministic(Seed::from_env_value("token-example-seed").unwrap());

    // ── API Key ──────────────────────────────────────────────────────────
    println!("=== API Key ===");
    let api_key = fx.token("my-service", TokenSpec::api_key());

    println!("  Value:  {}", api_key.value());
    println!("  Header: {}", api_key.authorization_header());

    // API keys have a recognizable prefix
    assert!(api_key.value().starts_with("uk_test_"));
    println!("  Prefix: uk_test_ ✓");

    // ── Bearer Token ─────────────────────────────────────────────────────
    println!("\n=== Bearer Token ===");
    let bearer = fx.token("session-store", TokenSpec::bearer());

    println!("  Value:  {}", bearer.value());
    println!("  Header: {}", bearer.authorization_header());

    assert!(bearer.authorization_header().starts_with("Bearer "));
    println!("  Scheme: Bearer ✓");

    // ── OAuth Access Token (JWT shape) ───────────────────────────────────
    println!("\n=== OAuth Access Token ===");
    let oauth = fx.token("identity-provider", TokenSpec::oauth_access_token());

    println!("  Value:  {}...", &oauth.value()[..40]);
    println!("  Header: {}...", &oauth.authorization_header()[..48]);

    // OAuth tokens have JWT shape: header.payload.signature
    let segments: Vec<&str> = oauth.value().split('.').collect();
    assert_eq!(segments.len(), 3, "OAuth token has three JWT segments");
    println!("  JWT segments: {} ✓", segments.len());

    // ── Determinism ──────────────────────────────────────────────────────
    println!("\n=== Determinism ===");
    let api_key_again = fx.token("my-service", TokenSpec::api_key());
    assert_eq!(api_key.value(), api_key_again.value());
    println!("  Same seed+label → identical token ✓");

    // ── Different labels produce different tokens ────────────────────────
    println!("\n=== Label Isolation ===");
    let key_a = fx.token("service-a", TokenSpec::api_key());
    let key_b = fx.token("service-b", TokenSpec::api_key());
    assert_ne!(key_a.value(), key_b.value());
    println!("  Different labels → different tokens ✓");

    // ── Debug output never leaks the token value ─────────────────────────
    println!("\n=== Safe Debug ===");
    let debug_output = format!("{:?}", api_key);
    assert!(!debug_output.contains(api_key.value()));
    println!("  Debug output: {debug_output}");
    println!("  Token value not leaked in Debug ✓");

    println!("\nAll token fixtures generated successfully!");
}

#[cfg(not(feature = "token"))]
fn main() {
    eprintln!("Enable the 'token' feature to run this example:");
    eprintln!("  cargo run -p uselesskey --example token --features token");
}
