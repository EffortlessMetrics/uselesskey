#![no_main]

use libfuzzer_sys::fuzz_target;

use uselesskey::{Factory, Seed, TokenFactoryExt, TokenSpec};

fuzz_target!(|data: &[u8]| {
    // Use the first 32 bytes as seed material, padding with zeros if short.
    let mut seed_bytes = [0u8; 32];
    let len = data.len().min(32);
    seed_bytes[..len].copy_from_slice(&data[..len]);

    let fx = Factory::deterministic(Seed::new(seed_bytes));

    // Generate tokens for all 3 specs and assert basic format invariants.

    let api_key = fx.token("fuzz", TokenSpec::api_key());
    assert!(
        api_key.value().starts_with("uk_test_"),
        "API key must start with uk_test_"
    );

    let bearer = fx.token("fuzz", TokenSpec::bearer());
    assert_eq!(
        bearer.value().len(),
        43,
        "Bearer token must be 43 characters (base64url of 32 bytes)"
    );

    let oauth = fx.token("fuzz", TokenSpec::oauth_access_token());
    assert_eq!(
        oauth.value().matches('.').count(),
        2,
        "OAuth token must have exactly 2 dots (3 JWT segments)"
    );
});
