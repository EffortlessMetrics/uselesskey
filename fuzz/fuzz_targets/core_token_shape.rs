#![no_main]

use libfuzzer_sys::fuzz_target;

use uselesskey::Seed;
use uselesskey_core_token_shape::{authorization_scheme, generate_oauth_access_token, generate_token, TokenKind};

fuzz_target!(|data: &[u8]| {
    let mut seed = [0u8; 32];
    let len = data.len().min(32);
    seed[..len].copy_from_slice(&data[..len]);

    let seed = Seed::new(seed);

    let api_key = generate_token("fuzz", TokenKind::ApiKey, seed);
    let bearer = generate_token("fuzz", TokenKind::Bearer, seed);
    let oauth = generate_token("fuzz", TokenKind::OAuthAccessToken, seed);

    assert!(api_key.starts_with("uk_test_"));
    assert_eq!(bearer.len(), 43);
    assert_eq!(oauth.matches('.').count(), 2);

    assert_eq!(authorization_scheme(TokenKind::ApiKey), "ApiKey");
    assert_eq!(authorization_scheme(TokenKind::Bearer), "Bearer");
    assert_eq!(authorization_scheme(TokenKind::OAuthAccessToken), "Bearer");

    let _ = generate_oauth_access_token("fuzz", seed);
});
