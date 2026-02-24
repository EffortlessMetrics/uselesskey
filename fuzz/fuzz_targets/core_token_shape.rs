#![no_main]

use libfuzzer_sys::fuzz_target;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use uselesskey_core_token_shape::{TokenKind, authorization_scheme, generate_token, generate_oauth_access_token};

fuzz_target!(|data: &[u8]| {
    let mut seed = [0u8; 32];
    let len = data.len().min(32);
    seed[..len].copy_from_slice(&data[..len]);

    let mut api_rng = ChaCha20Rng::from_seed(seed);
    let mut bearer_rng = ChaCha20Rng::from_seed(seed);
    let mut oauth_rng = ChaCha20Rng::from_seed(seed);

    let api_key = generate_token("fuzz", TokenKind::ApiKey, &mut api_rng);
    let bearer = generate_token("fuzz", TokenKind::Bearer, &mut bearer_rng);
    let oauth = generate_token("fuzz", TokenKind::OAuthAccessToken, &mut oauth_rng);

    assert!(api_key.starts_with("uk_test_"));
    assert_eq!(bearer.len(), 43);
    assert_eq!(oauth.matches('.').count(), 2);

    assert_eq!(authorization_scheme(TokenKind::ApiKey), "ApiKey");
    assert_eq!(authorization_scheme(TokenKind::Bearer), "Bearer");
    assert_eq!(authorization_scheme(TokenKind::OAuthAccessToken), "Bearer");

    let _ = generate_oauth_access_token("fuzz", &mut oauth_rng);
});
