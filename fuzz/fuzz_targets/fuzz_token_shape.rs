#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey::Seed;
use uselesskey_core_token_shape::{
    authorization_scheme, generate_api_key, generate_bearer_token, generate_oauth_access_token,
    generate_token, random_base62, TokenKind,
};

#[derive(Arbitrary, Debug)]
struct TokenShapeInput {
    seed: [u8; 32],
    label: String,
    base62_len: u8,
    kind_idx: u8,
}

fuzz_target!(|input: TokenShapeInput| {
    // Cap label length to avoid excessive allocations.
    if input.label.len() > 512 {
        return;
    }

    let kind = match input.kind_idx % 3 {
        0 => TokenKind::ApiKey,
        1 => TokenKind::Bearer,
        _ => TokenKind::OAuthAccessToken,
    };

    // Exercise generate_token with arbitrary labels.
    let seed = Seed::new(input.seed);
    let token = generate_token(&input.label, kind, seed);
    assert!(!token.is_empty());

    // Determinism: same seed + label + kind = same output.
    let token2 = generate_token(&input.label, kind, seed);
    assert_eq!(token, token2);

    // authorization_scheme must not panic for any kind.
    let scheme = authorization_scheme(kind);
    assert!(!scheme.is_empty());

    // Exercise individual generators with fuzz-derived label.
    let api = generate_api_key(seed);
    assert!(api.starts_with("uk_test_"));

    let bearer = generate_bearer_token(seed);
    assert_eq!(bearer.len(), 43);

    let oauth = generate_oauth_access_token(&input.label, seed);
    assert_eq!(oauth.matches('.').count(), 2);

    // Exercise random_base62 with fuzz-derived length.
    let len = input.base62_len as usize;
    let b62 = random_base62(seed, len);
    assert_eq!(b62.len(), len);
    assert!(b62.chars().all(|c| c.is_ascii_alphanumeric()));
});
