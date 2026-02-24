use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use uselesskey_core_token_shape::{TokenKind, generate_token};

#[test]
fn integration_generate_token_all_kinds() {
    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);

    let api = generate_token("label", TokenKind::ApiKey, &mut rng);
    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
    let bearer = generate_token("label", TokenKind::Bearer, &mut rng);
    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
    let oauth = generate_token("label", TokenKind::OAuthAccessToken, &mut rng);

    assert_ne!(api, bearer);
    assert_ne!(api, oauth);
    assert_ne!(bearer, oauth);
}

#[test]
fn integration_api_key_prefix_is_stable() {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let token = generate_token("tenant-a", TokenKind::ApiKey, &mut rng);
    assert!(token.starts_with("uk_test_"));
}
