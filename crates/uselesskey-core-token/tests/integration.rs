use rand_chacha::rand_core::SeedableRng;

use uselesskey_core_token::{generate_api_key, generate_bearer_token, generate_oauth_access_token};

#[test]
fn facade_reexports_shape_generators() {
    let seed = [3u8; 32];
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);

    let api = generate_api_key(&mut rng);
    assert!(api.starts_with("uk_test_"));
    assert_eq!(api.len(), 40);

    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    let bearer = generate_bearer_token(&mut rng);
    assert_eq!(bearer.len(), 43);

    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    let oauth = generate_oauth_access_token("token-stack", &mut rng);
    assert_eq!(oauth.matches('.').count(), 2);
}

#[test]
fn facade_generators_are_stable() {
    let mut first = rand_chacha::ChaCha20Rng::from_seed([9u8; 32]);
    let first_api = generate_api_key(&mut first);

    let mut second = rand_chacha::ChaCha20Rng::from_seed([9u8; 32]);
    let second_api = generate_api_key(&mut second);

    assert_eq!(first_api, second_api);
}
