use uselesskey_core_seed::Seed;
use uselesskey_core_token::{generate_api_key, generate_bearer_token, generate_oauth_access_token};

#[test]
fn facade_reexports_shape_generators() {
    let seed = [3u8; 32];
    let rng = Seed::new(seed);

    let api = generate_api_key(rng);
    assert!(api.starts_with("uk_test_"));
    assert_eq!(api.len(), 40);

    let rng = Seed::new(seed);
    let bearer = generate_bearer_token(rng);
    assert_eq!(bearer.len(), 43);

    let rng = Seed::new(seed);
    let oauth = generate_oauth_access_token("token-stack", rng);
    assert_eq!(oauth.matches('.').count(), 2);
}

#[test]
fn facade_generators_are_stable() {
    let first = Seed::new([9u8; 32]);
    let first_api = generate_api_key(first);

    let second = Seed::new([9u8; 32]);
    let second_api = generate_api_key(second);

    assert_eq!(first_api, second_api);
}
