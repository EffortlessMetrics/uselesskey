#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use uselesskey_core_token_shape::{
    generate_api_key, generate_bearer_token, generate_oauth_access_token, random_base62,
};

#[derive(Arbitrary, Debug)]
struct TokenShapeInput {
    seed: [u8; 32],
    base62_len: u8,
    label_bytes: Vec<u8>,
}

fuzz_target!(|input: TokenShapeInput| {
    // Fuzz random_base62 with arbitrary lengths (capped to avoid OOM).
    let len = input.base62_len as usize;
    let mut rng = ChaCha20Rng::from_seed(input.seed);
    let token = random_base62(&mut rng, len);
    assert_eq!(token.len(), len);
    assert!(token.chars().all(|c| c.is_ascii_alphanumeric()));

    // Determinism: same seed + same length = same output.
    let mut rng2 = ChaCha20Rng::from_seed(input.seed);
    let token2 = random_base62(&mut rng2, len);
    assert_eq!(token, token2);

    // Fuzz individual generators.
    let mut rng_api = ChaCha20Rng::from_seed(input.seed);
    let api = generate_api_key(&mut rng_api);
    assert!(api.starts_with("uk_test_"));

    let mut rng_bearer = ChaCha20Rng::from_seed(input.seed);
    let bearer = generate_bearer_token(&mut rng_bearer);
    assert_eq!(bearer.len(), 43);

    let label = String::from_utf8_lossy(&input.label_bytes);
    let mut rng_oauth = ChaCha20Rng::from_seed(input.seed);
    let oauth = generate_oauth_access_token(&label, &mut rng_oauth);
    assert_eq!(oauth.matches('.').count(), 2);
});
