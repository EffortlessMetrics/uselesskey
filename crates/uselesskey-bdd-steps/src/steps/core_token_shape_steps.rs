#[cfg(feature = "uk-core-token-shape")]
use base64::Engine as _;
#[cfg(feature = "uk-core-token-shape")]
use cucumber::{then, when};
#[cfg(feature = "uk-core-token-shape")]
use rand_chacha::ChaCha20Rng;
#[cfg(feature = "uk-core-token-shape")]
use rand_core::SeedableRng;
#[cfg(feature = "uk-core-token-shape")]
use uselesskey_core_token_shape::{authorization_scheme, generate_api_key, generate_bearer_token, generate_oauth_access_token, generate_token, TokenKind};

#[cfg(feature = "uk-core-token-shape")]
fn seed_from_text(raw: &str) -> [u8; 32] {
    let bytes = raw.as_bytes();
    let mut seed = [0u8; 32];
    let len = bytes.len().min(seed.len());
    seed[..len].copy_from_slice(&bytes[..len]);
    seed
}

#[cfg(feature = "uk-core-token-shape")]
fn set_next_core_token_shape_value(world: &mut crate::UselessWorld, value: String) {
    if world.core_token_shape_value_1.is_none() {
        world.core_token_shape_value_1 = Some(value);
    } else {
        world.core_token_shape_value_2 = Some(value);
    }
}

#[cfg(feature = "uk-core-token-shape")]
#[when(regex = r#"^I generate a core token-shape API key with seed "([^"]+)"$"#)]
fn core_token_shape_api_key(world: &mut crate::UselessWorld, seed: String) {
    let mut rng = ChaCha20Rng::from_seed(seed_from_text(&seed));
    let value = generate_api_key(&mut rng);
    set_next_core_token_shape_value(world, value);
}

#[cfg(feature = "uk-core-token-shape")]
#[when(
    regex = r#"^I generate a core token-shape bearer token with seed "([^"]+)"$"#
)]
fn core_token_shape_bearer(world: &mut crate::UselessWorld, seed: String) {
    let mut rng = ChaCha20Rng::from_seed(seed_from_text(&seed));
    let value = generate_bearer_token(&mut rng);
    set_next_core_token_shape_value(world, value);
}

#[cfg(feature = "uk-core-token-shape")]
#[when(
    regex = r#"^I generate a core token-shape OAuth access token with seed "([^"]+)" and subject "([^"]+)"$"#
)]
fn core_token_shape_oauth(
    world: &mut crate::UselessWorld,
    seed: String,
    subject: String,
) {
    let mut rng = ChaCha20Rng::from_seed(seed_from_text(&seed));
    let value = generate_oauth_access_token(&subject, &mut rng);
    set_next_core_token_shape_value(world, value);
}

#[cfg(feature = "uk-core-token-shape")]
#[when(
    regex = r#"^I generate a core token-shape token with seed "([^"]+)" and kind "([^"]+)"$"#
)]
fn core_token_shape_kind(world: &mut crate::UselessWorld, seed: String, kind: String) {
    let mut rng = ChaCha20Rng::from_seed(seed_from_text(&seed));
    let kind = match kind.as_str() {
        "api_key" => TokenKind::ApiKey,
        "bearer" => TokenKind::Bearer,
        "oauth_access_token" => TokenKind::OAuthAccessToken,
        other => panic!("unsupported token kind: {other}"),
    };
    let value = generate_token("bdd-subject", kind, &mut rng);
    set_next_core_token_shape_value(world, value);
}

#[cfg(feature = "uk-core-token-shape")]
#[then("the first and second core token-shape values should be identical")]
fn core_token_shape_values_identical(world: &mut crate::UselessWorld) {
    assert_eq!(
        world.core_token_shape_value_1,
        world.core_token_shape_value_2,
        "expected shape values to match",
    );
}

#[cfg(feature = "uk-core-token-shape")]
#[then("the first and second core token-shape values should be different")]
fn core_token_shape_values_different(world: &mut crate::UselessWorld) {
    assert_ne!(
        world.core_token_shape_value_1,
        world.core_token_shape_value_2,
        "expected shape values to differ",
    );
}

#[cfg(feature = "uk-core-token-shape")]
#[then(regex = r#"^the first core token-shape value should start with "([^"]+)"$"#)]
fn core_token_shape_value_starts_with(world: &mut crate::UselessWorld, prefix: String) {
    let value = world
        .core_token_shape_value_1
        .as_ref()
        .expect("core-token-shape value not set");
    assert!(
        value.starts_with(&prefix),
        "expected token-shape value to start with {prefix}, got {value}"
    );
}

#[cfg(feature = "uk-core-token-shape")]
#[then(regex = r#"^the first core token-shape value should have length (\d+)$"#)]
fn core_token_shape_value_length(world: &mut crate::UselessWorld, expected: usize) {
    let value = world
        .core_token_shape_value_1
        .as_ref()
        .expect("core-token-shape value not set");
    assert_eq!(value.len(), expected);
}

#[cfg(feature = "uk-core-token-shape")]
#[then(regex = r#"^the first core token-shape value should be valid base64url$"#)]
fn core_token_shape_value_base64(world: &mut crate::UselessWorld) {
    let value = world
        .core_token_shape_value_1
        .as_ref()
        .expect("core-token-shape value not set");
    assert!(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value).is_ok());
}

#[cfg(feature = "uk-core-token-shape")]
#[then("the first core token-shape value should have three dot-separated segments")]
fn core_token_shape_oauth_has_segments(world: &mut crate::UselessWorld) {
    let value = world
        .core_token_shape_value_1
        .as_ref()
        .expect("core-token-shape value not set");
    assert_eq!(value.split('.').count(), 3);
}

#[cfg(feature = "uk-core-token-shape")]
#[then(regex = r#"^the core-token-shape authorization scheme for API key should be "([^"]+)"$"#)]
fn core_token_shape_auth_scheme_api_key(_world: &mut crate::UselessWorld, expected: String) {
    assert_eq!(expected, authorization_scheme(TokenKind::ApiKey));
}

#[cfg(feature = "uk-core-token-shape")]
#[then(regex = r#"^the core-token-shape authorization scheme for bearer token should be "([^"]+)"$"#)]
fn core_token_shape_auth_scheme_bearer(_world: &mut crate::UselessWorld, expected: String) {
    assert_eq!(expected, authorization_scheme(TokenKind::Bearer));
}

#[cfg(feature = "uk-core-token-shape")]
#[then(
    regex = r#"^the core-token-shape authorization scheme for OAuth access token should be "([^"]+)"$"#
)]
fn core_token_shape_auth_scheme_oauth(_world: &mut crate::UselessWorld, expected: String) {
    assert_eq!(expected, authorization_scheme(TokenKind::OAuthAccessToken));
}
