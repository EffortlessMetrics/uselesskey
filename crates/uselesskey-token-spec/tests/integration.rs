#![forbid(unsafe_code)]

use uselesskey_token_spec::TokenSpec;

// ---------------------------------------------------------------------------
// Constructor helpers
// ---------------------------------------------------------------------------

#[test]
fn api_key_constructor() {
    let spec = TokenSpec::api_key();
    assert_eq!(spec, TokenSpec::ApiKey);
}

#[test]
fn bearer_constructor() {
    let spec = TokenSpec::bearer();
    assert_eq!(spec, TokenSpec::Bearer);
}

#[test]
fn oauth_access_token_constructor() {
    let spec = TokenSpec::oauth_access_token();
    assert_eq!(spec, TokenSpec::OAuthAccessToken);
}

// ---------------------------------------------------------------------------
// kind_name
// ---------------------------------------------------------------------------

#[test]
fn kind_name_returns_expected_strings() {
    assert_eq!(TokenSpec::ApiKey.kind_name(), "api_key");
    assert_eq!(TokenSpec::Bearer.kind_name(), "bearer");
    assert_eq!(TokenSpec::OAuthAccessToken.kind_name(), "oauth_access_token");
}

#[test]
fn kind_name_is_snake_case() {
    for spec in [TokenSpec::ApiKey, TokenSpec::Bearer, TokenSpec::OAuthAccessToken] {
        let name = spec.kind_name();
        assert!(
            name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "kind_name '{name}' is not snake_case"
        );
    }
}

// ---------------------------------------------------------------------------
// stable_bytes — uniqueness and known values
// ---------------------------------------------------------------------------

#[test]
fn stable_bytes_are_distinct_across_variants() {
    let all = [
        TokenSpec::ApiKey.stable_bytes(),
        TokenSpec::Bearer.stable_bytes(),
        TokenSpec::OAuthAccessToken.stable_bytes(),
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "variants {i} and {j} collide");
            }
        }
    }
}

#[test]
fn stable_bytes_known_values() {
    assert_eq!(TokenSpec::ApiKey.stable_bytes(), [0, 0, 0, 1]);
    assert_eq!(TokenSpec::Bearer.stable_bytes(), [0, 0, 0, 2]);
    assert_eq!(TokenSpec::OAuthAccessToken.stable_bytes(), [0, 0, 0, 3]);
}

// ---------------------------------------------------------------------------
// Trait impls: Clone, Copy, Debug, Eq, PartialEq, Hash
// ---------------------------------------------------------------------------

#[test]
fn clone_and_copy() {
    let spec = TokenSpec::ApiKey;
    #[allow(clippy::clone_on_copy)]
    let cloned = spec.clone();
    let copied = spec;
    assert_eq!(spec, cloned);
    assert_eq!(spec, copied);
}

#[test]
fn debug_impl_does_not_leak_key_material() {
    let dbg = format!("{:?}", TokenSpec::ApiKey);
    assert!(dbg.contains("ApiKey"), "Debug output: {dbg}");
    assert!(!dbg.contains("BEGIN"), "Debug must not contain key material");

    let dbg = format!("{:?}", TokenSpec::Bearer);
    assert!(dbg.contains("Bearer"), "Debug output: {dbg}");

    let dbg = format!("{:?}", TokenSpec::OAuthAccessToken);
    assert!(dbg.contains("OAuthAccessToken"), "Debug output: {dbg}");
}

#[test]
fn hash_impl_is_consistent() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(TokenSpec::ApiKey);
    set.insert(TokenSpec::Bearer);
    set.insert(TokenSpec::OAuthAccessToken);
    assert_eq!(set.len(), 3);

    // Re-inserting same variant does not grow the set
    set.insert(TokenSpec::ApiKey);
    assert_eq!(set.len(), 3);
}

#[test]
fn equality_between_variants() {
    assert_eq!(TokenSpec::ApiKey, TokenSpec::ApiKey);
    assert_ne!(TokenSpec::ApiKey, TokenSpec::Bearer);
    assert_ne!(TokenSpec::ApiKey, TokenSpec::OAuthAccessToken);
    assert_ne!(TokenSpec::Bearer, TokenSpec::OAuthAccessToken);
}

// ---------------------------------------------------------------------------
// Const-evaluable constructors
// ---------------------------------------------------------------------------

#[test]
fn constructors_are_const() {
    const API: TokenSpec = TokenSpec::api_key();
    const BEARER: TokenSpec = TokenSpec::bearer();
    const OAUTH: TokenSpec = TokenSpec::oauth_access_token();
    assert_eq!(API, TokenSpec::ApiKey);
    assert_eq!(BEARER, TokenSpec::Bearer);
    assert_eq!(OAUTH, TokenSpec::OAuthAccessToken);
}

#[test]
fn kind_name_is_const() {
    const NAME: &str = TokenSpec::api_key().kind_name();
    assert_eq!(NAME, "api_key");
}

#[test]
fn stable_bytes_is_const() {
    const BYTES: [u8; 4] = TokenSpec::api_key().stable_bytes();
    assert_eq!(BYTES, [0, 0, 0, 1]);
}
