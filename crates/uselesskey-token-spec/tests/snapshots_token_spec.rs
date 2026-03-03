//! Insta snapshot tests for uselesskey-token-spec.
//!
//! Snapshot spec variants, constructors, kind names, and stable bytes.

use serde::Serialize;
use uselesskey_token_spec::TokenSpec;

#[derive(Serialize)]
struct TokenSpecSnapshot {
    variant: &'static str,
    kind_name: &'static str,
    debug_repr: String,
    stable_bytes: [u8; 4],
}

#[test]
fn snapshot_token_spec_all_variants() {
    let specs = [
        ("ApiKey", TokenSpec::api_key()),
        ("Bearer", TokenSpec::bearer()),
        ("OAuthAccessToken", TokenSpec::oauth_access_token()),
    ];

    let results: Vec<TokenSpecSnapshot> = specs
        .iter()
        .map(|(name, spec)| TokenSpecSnapshot {
            variant: name,
            kind_name: spec.kind_name(),
            debug_repr: format!("{:?}", spec),
            stable_bytes: spec.stable_bytes(),
        })
        .collect();

    insta::assert_yaml_snapshot!("token_spec_all_variants", results);
}

#[test]
fn snapshot_token_spec_stable_bytes_uniqueness() {
    #[derive(Serialize)]
    struct StableBytesCheck {
        api_key: [u8; 4],
        bearer: [u8; 4],
        oauth_access_token: [u8; 4],
        all_unique: bool,
    }

    let api = TokenSpec::api_key().stable_bytes();
    let bearer = TokenSpec::bearer().stable_bytes();
    let oauth = TokenSpec::oauth_access_token().stable_bytes();

    let result = StableBytesCheck {
        api_key: api,
        bearer,
        oauth_access_token: oauth,
        all_unique: api != bearer && api != oauth && bearer != oauth,
    };

    insta::assert_yaml_snapshot!("token_spec_stable_bytes", result);
}

#[test]
fn snapshot_token_spec_kind_names() {
    #[derive(Serialize)]
    struct KindNames {
        api_key: &'static str,
        bearer: &'static str,
        oauth_access_token: &'static str,
        all_snake_case: bool,
    }

    fn is_snake_case(s: &str) -> bool {
        s.chars().all(|c| c.is_ascii_lowercase() || c == '_')
    }

    let api = TokenSpec::api_key().kind_name();
    let bearer = TokenSpec::bearer().kind_name();
    let oauth = TokenSpec::oauth_access_token().kind_name();

    let result = KindNames {
        api_key: api,
        bearer,
        oauth_access_token: oauth,
        all_snake_case: is_snake_case(api) && is_snake_case(bearer) && is_snake_case(oauth),
    };

    insta::assert_yaml_snapshot!("token_spec_kind_names", result);
}
