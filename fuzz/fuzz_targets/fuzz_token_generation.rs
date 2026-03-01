#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey::{Factory, Seed, TokenFactoryExt, TokenSpec};

#[derive(Arbitrary, Debug)]
struct TokenInput {
    seed: [u8; 32],
    label: String,
    /// 0 = ApiKey, 1 = Bearer, 2 = OAuthAccessToken
    spec_idx: u8,
}

fuzz_target!(|input: TokenInput| {
    // Limit label length.
    if input.label.len() > 256 {
        return;
    }

    let fx = Factory::deterministic(Seed::new(input.seed));
    let spec = match input.spec_idx % 3 {
        0 => TokenSpec::api_key(),
        1 => TokenSpec::bearer(),
        _ => TokenSpec::oauth_access_token(),
    };

    let tok = fx.token(&input.label, spec);
    let value = tok.value();

    // Token must be non-empty
    assert!(!value.is_empty(), "token value must not be empty");

    // Format-specific invariants
    match input.spec_idx % 3 {
        0 => {
            // API key must start with prefix
            assert!(
                value.starts_with("uk_test_"),
                "API key must start with uk_test_, got: {}",
                &value[..value.len().min(20)]
            );
        }
        1 => {
            // Bearer token: base64url of 32 bytes = 43 chars
            assert_eq!(value.len(), 43, "Bearer token must be 43 characters");
        }
        _ => {
            // OAuth JWT shape: exactly 2 dots (3 segments)
            assert_eq!(
                value.matches('.').count(),
                2,
                "OAuth token must have exactly 2 dots"
            );
        }
    }

    // Determinism: same inputs = same output
    let tok2 = fx.token(&input.label, spec);
    assert_eq!(value, tok2.value());
});
