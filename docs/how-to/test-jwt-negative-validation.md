# Test JWT Negative Validation

Use this guide when a downstream token parser or validator needs
JWT-shaped negative inputs that are realistic enough to reach policy checks.

## Generate bundle files

For file-based tests, use the OIDC contract pack:

```bash
cargo run -p uselesskey-cli -- bundle \
  --profile oidc \
  --out target/oidc-fixtures

cargo run -p uselesskey-cli -- verify-bundle \
  --path target/oidc-fixtures
```

Use these token files:

| File | Intended failure |
| --- | --- |
| `tokens/valid-rs256.json` | positive parser control |
| `tokens/negative-alg-none.json` | reject insecure `alg: none` policy |
| `tokens/negative-bad-audience.json` | reject wrong audience |

Each file is JSON with metadata and a `value` field containing the token-shaped
string. Load the value in the downstream test and assert the validator's policy
failure.

## Generate in Rust tests

For runtime test generation:

```toml
[dev-dependencies]
uselesskey = { version = "0.7", default-features = false, features = ["token"] }
```

```rust
use uselesskey::{Factory, NegativeToken, TokenFactoryExt, TokenSpec};

let fx = Factory::deterministic_from_str("jwt-negative");
let token = fx.token("api", TokenSpec::oauth_access_token());

let alg_none = token.negative_value(NegativeToken::AlgNone);
assert!(validator_rejects_alg_none(&alg_none));

let bad_audience = token.negative_value(NegativeToken::BadAudience);
assert!(validator_rejects_bad_audience(&bad_audience));
```

Keep the test assertion specific. A useful test distinguishes "rejected because
the algorithm is forbidden" from "failed to parse any token at all."

## Near-miss API keys

Use `NegativeToken::NearMissApiKey` for parser or scanner-safety tests where the
input should look close to an API key but must not be a usable `uk_test_` token:

```rust
let api_key = fx.token("billing", TokenSpec::api_key());
let near_miss = api_key.negative_value(NegativeToken::NearMissApiKey);

assert!(!near_miss.starts_with("uk_test_"));
assert!(api_key_parser_rejects(&near_miss));
```

## Scanner-safety note

Token negatives are scanner-safe fixture shapes. They are for parser and
validator tests, not for production authorization decisions.

## What this does not prove

- It does not prove signature validation by itself.
- It does not prove production issuer or audience configuration.
- It does not prove cryptographic assurance.
- It does not replace adapter-specific tests such as `uselesskey-jsonwebtoken`
  when native downstream types matter.

## Evidence

```bash
cargo test -p uselesskey-token --all-features
cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc
cargo xtask no-blob
```
