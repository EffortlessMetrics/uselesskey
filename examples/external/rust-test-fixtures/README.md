# Rust Test Fixtures

Use this downstream-shaped example when a Rust test crate needs deterministic
RSA/JWK and token-shaped fixtures through the `uselesskey` facade crate without
committed payload blobs.

User job:

```text
I need deterministic valid and invalid fixtures inside Rust tests.
```

Dependency:

```toml
[dev-dependencies]
uselesskey = { version = "0.10.0", default-features = false, features = ["rsa", "jwk", "token"] }
```

First imports:

```rust
use uselesskey::{Factory, NegativeToken, RsaFactoryExt, RsaSpec, TokenFactoryExt, TokenSpec};
```

Positive path:

```text
Factory::deterministic_from_str("external-rust-test-fixtures")
  -> fx.rsa("issuer", RsaSpec::rs256())
  -> public JWK with kty=RSA and alg=RS256
```

Negative path:

```text
fx.token("api", TokenSpec::api_key())
  -> negative_value(NegativeToken::NearMissApiKey)
  -> parser rejects a token-like value that does not start with uk_test_
```

```bash
cargo test
```

The example depends on the published facade crate shape. In repo-local adoption
smoke, `cargo xtask external-adoption-smoke --path .` copies this project under
`target/` and patches the dependency to the current checkout.

For generated CLI bundles, use `uselesskey audit-bundle` to create
metadata-only reviewer receipts. The Rust crate example does not write bundle
payloads by itself.

Boundary:

- This proves a clean Rust test project can use the facade crate without leaf
  crate imports.
- It does not prove production key generation, production authorization, or
  downstream verifier correctness.
- It does not give permission to commit generated secret-shaped payloads.
