# uselesskey-hmac

HMAC secret fixtures for `uselesskey` test suites.

Generates deterministic or random symmetric secrets for HS256, HS384, and HS512 tests.

## Features

| Feature | Description |
|---------|-------------|
| `jwk` | Octet JWK/JWKS output via `uselesskey-jwk` |

## Example

```rust
use uselesskey_core::Factory;
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

let fx = Factory::random();
let secret = fx.hmac("issuer", HmacSpec::hs256());

assert_eq!(secret.secret_bytes().len(), 32);
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
