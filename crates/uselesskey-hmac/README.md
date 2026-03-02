# uselesskey-hmac

[![Crates.io](https://img.shields.io/crates/v/uselesskey-hmac.svg)](https://crates.io/crates/uselesskey-hmac)
[![docs.rs](https://docs.rs/uselesskey-hmac/badge.svg)](https://docs.rs/uselesskey-hmac)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

HMAC secret fixtures for testing — generates deterministic or random symmetric
secrets for HS256, HS384, and HS512 workflows.

Part of the [`uselesskey`](https://crates.io/crates/uselesskey) workspace. Use
the facade crate for the simplest experience, or depend on this crate directly
for minimal compile time.

## Usage

```rust
use uselesskey_core::Factory;
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

let fx = Factory::random();
let secret = fx.hmac("issuer", HmacSpec::hs256());

assert_eq!(secret.secret_bytes().len(), 32);
```

### Specs

| Constructor | Algorithm | Secret Length |
|-------------|-----------|--------------|
| `HmacSpec::hs256()` | HMAC-SHA256 | 32 bytes |
| `HmacSpec::hs384()` | HMAC-SHA384 | 48 bytes |
| `HmacSpec::hs512()` | HMAC-SHA512 | 64 bytes |

### Deterministic Mode

```rust
use uselesskey_core::{Factory, Seed};
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

let seed = Seed::from_env_value("test-seed").unwrap();
let fx = Factory::deterministic(seed);

// Same seed + label + spec = same secret
let s1 = fx.hmac("issuer", HmacSpec::hs384());
let s2 = fx.hmac("issuer", HmacSpec::hs384());
assert_eq!(s1.secret_bytes(), s2.secret_bytes());
```

## Features

| Feature | Description |
|---------|-------------|
| `jwk` | Octet JWK/JWKS output via `uselesskey-jwk` |

## License

Licensed under either of [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
or [MIT license](https://opensource.org/licenses/MIT) at your option.

See the [`uselesskey` crate](https://crates.io/crates/uselesskey) for full
documentation.
