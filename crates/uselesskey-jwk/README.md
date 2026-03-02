# uselesskey-jwk

Compatibility facade for typed JWK/JWKS models used by `uselesskey` fixture crates.

The canonical implementation lives in `uselesskey-core-jwk`; this crate re-exports
that API to preserve the stable `uselesskey-jwk` crate name.

## Example

```rust
use uselesskey_jwk::{JwksBuilder, OctJwk, PrivateJwk};

let mut builder = JwksBuilder::new();
builder.push_private(PrivateJwk::Oct(OctJwk {
    kty: "oct",
    use_: "sig",
    alg: "HS256",
    kid: "test-key-1".to_string(),
    k: "dGVzdF9zZWNyZXQ".to_string(),
}));

let jwks = builder.build();
assert_eq!(jwks.keys.len(), 1);
```

## License

Licensed under either of [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
or [MIT license](https://opensource.org/licenses/MIT) at your option.

See the [`uselesskey` crate](https://crates.io/crates/uselesskey) for full
documentation.
