# uselesskey-jwk

Typed JWK/JWKS models for `uselesskey` fixture crates.

This crate provides lightweight serializable structs (`PublicJwk`, `PrivateJwk`, `AnyJwk`) plus `JwksBuilder` with stable `kid` ordering.

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

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
