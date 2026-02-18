# uselesskey-pgp

OpenPGP key fixtures for `uselesskey` test suites.

Generates armored and binary OpenPGP key material at runtime via `PgpFactoryExt`, with deterministic derivation support.

## Example

```rust
use uselesskey_core::Factory;
use uselesskey_pgp::{PgpFactoryExt, PgpSpec};

let fx = Factory::random();
let key = fx.pgp("issuer", PgpSpec::ed25519());

let private_armor = key.private_key_armored();
let public_armor = key.public_key_armored();

assert!(private_armor.contains("BEGIN PGP PRIVATE KEY BLOCK"));
assert!(public_armor.contains("BEGIN PGP PUBLIC KEY BLOCK"));
```

Use this crate for test fixtures only, not production key management.

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.

See the [main uselesskey README](../../README.md) for full documentation.
