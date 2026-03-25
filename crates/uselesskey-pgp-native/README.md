# uselesskey-pgp-native

Adapters from `uselesskey` OpenPGP fixtures to native `pgp` crate types.

## Feature support

| Feature      | Source artifact | Native output |
|--------------|-----------------|---------------|
| `pgp-native` | `PgpKeyPair`    | `SignedSecretKey`, `SignedPublicKey` |

## Example

```rust
use uselesskey_core::Factory;
use uselesskey_pgp::{PgpFactoryExt, PgpSpec};
use uselesskey_pgp_native::PgpNativeExt;

let fx = Factory::random();
let keypair = fx.pgp("signer", PgpSpec::ed25519());

let secret = keypair.secret_key_armor();
let public = keypair.public_key_armor();

assert_eq!(secret.fingerprint(), public.fingerprint());
println!("fingerprint={}", secret.fingerprint());
```

## Tests

- one smoke test that parses binary and armored fixture values
- one integration-style assertion test for deterministic conversion in an external path

## License

Licensed under either of [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
or [MIT license](https://opensource.org/licenses/MIT), at your option.
