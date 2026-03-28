# uselesskey-proptest

`proptest` strategy builders for `uselesskey` fixtures.

This crate exposes composable strategies that yield fixture structs/enums for:

- Valid RSA/ECDSA/Ed25519/HMAC fixtures
- Token fixtures
- X.509 chains
- Negative PEM/DER fixtures
- X.509 negative variants

And higher-level profiles:

- `any_jwt_fixture()`
- `any_x509_chain_negative()`
- `valid_or_corrupt_jwk()`
