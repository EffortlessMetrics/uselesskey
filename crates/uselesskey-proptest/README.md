# uselesskey-proptest

`proptest` strategy builders for generating `uselesskey` fixture structs.

This crate is intended for downstream property tests and fuzz harnesses that want
fixture-shaped values (RSA/ECDSA/Ed25519/HMAC/token/X.509 and negative variants)
instead of ad-hoc tuples.
