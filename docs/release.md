# Release

This is the publish order for the uselesskey workspace crates.

## Order

1. `uselesskey-core`
2. `uselesskey-jwk`
3. `uselesskey-rsa`
4. `uselesskey-ecdsa`
5. `uselesskey-ed25519`
6. `uselesskey-hmac`
7. `uselesskey-x509`
8. `uselesskey`
9. `uselesskey-jsonwebtoken` (adapter, depends on key type crates)
10. `uselesskey-rustls`
11. `uselesskey-ring`
12. `uselesskey-rustcrypto`
13. `uselesskey-aws-lc-rs`

This list matches the `cargo xtask publish-check` order.

## Dry run

```bash
cargo xtask publish-check
```

## Publish

```bash
cargo publish -p uselesskey-core
cargo publish -p uselesskey-jwk
cargo publish -p uselesskey-rsa
cargo publish -p uselesskey-ecdsa
cargo publish -p uselesskey-ed25519
cargo publish -p uselesskey-hmac
cargo publish -p uselesskey-x509
cargo publish -p uselesskey
cargo publish -p uselesskey-jsonwebtoken
cargo publish -p uselesskey-rustls
cargo publish -p uselesskey-ring
cargo publish -p uselesskey-rustcrypto
cargo publish -p uselesskey-aws-lc-rs
```
