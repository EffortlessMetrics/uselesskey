# Rust Test Fixtures

Use this downstream-shaped example when a Rust test crate needs deterministic
RSA/JWK and token-shaped fixtures without committed payload blobs.

```bash
cargo test
```

The example depends on the published facade crate shape. In repo-local adoption
smoke, `cargo xtask external-adoption-smoke --path .` copies this project under
`target/` and patches the dependency to the current checkout.

For generated CLI bundles, use `uselesskey audit-bundle` to create
metadata-only reviewer receipts. The Rust crate example does not write bundle
payloads by itself.
