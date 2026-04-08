# Choosing A Fixture Lane

Use the cheapest lane that preserves the semantics your test actually needs.

## Entropy / scanner-shape only

Use `uselesskey-entropy` or the facade with `features = ["entropy"]`.

Choose this when the test only needs deterministic high-entropy bytes or scanner-safe placeholder data.

## Token shapes only

Use `uselesskey-token` or the facade with `features = ["token"]`.

Choose this when the test needs API-key, bearer-token, or JWT-shaped strings but does not need real key material.

## Valid runtime crypto semantics

Use the leaf crate for the fixture family you actually need.

Examples:
- `uselesskey-rsa` for PKCS#8/JWK runtime RSA fixtures
- `uselesskey-x509` for certificate and chain semantics
- `uselesskey-ssh` for SSH key material

Choose this lane when the test must exercise real cryptographic shapes or adapter behavior at runtime.

## Build-time materialized fixtures

Use `uselesskey-cli materialize` and `uselesskey-cli verify`.

Choose this lane when the repo wants `OUT_DIR`, `include_bytes!`, deterministic checked outputs, and no committed secret-shaped blobs.

For shape-only build-time fixtures, depend on the slim library surface:

```toml
[build-dependencies]
uselesskey-cli = { version = "0.6.0", default-features = false }
```

For RSA PKCS#8 build-time fixtures, opt into the specialized RSA materialize support:

```toml
[build-dependencies]
uselesskey-cli = { version = "0.6.0", default-features = false, features = ["rsa-materialize"] }
```

See `crates/materialize-shape-buildrs-example/` for the common shape-only pattern and `crates/materialize-buildrs-example/` for the specialized RSA pattern.
