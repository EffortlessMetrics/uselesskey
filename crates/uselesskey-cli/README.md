# uselesskey-cli

Export and materialization helpers for handing off generated uselesskey fixtures
to local files and common secret-management interchange formats.

This crate is intentionally focused on one-shot export: generate once, write
artifacts or manifests, verify them later, stop.

## Materialize

Use the manifest workflow when a repo wants static-like fixtures under
`target/` or `OUT_DIR` without checking secret-shaped blobs into git.

Shape-only common lane:

```bash
cargo run -p uselesskey-cli -- materialize \
  --manifest crates/materialize-shape-buildrs-example/uselesskey-fixtures.toml \
  --out-dir target/tmp-fixtures

cargo run -p uselesskey-cli -- verify \
  --manifest crates/materialize-shape-buildrs-example/uselesskey-fixtures.toml \
  --out-dir target/tmp-fixtures
```

`build.rs` consumers can keep this path slim with:

```toml
[build-dependencies]
uselesskey-cli = { version = "0.6.0", default-features = false }
```

Specialized RSA PKCS#8 build-time lane:

```toml
[build-dependencies]
uselesskey-cli = { version = "0.6.0", default-features = false, features = ["rsa-materialize"] }
```

The workspace ships both compiled build-time examples:

- `crates/materialize-shape-buildrs-example/` for the common shape-only pattern
- `crates/materialize-buildrs-example/` for the specialized RSA pattern
