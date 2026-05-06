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

## Bundle

Use the bundle workflow when a downstream test suite wants a deterministic
directory of related fixture artifacts plus a manifest it can verify in CI.

```bash
cargo run -p uselesskey-cli -- bundle \
  --profile scanner-safe \
  --out target/uselesskey-bundle

cargo run -p uselesskey-cli -- verify-bundle \
  --path target/uselesskey-bundle
```

`verify-bundle` reloads `manifest.json`, regenerates the expected artifacts from
the recorded seed/label/format/profile, and fails if any file or manifest
metadata is missing or changed.

`scanner-safe` is the default bundle profile. It emits public key material,
public certificate material, scanner-safe symmetric JWK shape data, and
near-miss token shapes. Use `--profile runtime` when a downstream test really
needs runtime-generated private or symmetric fixture material in the bundle.
