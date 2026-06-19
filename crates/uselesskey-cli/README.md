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
uselesskey-cli = { version = "0.10.0", default-features = false }
```

Specialized RSA PKCS#8 build-time lane:

```toml
[build-dependencies]
uselesskey-cli = { version = "0.10.0", default-features = false, features = ["rsa-materialize"] }
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

cargo run -p uselesskey-cli -- inspect-bundle \
  --path target/uselesskey-bundle

cargo run -p uselesskey-cli -- export k8s \
  --bundle-dir target/uselesskey-bundle \
  --name uselesskey-fixtures \
  --namespace tests \
  --out target/uselesskey-bundle/secret.yaml

cargo run -p uselesskey-cli -- export vault-kv-json \
  --bundle-dir target/uselesskey-bundle \
  --out target/uselesskey-bundle/kv-v2.json
```

`verify-bundle` reloads `manifest.json`, regenerates the expected artifacts from
the recorded seed/label/format/profile, and fails if any file or manifest
metadata is missing or changed. Bundles also include deterministic
`receipts/materialization.json` and `receipts/audit-surface.json` metadata files;
`verify-bundle` regenerates those receipts and fails on drift.

`inspect-bundle` runs the same verification first, then prints a short
human-readable summary of the profile, artifact count, scanner-safety posture,
runtime material count, private/symmetric material flags, and receipt kinds. It
does not print fixture payloads.

The `export` subcommands verify the bundle first, then render handoff payloads
for downstream tools. They write local files only; they do not call Kubernetes,
Vault, cloud APIs, or long-running secret stores.

`scanner-safe` is the default bundle profile. It emits public key material,
public certificate material, scanner-safe symmetric JWK shape data, and
near-miss token shapes. Use `--profile runtime` when a downstream test really
needs runtime-generated private or symmetric fixture material in the bundle.

Use `--profile oidc` when a downstream OIDC/JWKS validator needs a focused
contract pack:

```bash
cargo run -p uselesskey-cli -- bundle \
  --profile oidc \
  --out target/oidc-fixtures

cargo run -p uselesskey-cli -- verify-bundle \
  --path target/oidc-fixtures
```

The OIDC profile emits:

- `jwks/valid.json`
- `jwks/negative-duplicate-kid.json`
- `jwks/negative-missing-kid.json`
- `tokens/valid-rs256.json`
- `tokens/negative-alg-none.json`
- `tokens/negative-bad-audience.json`
