# Scanner-Safe Bundle Reference

This example is the release-facing reference for the default bundle handoff
lane. It shows the CLI path a platform or CI user can copy without committing
runtime private key material or symmetric secret material.

## Regenerate

```bash
cargo run -p uselesskey-cli -- bundle \
  --profile scanner-safe \
  --out target/uselesskey-bundle

cargo run -p uselesskey-cli -- verify-bundle \
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

## Reference Files

The `expected/` directory records the stable handoff outputs used by release
checks:

- `manifest.json`
- `receipts/materialization.json`
- `receipts/audit-surface.json`
- `secret.yaml`
- `kv-v2.json`

The full generated bundle also includes per-artifact files such as
`rsa.jwk.json`, `jwks.jwks.json`, and `x509.pem`. Those are regenerated and
verified from `manifest.json`; the committed reference keeps only the manifest,
receipts, and downstream export payloads.

## Scanner-Safety Boundary

The `scanner-safe` profile emits public key material, public certificate
material, scanner-safe invalid symmetric JWK shape data, and near-miss token
shapes. It is intended for parser, configuration, and platform handoff tests.
Use `--profile runtime` only when a downstream test truly needs runtime private
or symmetric fixture material.
