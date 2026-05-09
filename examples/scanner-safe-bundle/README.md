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

The `expected/` directory records exact generated metadata outputs that are safe
to keep in source control:

- `manifest.json`
- `receipts/materialization.json`
- `receipts/audit-surface.json`

The full generated bundle also includes per-artifact files such as
`rsa.jwk.json`, `jwks.jwks.json`, `x509.pem`, `secret.yaml`, and `kv-v2.json`.
Those are regenerated under `target/` by the commands above.

The committed export-shape files show downstream payload structure without
committing high-entropy encoded fixture bytes:

- `secret.shape.yaml`
- `kv-v2.shape.json`

## Scanner-Safety Boundary

The `scanner-safe` profile emits public key material, public certificate
material, scanner-safe invalid symmetric JWK shape data, and near-miss token
shapes. It is intended for parser, configuration, and platform handoff tests.

Kubernetes and Vault exports intentionally encode bundle artifacts for handoff.
Even when those artifacts are scanner-safe fixtures, committing the encoded
payloads can still trip high-entropy secret scanners. Keep those generated files
under `target/` and verify them in CI instead of committing them.

Use `--profile runtime` only when a downstream test truly needs runtime private
or symmetric fixture material.
