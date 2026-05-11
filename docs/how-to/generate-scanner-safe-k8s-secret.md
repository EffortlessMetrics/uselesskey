# Generate a Scanner-Safe Kubernetes Secret

Use this guide when a CI or platform test needs Kubernetes Secret-shaped data
without committing runtime private key material or symmetric secret material.

## Generate and verify the bundle

```bash
cargo run -p uselesskey-cli -- bundle \
  --profile scanner-safe \
  --out target/uselesskey-bundle

cargo run -p uselesskey-cli -- verify-bundle \
  --path target/uselesskey-bundle

cargo run -p uselesskey-cli -- inspect-bundle \
  --path target/uselesskey-bundle
```

The inspection step prints the profile, artifact count, scanner-safety posture,
runtime material count, private/symmetric material flags, exports, verification
status, and receipt kinds. It does not print fixture payloads.

## Export Kubernetes and Vault-shaped payloads

```bash
cargo run -p uselesskey-cli -- export k8s \
  --bundle-dir target/uselesskey-bundle \
  --name uselesskey-fixtures \
  --namespace tests \
  --out target/uselesskey-bundle/secret.yaml

cargo run -p uselesskey-cli -- export vault-kv-json \
  --bundle-dir target/uselesskey-bundle \
  --out target/uselesskey-bundle/kv-v2.json
```

Keep `secret.yaml` and `kv-v2.json` under `target/`. They are generated
handoff payloads, not committed fixtures.

## Positive platform test

Use `target/uselesskey-bundle/secret.yaml` to test Kubernetes Secret loading,
YAML parsing, key naming, mount wiring, or CI handoff logic. The positive case
should prove that platform plumbing can consume the Secret-shaped payload.

## Negative platform test

Use the scanner-safe token and HMAC JWK shape entries in the bundle to exercise
parser or policy rejection without introducing real symmetric material. For
example, a downstream parser can assert that a near-miss token is rejected while
the surrounding Kubernetes Secret shape still loads.

## Scanner-safety note

The `scanner-safe` profile emits public key material, public certificate
material, invalid symmetric JWK shape data, and near-miss token shapes. Use
`--profile runtime` only when a downstream test truly needs runtime private or
symmetric fixture material.

## What this does not prove

- It does not create Kubernetes objects.
- It does not call Vault or a cloud API.
- It does not prove production secret rotation or access control.
- It does not prove scanner evasion. It proves the checked bundle profile avoids
  usable committed secret material.

## Evidence

```bash
cargo xtask bundle-proof --profile scanner-safe --out target/release-evidence/scanner-safe
cargo xtask scanner-safe-reference --check
cargo xtask no-blob
```

`cargo xtask scanner-safe-reference --check` regenerates the bundle under
`target/scanner-safe-reference/` and diffs `manifest.json`,
`receipts/audit-surface.json`, and `receipts/materialization.json` against the
committed reference under `examples/scanner-safe-bundle/expected/`. It also
asserts the encoded `secret.yaml` and `kv-v2.json` payloads are not committed
under that directory.
