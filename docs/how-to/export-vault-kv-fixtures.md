# Export Vault KV-v2 fixtures from a scanner-safe bundle

Use this guide when a downstream Vault consumer needs KV-v2-shaped JSON
payloads to test parsing, secret-name handling, and client wiring without
committing real secret material. The `uselesskey bundle --profile
scanner-safe` workflow plus `export vault-kv-json` emit a single JSON
payload that matches the `{"data": {...}, "metadata": {...}}` shape a
Vault KV-v2 read response uses.

## Generate the bundle

```bash
uselesskey bundle \
  --profile scanner-safe \
  --out target/uselesskey-bundle

uselesskey verify-bundle \
  --path target/uselesskey-bundle

uselesskey inspect-bundle \
  --path target/uselesskey-bundle
```

From a repo checkout while changing the CLI, prefix those subcommands with
`cargo run -p uselesskey-cli --`.

`inspect-bundle` prints the profile, artifact count, scanner-safety
posture, runtime material count, private/symmetric material flags,
exports, verification status, and receipt kinds. It does not print
fixture payloads.

## Export to Vault KV-v2 JSON

```bash
uselesskey export vault-kv-json \
  --bundle-dir target/uselesskey-bundle \
  --out target/uselesskey-bundle/kv-v2.json
```

The export reads the bundle's artifact set, collects each artifact's
key and value, and writes a single JSON document. `--out` is optional;
omit it to stream to stdout. Keep generated `kv-v2.json` under
`target/`. It is a generated handoff payload, not a committed fixture.

## Expected shape

The export writes a top-level `data` map keyed by artifact name, plus a
`metadata` map recording the export's source and mode. The shape mirrors
a Vault KV-v2 read response well enough that a consumer parser can be
pointed at the file:

```json
{
  "data": {
    "rsa.jwk.json": "<generated-artifact-text>",
    "ecdsa.jwk.json": "<generated-artifact-text>",
    "ed25519.jwk.json": "<generated-artifact-text>",
    "hmac.jwk.json": "<generated-artifact-text>",
    "token.json": "<generated-artifact-text>",
    "x509.pem": "<generated-artifact-text>",
    "jwk.jwk.json": "<generated-artifact-text>",
    "jwks.jwks.json": "<generated-artifact-text>"
  },
  "metadata": {
    "mode": "one_shot_export",
    "source": "uselesskey-cli"
  }
}
```

The `data` keys are stable artifact names from the bundle's manifest.
Each value is the artifact's textual payload. Under the `scanner-safe`
profile the payloads are public key material, public certificate
material, invalid HMAC JWK shape data, and near-miss token shapes;
they look like KV-v2 secret values but are not usable secret material.

The `metadata` fields are fixed:

- `mode` is `one_shot_export` to mark that the file is a single
  rendered payload, not a Vault server response with version metadata.
- `source` is `uselesskey-cli` so downstream parsers can identify the
  payload's origin.

## What this proves

- Your Vault consumer can parse the KV-v2 `{"data": {...},
  "metadata": {...}}` shape.
- Your client handles secret-name conventions (artifact-name keys with
  dots, JSON-suffixed filenames, mixed-content payload bodies).
- You can wire a test rig that exercises the KV-v2 parse and lookup
  path without committing or fetching real secret material.

## What this does NOT prove

- It does not prove a Vault server. The export is a static JSON file,
  not an HTTP response from `vault kv get`.
- It does not prove Vault policy, token, or capability enforcement.
- It does not prove audit-log behavior, request-id propagation, or any
  server-side response wrapping.
- It does not prove AppRole, JWT, Kubernetes, OIDC, or any other Vault
  auth flow.
- It does not prove real KV-v2 versioning semantics. The `metadata`
  block is fixed (`mode`, `source`) and intentionally omits
  `created_time`, `version`, `deletion_time`, `destroyed`,
  `custom_metadata`, and other server-only fields.
- It does not prove namespace, mount-path, or KV-v2 `data/`-prefix
  routing beyond what the export's static shape covers.

## Scanner-safety boundary

The `scanner-safe` profile is the default for export workflows. It
emits public key material, public certificate material, invalid
symmetric JWK shape data, and near-miss token shapes; it never writes
runtime private or symmetric secret material. Regenerate under
`target/` and treat `kv-v2.json` as a build output rather than a
committed fixture. The committed reference at
`examples/scanner-safe-bundle/expected/kv-v2.shape.json` records the
canonical key set and metadata block; it does not record artifact
payload bytes.

Use `--profile runtime` only when a downstream test truly needs
runtime private or symmetric fixture material, and keep the resulting
`kv-v2.json` out of version control regardless.

See [`../release/publish-recovery.md`](../release/publish-recovery.md)
for the registry-truth analogue: that doc covers the publish-side
"don't trust local state, regenerate from upstream" pattern.

## Evidence

Repo-checkout proof:

```bash
cargo xtask bundle-proof --profile scanner-safe --out target/release-evidence/scanner-safe
cargo xtask scanner-safe-reference --check
cargo xtask no-blob
```

`scanner-safe-reference --check` regenerates the bundle under
`target/scanner-safe-reference/` and diffs `manifest.json`,
`receipts/audit-surface.json`, `receipts/bundle-verification.json`,
`receipts/materialization.json`, `receipts/negative-coverage.json`, and
`receipts/scanner-safety.json`
against the committed reference. It also asserts the encoded
`secret.yaml` and `kv-v2.json` payloads are not committed under
`examples/scanner-safe-bundle/expected/`.

## See also

- [`generate-scanner-safe-k8s-secret.md`](generate-scanner-safe-k8s-secret.md)
  — the Kubernetes Secret analogue from the same bundle.
- [`test-oidc-jwks-validation.md`](test-oidc-jwks-validation.md) — OIDC
  JWKS validation workflow against a different profile.
- [`test-tls-chain-validation.md`](test-tls-chain-validation.md) —
  TLS chain validation workflow against the `tls` profile.
- [`../release/v0.7.0-category-notes.md`](../release/v0.7.0-category-notes.md)
  — v0.7.0 release context for the scanner-safe bundle and export
  surface this how-to documents.
