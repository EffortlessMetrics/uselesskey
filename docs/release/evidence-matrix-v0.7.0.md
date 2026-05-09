# v0.7.0 Public Fixture Evidence Matrix

This matrix ties release evidence to user-facing fixture promises. It is not a
replacement for the release run itself. Before cutting v0.7.0, refresh each
listed command on the release candidate and replace `Pending RC run` with the
actual result, artifact, or issue link.

v0.6.0 is the Rust 1.92 crates.io baseline. v0.7.0 is the next release and the
Rust 1.95 scanner-safe fixture platform release. It keeps published internal
implementation shards as compatibility shims for this release while directing
users to the owner crates and facade surfaces.

The release claim is narrow:

```text
uselesskey generates deterministic, scanner-safe, protocol-shaped test fixtures
and bundles. It is not production key management or a cryptographic assurance
tool.
```

## Required Release Gates

| Gate | Command or artifact | Release claim covered | v0.7.0 status |
| --- | --- | --- | --- |
| Public-surface guard | `cargo xtask public-surface` | Public crates match the documented support promises. | Pending RC run |
| Docs drift guard | `cargo xtask docs-sync --check` | User docs, snippets, and support metadata are synchronized. | Pending RC run |
| Package proof | `cargo xtask publish-preflight` | Publishable crates package with expected metadata and files. | Pending RC run |
| Publish dry-run | `cargo xtask publish-check` | Dependency order and crates.io publishability are proven before upload. | Pending RC run |
| PR evidence lane | `cargo xtask pr` plus PR summary artifacts | Fast evidence remains usable for release prep changes. | Pending RC run |
| RIPR exposure | `cargo xtask ripr-pr` / `target/ripr/pr/*` | Changed release-candidate behavior has oracle-exposure evidence. | Pending RC run |
| Public mutation scope | `cargo xtask mutants-nightly --scope public` / `target/mutation/*` | Public fixture owners have survivor-regression evidence. | Pending RC run |
| Survivor ledger | `policy/mutation-survivors.toml` / `target/mutation/survivors.*` | Mutation survivors are classified instead of rediscovered. | Pending RC run |
| Performance evidence | `cargo xtask perf --compare` / `target/xtask/perf/*` / `.github/workflows/performance.yml` | Fixture-generation and materialization cost trends stay inside enforced budgets or produce a release-visible regression. | Pending RC run |
| Receipt drift | `cargo xtask economics` and `cargo xtask audit-surface` | Cost and audit-surface receipts are current. | Pending RC run |
| Scanner guard | `cargo xtask no-blob` | Docs/examples/fixtures do not introduce committed secret-shaped blobs. | Pending RC run |
| Examples smoke | `cargo xtask examples-smoke` | User-facing examples compile or run according to the curated list. | Pending RC run |
| Bundle verifier and inspection | `cargo run -p uselesskey-cli -- verify-bundle --path <bundle>`; `cargo run -p uselesskey-cli -- inspect-bundle --path <bundle>` | Exported bundle manifests and files can be regenerated, checked, and summarized without printing fixture payloads. | Pending RC run |

## Public Promise Matrix

| Public promise | Crates or surfaces | Required evidence | Artifact or command | v0.7.0 status |
| --- | --- | --- | --- | --- |
| Default Rust fixture facade | `uselesskey` | No-default and feature-enabled facade checks; docs snippets remain synchronized. | `cargo test -p uselesskey --no-default-features`; `cargo test -p uselesskey --all-features`; `cargo xtask docs-sync --check` | Pending RC run |
| Core deterministic identity | `uselesskey-core` | Derivation, seed, identity, cache, sink, and negative-helper behavior retain focused tests and mutation evidence. | `cargo test -p uselesskey-core --all-features`; `cargo test -p uselesskey-core --no-default-features`; `cargo xtask mutants-pr --crate uselesskey-core --full-owner` when core behavior changed | Pending RC run |
| JWK/JWKS fixtures and negatives | `uselesskey-jwk`, `uselesskey-test-server`, `uselesskey-axum` | Valid/negative JWK and JWKS shapes, stable ordering, duplicate/missing `kid`, and adapter route expectations are covered at owner surfaces. | `cargo test -p uselesskey-jwk --all-features`; `cargo xtask mutants-pr --crate uselesskey-jwk` when JWK behavior changed | Pending RC run |
| Token-shape fixtures and negatives | `uselesskey-token`, `uselesskey-jsonwebtoken` | API-key, bearer, JWT-shape, near-miss, and negative-token behavior remains scanner-safe by default. | `cargo test -p uselesskey-token --all-features`; `cargo test -p uselesskey-jsonwebtoken --all-features`; `cargo xtask mutants-pr --crate uselesskey-token` when token behavior changed | Pending RC run |
| Scanner-safe bundle default | `uselesskey-cli` | `scanner-safe` bundle generation, manifest verification, human-readable inspection, materialization receipts, audit-surface receipts, and no-blob proof agree. | `cargo run -p uselesskey-cli -- bundle --profile scanner-safe --out target/uselesskey-bundle`; `cargo run -p uselesskey-cli -- verify-bundle --path target/uselesskey-bundle`; `cargo run -p uselesskey-cli -- inspect-bundle --path target/uselesskey-bundle`; `cargo xtask no-blob` | Pending RC run |
| OIDC/JWKS contract pack | `uselesskey-cli`, `uselesskey-jwk`, `uselesskey-token` | OIDC profile emits valid JWKS/JWT-shaped fixtures plus duplicate-`kid`, missing-`kid`, `alg: none`, and bad-audience negatives. | `cargo run -p uselesskey-cli -- bundle --profile oidc --out target/oidc-fixtures`; `cargo run -p uselesskey-cli -- verify-bundle --path target/oidc-fixtures`; `cargo test -p uselesskey-cli bundle_profile_oidc_writes_contract_pack --all-features` | Pending RC run |
| Kubernetes and Vault export handoff | `uselesskey-cli` | Export payloads are generated from verified bundles and do not require committed real secret material. | `cargo run -p uselesskey-cli -- export k8s --bundle-dir target/uselesskey-bundle --name uselesskey-fixtures --namespace tests --out target/uselesskey-bundle/secret.yaml`; `cargo run -p uselesskey-cli -- export vault-kv-json --bundle-dir target/uselesskey-bundle --out target/uselesskey-bundle/kv-v2.json` | Pending RC run |
| X.509 and TLS fixtures | `uselesskey-x509`, `uselesskey-rustls`, `uselesskey-tonic` | Certificate/chain fixtures, stable bytes, validity offsets, and rustls/tonic adapter contracts remain covered. | `cargo test -p uselesskey-x509 --all-features`; `cargo test -p uselesskey-rustls --all-features`; `cargo test -p uselesskey-tonic --all-features` | Pending RC run |
| RSA/ECDSA/Ed25519 fixtures | `uselesskey-rsa`, `uselesskey-ecdsa`, `uselesskey-ed25519` | Key-family encodings and deterministic fixture identity remain stable. | `cargo test -p uselesskey-rsa --all-features`; `cargo test -p uselesskey-ecdsa --all-features`; `cargo test -p uselesskey-ed25519 --all-features` | Pending RC run |
| HMAC and entropy fixtures | `uselesskey-hmac`, `uselesskey-entropy` | Symmetric and shape-only lanes keep scanner-safe defaults and explicit materialization boundaries. | `cargo test -p uselesskey-hmac --all-features`; `cargo test -p uselesskey-entropy --all-features` | Pending RC run |
| Webhook, WebAuthn, and PKCS#11 test infrastructure | `uselesskey-webhook`, `uselesskey-webauthn`, `uselesskey-pkcs11-mock` | Test infrastructure fixtures keep deterministic shape, negative/replay semantics where available, and no real secret material in repo fixtures. | `cargo test -p uselesskey-webhook --all-features`; `cargo test -p uselesskey-webauthn --all-features`; `cargo test -p uselesskey-pkcs11-mock --all-features` | Pending RC run |
| Native adapter contracts | `uselesskey-ring`, `uselesskey-rustcrypto`, `uselesskey-aws-lc-rs`, `uselesskey-pgp-native`, `uselesskey-jose-openid` | Adapter crates still return the native downstream types/configuration objects they promise. | `cargo test -p uselesskey-ring --all-features`; `cargo test -p uselesskey-rustcrypto --all-features`; `cargo test -p uselesskey-aws-lc-rs --all-features`; `cargo xtask examples-smoke` | Pending RC run |

## Bundle Reference Evidence

The v0.7.0 release candidate must attach or link a generated scanner-safe bundle
proof:

```bash
cargo xtask bundle-proof --profile scanner-safe --out target/release-evidence/scanner-safe
```

Record `scanner-safe-bundle-proof.json`,
`scanner-safe-bundle-proof.md`, the generated `manifest.json`,
`receipts/materialization.json`, `receipts/audit-surface.json`, Kubernetes
payload, Vault payload, verifier result, inspection summary, and no-blob result
in the release PR or release notes.

## Claim Boundaries

- Passing this matrix does not prove cryptographic correctness.
- Passing this matrix does not make `uselesskey` a production key-management
  system.
- Mutation evidence is sampled by crate and scope; it complements but does not
  replace deterministic regression tests.
- RIPR evidence is static oracle-exposure evidence; it does not run mutants.
- Scanner-safe bundle proof means no usable committed secret material for the
  checked bundle/profile, not scanner evasion.
