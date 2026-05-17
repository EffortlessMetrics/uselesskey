# v0.9.1 Post-Release Audit

Audit date: 2026-05-17 local and UTC.

## Summary

v0.9.1 is published and externally verifiable.

- GitHub release is visible at
  <https://github.com/EffortlessMetrics/uselesskey/releases/tag/v0.9.1>.
- Tag `v0.9.1` points at
  `fc69fb4acc6d585505b11b50ec1ca76cf8d49f98`.
- The tag-triggered Release workflow completed successfully through preflight,
  publish, and GitHub release creation.
- All intended publish crates are visible on crates.io at `0.9.1`.
- The 29 removed v0.7.x shim crates were not republished at `0.9.1`.
- `cargo xtask cratesio-smoke --version 0.9.1` passed from a fresh registry
  install path.
- docs.rs reports `doc_status: true` for `uselesskey 0.9.1`.
- Adoption-regression, stable claim proof, verification-pack, and
  TLS/OIDC/webhook bundle proofs passed after publish.

## Release Identity

| Item | State |
| --- | --- |
| Tag | `v0.9.1` |
| Tag SHA | `fc69fb4acc6d585505b11b50ec1ca76cf8d49f98` |
| GitHub release | <https://github.com/EffortlessMetrics/uselesskey/releases/tag/v0.9.1> |
| GitHub release published | `2026-05-17T11:48:03Z` |
| Release workflow | <https://github.com/EffortlessMetrics/uselesskey/actions/runs/25989100361> |
| Cut PR | #763 `release: cut v0.9.1` |

## crates.io

The intended publish surface was checked through the crates.io API. Each crate
reported `max_version = 0.9.1` and a visible `0.9.1` version:

```text
uselesskey-jwk
uselesskey-core
uselesskey-entropy
uselesskey-rsa
uselesskey-ecdsa
uselesskey-ed25519
uselesskey-hmac
uselesskey-token
uselesskey-webhook
uselesskey-pkcs11-mock
uselesskey-webauthn
uselesskey-ssh
uselesskey-pgp
uselesskey-x509
uselesskey-test-server
uselesskey-axum
uselesskey-cli
uselesskey-jsonwebtoken
uselesskey-rustls
uselesskey-tonic
uselesskey-ring
uselesskey-rustcrypto
uselesskey-aws-lc-rs
uselesskey
```

The external install smoke passed:

```bash
cargo xtask cratesio-smoke --version 0.9.1
```

The smoke installed `uselesskey 0.9.1` with `rsa,jwk,token`, installed
`uselesskey-cli 0.9.1`, generated a scanner-safe bundle, verified it, and
inspected it.

## Removed Shims

The removed v0.7.x compatibility shim crates remain capped at `0.7.1` and do
not have a `0.9.1` version:

```text
uselesskey-core-cache
uselesskey-core-factory
uselesskey-core-hash
uselesskey-core-id
uselesskey-core-seed
uselesskey-core-sink
uselesskey-core-keypair
uselesskey-core-keypair-material
uselesskey-core-negative
uselesskey-core-negative-der
uselesskey-core-negative-pem
uselesskey-core-kid
uselesskey-core-jwk
uselesskey-core-jwk-builder
uselesskey-core-jwk-shape
uselesskey-core-jwks-order
uselesskey-core-base62
uselesskey-core-token
uselesskey-core-token-shape
uselesskey-token-spec
uselesskey-core-x509
uselesskey-core-x509-spec
uselesskey-core-x509-derive
uselesskey-core-x509-negative
uselesskey-core-x509-chain-negative
uselesskey-core-hmac-spec
uselesskey-core-rustls-pki
uselesskey-pgp-native
uselesskey-jose-openid
```

## docs.rs

docs.rs accepted and built the facade docs for `uselesskey 0.9.1`.

Checked endpoints:

```text
https://docs.rs/crate/uselesskey/0.9.1
https://docs.rs/uselesskey/0.9.1/uselesskey/
https://docs.rs/crate/uselesskey/0.9.1/status.json
```

The status endpoint returned:

```json
{"doc_status":true,"version":"0.9.1"}
```

No republish action is needed.

## Post-Release Proof

These commands passed after publishing:

```bash
cargo xtask cratesio-smoke --version 0.9.1
cargo xtask adoption-regression
cargo xtask claim-proof --all-stable
cargo xtask verification-pack --out target/uselesskey-verification
cargo xtask bundle-proof --profile tls --out target/release-evidence/tls
cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc
cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook
cargo xtask no-blob
cargo xtask check-no-panic-family
cargo xtask public-surface
cargo xtask publish-check
cargo xtask badges --check
git diff --check
```

Proof highlights:

- `adoption-regression` passed and wrote Markdown/JSON receipts under
  `target/adoption-regression/`.
- `claim-proof --all-stable` passed for stable public claims.
- `verification-pack` built a metadata-only reviewer bundle.
- TLS, OIDC/JWKS, and webhook bundle proofs all passed.
- `no-blob` passed after generated release proof artifacts were written under
  `target/`.
- `check-no-panic-family` reported 0 new debt, 0 stale baseline entries, and 0
  expired allowlist entries in no-new-debt mode.
- `public-surface` checked 35 workspace crates: 17 public promises, 7 adapter
  promises, 0 published internals, and 11 workspace-only crates.

## Workflow Notes

The tag-triggered Release workflow ran after `v0.9.1` was pushed.

- `preflight`: success.
- `publish`: success.
- `release`: success.

The v0.9.0 audit found that GitHub release creation needed a single authority.
For v0.9.1, the tag-triggered workflow was that authority and created the
release successfully.

## Claim Boundaries

v0.9.1 is an adoption-confidence patch, not a new product-claim release.

- Scanner-safe means committed fixture surfaces passed the configured policy and
  bundle metadata classifies material by sensitivity. Derived encoded exports
  are not automatically safe to commit.
- Runtime public asymmetric JWK/JWKS metadata now marks public material as
  scanner-safe; private PEM/DER, HMAC `k`, token values, and secret-bearing
  runtime outputs remain outside that claim.
- TLS fixtures prove deterministic verifier-path fixtures, not production PKI,
  revocation, CT, mTLS, browser trust-store behavior, or certificate
  operations.
- OIDC/JWKS fixtures prove deterministic discovery/JWKS verifier fixtures, not
  identity-provider compatibility, token lifetime policy, key rotation policy,
  or network security.
- Webhook fixtures prove deterministic HMAC verifier request fixtures and
  negative cases, not provider compatibility, secret rotation, delivery
  retries, replay protection completeness, transport security, or production
  secret management.

## Follow-Up

No crates.io, docs.rs, claim-proof, verification-pack, bundle-proof,
no-panic-family, or no-blob defect was found.

The release lane can be closed. The next product lane should start from a fresh
active goal instead of extending v0.9.1 release state.
