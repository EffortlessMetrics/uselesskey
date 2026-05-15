# v0.9.0 Post-Release Audit

Audit date: 2026-05-14 local, 2026-05-15 UTC.

## Summary

v0.9.0 is published and externally verifiable.

- GitHub release is visible at
  <https://github.com/EffortlessMetrics/uselesskey/releases/tag/v0.9.0>.
- Tag `v0.9.0` points at
  `b03772d01e3d194a638b5b6a606f551c436adc43`.
- All intended publish crates are visible on crates.io at `0.9.0`.
- The 29 removed v0.7.x shim crates were not republished at `0.9.0`.
- `cargo xtask cratesio-smoke --version 0.9.0` passed from a fresh registry
  install path.
- docs.rs reports `doc_status: true` for `uselesskey 0.9.0`.
- Stable claim proof, verification pack, and TLS/OIDC/webhook bundle proofs
  passed after publish.

## Release Identity

| Item | State |
| --- | --- |
| Tag | `v0.9.0` |
| Tag SHA | `b03772d01e3d194a638b5b6a606f551c436adc43` |
| GitHub release | <https://github.com/EffortlessMetrics/uselesskey/releases/tag/v0.9.0> |
| GitHub release published | `2026-05-15T00:52:41Z` |
| Cut PR | #673 `release: cut v0.9.0` |

## crates.io

The intended publish surface was checked through the crates.io API. Each crate
reported `max_version = 0.9.0` and a visible `0.9.0` version:

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
cargo xtask cratesio-smoke --version 0.9.0
```

The smoke installed `uselesskey 0.9.0` with `rsa,jwk,token`, installed
`uselesskey-cli 0.9.0`, generated a scanner-safe bundle, verified it, and
inspected it.

## Removed Shims

The removed v0.7.x compatibility shim crates remain capped at `0.7.1` and do
not have a `0.9.0` version:

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

docs.rs accepted and built the facade docs for `uselesskey 0.9.0`.

Checked endpoints:

```text
https://docs.rs/crate/uselesskey/0.9.0
https://docs.rs/uselesskey/0.9.0/uselesskey/
https://docs.rs/crate/uselesskey/0.9.0/status.json
```

The status endpoint returned:

```json
{"doc_status":true,"version":"0.9.0"}
```

No republish action is needed.

## Post-Release Proof

These commands passed after publishing:

```bash
cargo xtask cratesio-smoke --version 0.9.0
cargo xtask claim-proof --all-stable
cargo xtask verification-pack --out target/uselesskey-verification
cargo xtask bundle-proof --profile tls --out target/release-evidence/tls
cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc
cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook
cargo xtask public-surface
cargo xtask publish-check
cargo xtask badges --check
cargo xtask check-no-panic-family
git diff --check
```

Proof highlights:

- `claim-proof --all-stable` passed for stable public claims.
- `verification-pack` built a metadata-only reviewer bundle.
- TLS, OIDC/JWKS, and webhook bundle proofs all passed.
- `public-surface` checked 35 workspace crates: 17 public promises, 7 adapter
  promises, 0 published internals, and 11 workspace-only crates.
- `check-no-panic-family` reported 0 new debt, 0 stale baseline entries, and 0
  expired allowlist entries in no-new-debt mode.

## Workflow Notes

The tag-triggered Release workflow ran after `v0.9.0` was pushed.

- `preflight`: success.
- `publish`: success.
- `release`: failed only at `gh release create "v0.9.0" --generate-notes`.

The release job failed because the GitHub release had already been created
manually with curated changelog notes:

```text
HTTP 422: Validation Failed
Release.tag_name already exists
```

This is an audit finding about release automation idempotency, not a package
publish defect. The GitHub release exists and is public.

## Claim Boundaries

v0.9.0 ships command-backed fixture-platform proof, not broad security
assurance.

- `ripr+` is repo-scoped static evidence and test-efficiency signal, not
  runtime correctness or mutation adequacy.
- Scanner-safe means committed fixture surfaces passed the configured policy;
  derived encoded exports are not automatically safe to commit.
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

The only release-audit follow-up is to make the tag-triggered release creation
step idempotent, or choose one release creation authority for future releases.
No crates.io, docs.rs, claim-proof, verification-pack, or contract-pack proof
defect was found.
