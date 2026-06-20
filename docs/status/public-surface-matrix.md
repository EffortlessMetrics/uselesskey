# Public Surface Matrix

This page is the compact status view for public crate promises. The architecture
policy lives in [`docs/architecture/public-surface.md`](../architecture/public-surface.md),
and the generated support table lives in
[`docs/reference/support-matrix.md`](../reference/support-matrix.md).

Rule:

```text
Public crates are user promises.
Workspace-only crates are load-bearing structure.
```

## Primary User Surfaces

| Crate | Status | User job | Public promise | Feature flags | Docs | Action |
| --- | --- | --- | --- | --- | --- | --- |
| `uselesskey` | primary public | Rust test author needs deterministic fixture APIs. | Facade crate for valid/negative fixtures and materialization helpers. | `rsa`, `jwk`, `token`, family flags | `docs/how-to/start-here.md` | keep |
| `uselesskey-cli` | primary public | Installed user needs bundle, verify, inspect, audit, and doctor commands. | Installed CLI product surface for deterministic bundles and metadata-only receipts. | n/a | `README.md`, `docs/how-to/verify-a-fixture-bundle.md` | keep |

## Fixture-Family Surfaces

| Crate | Status | User job | Public promise | Docs | Action |
| --- | --- | --- | --- | --- | --- |
| `uselesskey-core` | public foundation | Advanced users need `Factory`, `Seed`, and shared fixture primitives. | Stable fixture foundation used by facade and family crates. | `docs/architecture/public-surface.md` | keep |
| `uselesskey-entropy` | public family | Tests need deterministic byte fixtures or scanner-safe placeholder data. | Entropy and placeholder fixture generation. | `docs/reference/support-matrix.md` | keep |
| `uselesskey-rsa` | public family | Tests need RSA PEM/DER/JWK-compatible fixtures. | RSA fixture extension trait and specs. | `docs/how-to/materialize-rsa-fixtures-at-build-time.md` | keep |
| `uselesskey-ecdsa` | public family | Tests need ECDSA P-256/P-384 fixtures. | ECDSA fixture extension trait and specs. | `docs/reference/support-matrix.md` | keep |
| `uselesskey-ed25519` | public family | Tests need Ed25519 fixtures. | Ed25519 fixture extension trait. | `docs/reference/support-matrix.md` | keep |
| `uselesskey-hmac` | public family | Tests need deterministic HMAC fixture material. | HMAC fixture extension trait and specs. | `docs/reference/support-matrix.md` | keep |
| `uselesskey-token` | public family | Tests need token-shaped positives and negatives. | Token fixture extension trait plus `NegativeToken` stable IDs. | `docs/how-to/test-jwt-negative-validation.md` | keep |
| `uselesskey-jwk` | public family | Tests need typed JWK/JWKS shapes and negatives. | JWK/JWKS builders and `NegativeJwk`/`NegativeJwks` stable IDs. | `docs/how-to/test-oidc-jwks-validation.md` | keep |
| `uselesskey-x509` | public family | Tests need certificates, chains, and TLS-shaped negatives. | X.509 fixture extension trait and negative chain helpers. | `docs/how-to/test-tls-chain-validation.md` | keep |
| `uselesskey-ssh` | public family | Tests need SSH key and certificate fixtures. | OpenSSH fixture traits and specs. | `docs/reference/support-matrix.md` | keep |
| `uselesskey-pgp` | public family | Tests need OpenPGP-shaped fixtures. | PGP fixture extension trait and armored/binary output. | `docs/reference/support-matrix.md` | keep |
| `uselesskey-webhook` | public family | Tests need deterministic HMAC webhook requests. | Webhook fixture APIs for valid and negative verifier paths. | `docs/how-to/test-webhook-signature-validation.md` | keep |
| `uselesskey-test-server` | public test infrastructure | Integration tests need OIDC/JWKS HTTP routes. | Test server fixture surface. | `docs/reference/support-matrix.md` | keep |
| `uselesskey-pkcs11-mock` | public test infrastructure | Tests need PKCS#11 mock/provider fixtures. | Mock provider fixture surface. | `docs/reference/support-matrix.md` | keep |
| `uselesskey-webauthn` | public test infrastructure | Tests need WebAuthn credential/assertion fixtures. | WebAuthn fixture surface. | `docs/reference/support-matrix.md` | keep |

## Adapter Surfaces

| Crate | Status | User job | Public promise | Action |
| --- | --- | --- | --- | --- |
| `uselesskey-jsonwebtoken` | public adapter | Users already chose `jsonwebtoken`. | Native `jsonwebtoken` encoding/decoding fixture helpers. | keep |
| `uselesskey-rustls` | public adapter | Users already chose `rustls`. | Native `rustls` PKI/config fixture helpers. | keep |
| `uselesskey-tonic` | public adapter | Users already chose `tonic`. | Native tonic TLS identity/config fixture helpers. | keep |
| `uselesskey-axum` | public adapter | Users already chose `axum`. | Auth-test route and request fixture helpers. | keep |
| `uselesskey-ring` | public adapter | Users already chose `ring`. | Native `ring` fixture conversions. | keep |
| `uselesskey-rustcrypto` | public adapter | Users already chose RustCrypto APIs. | Native RustCrypto fixture conversions. | keep |
| `uselesskey-aws-lc-rs` | public adapter | Users already chose `aws-lc-rs`. | Native aws-lc-rs fixture conversions. | keep |

## Workspace-Only Structure

| Crate | Status | User job | Public promise | Action |
| --- | --- | --- | --- | --- |
| `uselesskey-test-grid` | workspace-only | CI/test grid only. | none | keep internal |
| `uselesskey-feature-grid` | workspace-only | CI feature matrix only. | none | keep internal |
| `uselesskey-bdd` | workspace-only | BDD runner only. | none | keep internal |
| `uselesskey-bdd-steps` | workspace-only | BDD shared steps only. | none | keep internal |
| `uselesskey-interop-tests` | workspace-only | Cross-adapter repo tests only. | none | keep internal |
| `uselesskey-bench` | workspace-only | Bench receipts only. | none | keep internal |
| `uselesskey-integration-tests` | workspace-only | Root integration tests only. | none | keep internal |
| `materialize-buildrs-example` | workspace-only | Example crate users copy, not depend on. | none | keep internal |
| `materialize-shape-buildrs-example` | workspace-only | Example crate users copy, not depend on. | none | keep internal |
| `xtask` | workspace-only | Maintainer/repo proof automation. | none as a crate | keep internal |

## Boundary

This matrix does not demote or remove crates. Public-surface changes that affect
publish status, support tier, or semver expectations must update the generated
support matrix, `docs/metadata/workspace-docs.json`, and the release story in a
separate release-aware PR.
