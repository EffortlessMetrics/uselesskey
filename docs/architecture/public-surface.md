# Public Surface

> **v0.8.0 status.** The "Published Internal" and "Maybe public" survey rows
> for the `uselesskey-core-*` shards, `uselesskey-token-spec`,
> `uselesskey-pgp-native`, and `uselesskey-jose-openid` were resolved by the
> v0.8.0 SRP collapse: those 29 crates are removed and their content lives
> under owner-crate `srp::*` modules. The remaining public surface is the
> facade, owner crates, adapters, CLI, and test-server / pkcs11-mock.

`uselesskey` has three different crate-level concepts. Keep them separate:

| Term | Meaning | User-facing promise |
|------|---------|---------------------|
| Workspace crate | A package in this repository. | Not automatically. |
| Published crate | A package released to crates.io. | Maybe, but not automatically. |
| Public support promise | A crate users are meant to depend on directly. | Yes. |

The support matrix remains the generated source of truth for support tier,
publish status, audience, and semver wording. This document is the human-facing
architecture policy for deciding whether a crate is a product surface or an
implementation boundary.

Run `cargo xtask public-surface` when changing workspace crates, publish
metadata, adapter stories, or public-support classification. The guard keeps
this policy, `docs/metadata/workspace-docs.json`, and the Cargo package graph in
sync before demicrocrate work lands.

The rule is:

```text
one public crate per user-facing promise
one SRP module per internal responsibility
```

Publishing a crate does not make it a recommended user dependency. Several
current microcrates are published only because the workspace went through a
microcrate extraction phase. Their generated metadata marks them as
`experimental`, `repo-internal`, and points users back to `uselesskey` or the
fixture-family crates. Treat that as the support signal.

## Public Promise Crates

These crates are product surfaces. A user can reasonably put one of them in
`Cargo.toml` because it maps to a real testing job.

| Crate | Classification | Why it exists | Downstream import story | Semver risk | Collapse? |
|-------|----------------|---------------|--------------------------|-------------|-----------|
| `uselesskey` | Public | Default facade for deterministic fixtures, scanner-safe defaults, negative helpers, and materialization lanes. | Most users depend on this crate with feature flags. | Highest public API coordination risk; facade changes shape the product. | No. |
| `uselesskey-cli` | Public operator surface | CI/operator commands for materialization, verification, bundles, receipts, and release checks. | Operators install or run it in scripts. | Medium; CLI flags, output schema, and receipts are user-visible. | No. |
| `uselesskey-core` | Public foundation | `Factory`, `Seed`, modes, temp artifacts, and generic negative helpers shared by facade and family crates. | Advanced users and fixture-family crates import foundational types. | Medium; small API but central to all extension traits. | No. |
| `uselesskey-entropy` | Public fixture family | Deterministic high-entropy byte fixtures and scanner-safe placeholder data. | Minimal-dependency users import entropy fixtures directly. | Low to medium; output shape and lane semantics matter. | No. |
| `uselesskey-rsa` | Public fixture family | RSA PEM/DER/JWK-compatible keypair fixtures and mismatch negatives. | Users who need only RSA fixtures import `RsaFactoryExt` and `RsaSpec`. | Medium; key formats and deterministic identity are visible. | No. |
| `uselesskey-ecdsa` | Public fixture family | ECDSA P-256/P-384 keypair fixtures. | Users who need only ECDSA fixtures import `EcdsaFactoryExt` and `EcdsaSpec`. | Medium; curve/spec and encoding stability are visible. | No. |
| `uselesskey-ed25519` | Public fixture family | Ed25519 keypair fixtures. | Users who need only Ed25519 fixtures import `Ed25519FactoryExt`. | Medium; encoding and identity stability are visible. | No. |
| `uselesskey-hmac` | Public fixture family | HMAC HS256/HS384/HS512 secret fixtures. | Users who need only symmetric fixtures import `HmacFactoryExt`. | Low to medium; byte length and JWK shape are visible. | No. |
| `uselesskey-token` | Public fixture family | API-key, bearer-token, OAuth/JWT-shape, and token-negative fixtures. | Users who need token-shaped fixtures import `TokenFactoryExt`. | Medium; scanner-safe token shape and negative semantics are visible. | No. |
| `uselesskey-jwk` | Public fixture family | Typed JWK/JWKS output and builder semantics. | Users who need JWKS payloads import typed JWK/JWKS helpers. | Medium; JSON shape and deterministic ordering are visible. | No. |
| `uselesskey-x509` | Public fixture family | Self-signed certificates, chains, TLS-shaped artifacts, and X.509 negatives. | Users who need cert fixtures import `X509FactoryExt`. | High; certificate fields, validity, and chain negatives are visible. | No. |
| `uselesskey-ssh` | Public fixture family | OpenSSH key and certificate fixtures. | Users who need SSH key/cert shapes import SSH fixture traits and specs. | Medium; OpenSSH encodings are visible. | No. |
| `uselesskey-pgp` | Public fixture family | OpenPGP key fixtures in armored and binary form. | Users who need PGP-shaped fixtures import `PgpFactoryExt`. | Medium; OpenPGP packet shape and platform tolerance are visible. | No. |
| `uselesskey-webhook` | Public fixture family | GitHub, Stripe, Slack, and near-miss webhook signature fixtures. | Users import webhook fixtures for request-verifier tests. | Medium; provider shape and near-miss semantics are visible. | No. |
| `uselesskey-test-server` | Public test infrastructure | OIDC discovery and JWKS HTTP test server fixtures. | Integration-test users run an HTTP test server without building routes. | Medium; HTTP routes and payload shapes are visible. | No. |
| `uselesskey-pkcs11-mock` | Public test infrastructure | PKCS#11 mock provider fixtures. | Users import it for HSM/provider integration tests. | Medium; provider API and fixture behavior are visible. | No. |
| `uselesskey-webauthn` | Public test infrastructure | WebAuthn credential and assertion fixtures. | Users import it for passkey/WebAuthn tests. | Medium; WebAuthn shape compatibility is visible. | No. |

## Adapter Promise Crates

Adapter crates are public when they return native downstream ecosystem types or
configuration objects. They serve users who already chose a downstream library.

| Crate | Classification | Why it exists | Downstream import story | Semver risk | Collapse? |
|-------|----------------|---------------|--------------------------|-------------|-----------|
| `uselesskey-jsonwebtoken` | Public adapter | Converts fixtures to `jsonwebtoken` encoding and decoding keys. | JWT users import native `jsonwebtoken` helpers. | Medium; tracks upstream API compatibility. | No. |
| `uselesskey-rustls` | Public adapter | Converts cert fixtures into `rustls` PKI/config types. | TLS users import `rustls` server/client config builders. | High; tracks `rustls` and provider compatibility. | No. |
| `uselesskey-tonic` | Public adapter | Builds `tonic::transport` TLS identity and config fixtures. | gRPC users import tonic-specific builders. | Medium; tracks tonic/rustls compatibility. | No. |
| `uselesskey-axum` | Public adapter | Provides auth-test helpers and deterministic JWKS/OIDC routes for `axum`. | HTTP-service users import route/test helpers. | Medium; tracks axum and route-shape expectations. | No. |
| `uselesskey-ring` | Public adapter | Exposes `ring` native signing/verifying fixture types. | Users import `ring` conversion helpers directly. | Medium; tracks ring API compatibility. | No. |
| `uselesskey-rustcrypto` | Public adapter | Exposes RustCrypto native key and signing fixture types. | Users import RustCrypto conversion helpers directly. | High; tracks pre-release RustCrypto APIs. | No. |
| `uselesskey-aws-lc-rs` | Public adapter | Exposes `aws-lc-rs` native key/signature fixtures. | Users import aws-lc-rs conversion helpers directly. | High; native build requirements and upstream API compatibility are visible. | No. |

## Workspace-Only Crates

These crates are repository infrastructure. They are not public promises.

| Crate | Classification | Why it exists | Downstream import story | Semver risk | Collapse? |
|-------|----------------|---------------|--------------------------|-------------|-----------|
| `uselesskey-test-grid` | Workspace-only | Test-grid facade for repo validation. | None; CI owns it. | No public risk. | Keep workspace-only. |
| `uselesskey-feature-grid` | Workspace-only | Feature-matrix definitions for CI and BDD. | None; CI owns it. | No public risk. | Keep workspace-only. |
| `uselesskey-bdd` | Workspace-only | Cucumber BDD test runner. | None; test runner only. | No public risk. | Keep workspace-only. |
| `uselesskey-bdd-steps` | Workspace-only | Shared BDD step definitions. | None; test runner only. | No public risk. | Keep workspace-only. |
| `uselesskey-interop-tests` | Workspace-only | Cross-adapter integration tests. | None; CI owns it. | No public risk. | Keep workspace-only. |
| `uselesskey-bench` | Workspace-only | Benchmark harness and performance receipts. | None; CI/release evidence owns it. | No public risk. | Keep workspace-only. |
| `uselesskey-integration-tests` | Workspace-only | Root integration-test package. | None; CI owns it. | No public risk. | Keep workspace-only. |
| `materialize-buildrs-example` | Workspace-only | Build-script materialization example crate. | Users copy the example pattern, not depend on the crate. | No public risk. | Keep workspace-only. |
| `materialize-shape-buildrs-example` | Workspace-only | Shape-only materialization example crate. | Users copy the example pattern, not depend on the crate. | No public risk. | Keep workspace-only. |
| `xtask` | Workspace-only | Repository automation. | None; invoked through `cargo xtask`. | No public crate risk; command behavior still matters to contributors. | Keep workspace-only. |

## Published Internal Crates

These crates are implementation shards. They may currently be published for
release-graph reasons, but they are not user promises. Prefer demoting them into
single-responsibility modules under the owning public crate over time.

| Crate | Classification | Why it exists | Downstream import story | Semver risk | Collapse target |
|-------|----------------|---------------|--------------------------|-------------|-----------------|

## Demotion Policy

Collapsing a published internal crate is release work, not cleanup churn. Do it
only when the owning crate can absorb the module without breaking current
published dependency constraints.

For each demotion:

- keep one owner crate responsible for the behavior and tests
- preserve deterministic derivation and fixture output compatibility
- keep public re-exports only where users already import them from a supported
  surface
- record deprecation/removal rationale in the changelog and release notes
- update `docs/metadata/workspace-docs.json`, the generated support matrix, and
  publish preflight expectations in the same PR
- run `cargo xtask public-surface` so the support metadata and package graph
  agree

Do not add new public crates for internal SRP boundaries. Add modules inside the
owning public crate instead.
