# Public Surface

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
| `uselesskey-jose-openid` | Maybe public | JOSE/OpenID-oriented native key conversion flows. | Keep only if it serves a distinct OpenID/Jose integration job beyond `jsonwebtoken` and `test-server`. | Medium; duplicate adapter risk. | Decide deliberately. |
| `uselesskey-pgp-native` | Maybe public | Native `pgp` crate key adapters. | Keep only if users need native `pgp` types, not just PGP-shaped fixtures. | Medium; duplicate adapter risk. | Decide deliberately. |

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
| `uselesskey-core-base62` | Published internal | Compatibility shim for base62 helpers now owned by `uselesskey-token`. | None; users should consume token outputs. | Low if not recommended; noisy if treated public. | `uselesskey_token::srp::base62`. |
| `uselesskey-core-cache` | Published internal | Cache mechanics for fixture identity. | None; hidden behind `Factory`. | High if exposed because cache internals constrain implementation. | `uselesskey_core::srp::cache`. |
| `uselesskey-core-factory` | Published internal | Factory orchestration implementation. | None; `uselesskey-core` exposes `Factory`. | High if exposed because it fragments the core API. | `uselesskey_core::srp::factory`. |
| `uselesskey-core-hash` | Published internal | Length-prefixed BLAKE3 derivation helper. | None; derivation is a contract through fixture outputs. | High if exposed because algorithm changes are derivation-sensitive. | `uselesskey_core::srp::hash`. |
| `uselesskey-core-id` | Published internal | Artifact identity tuple and derivation version inputs. | None; users name labels/specs/variants through public crates. | High if exposed because identity bytes are compatibility-sensitive. | `uselesskey_core::srp::identity`. |
| `uselesskey-core-seed` | Published internal | Seed parsing and redaction implementation. | Advanced users get `Seed` from `uselesskey-core`. | Medium because `Seed` is public via `uselesskey-core`; crate split is not. | `uselesskey_core::srp::seed`. |
| `uselesskey-core-kid` | Published internal | Compatibility shim for deterministic key-ID generation now owned by `uselesskey-jwk`. | None; users observe `kid()` on fixture outputs. | High if direct imports freeze internals. | `uselesskey_jwk::srp::kid`. |
| `uselesskey-core-hmac-spec` | Published internal | HMAC spec enum implementation. | Users should import `HmacSpec` from `uselesskey-hmac` or facade. | Medium; spec values are public, crate split is not. | `uselesskey_hmac::srp::spec` or `uselesskey_core::srp::hmac_spec`. |
| `uselesskey-core-keypair` | Published internal | Shared keypair compatibility facade. | None; key families expose their own fixture handles. | Medium; re-export shell should not become a user dependency. | `uselesskey_core::srp::keypair`. |
| `uselesskey-core-keypair-material` | Published internal | PKCS#8/SPKI material helpers. | None; users ask fixture crates for PEM/DER outputs. | High if exposed because encoding internals become promises. | `uselesskey_core::srp::keypair_material`. |
| `uselesskey-core-negative` | Published internal | Compatibility facade for DER/PEM corruption helpers. | Users should use `uselesskey::negative` or fixture-specific negative APIs. | Medium; negative behavior is public, crate split is not. | `uselesskey_core::srp::negative`. |
| `uselesskey-core-negative-der` | Published internal | DER truncation/corruption implementation. | None; exposed through public negative helpers. | Medium; output behavior matters, crate split should not. | `uselesskey_core::srp::negative::der`. |
| `uselesskey-core-negative-pem` | Published internal | PEM corruption implementation. | None; exposed through public negative helpers. | Medium; output behavior matters, crate split should not. | `uselesskey_core::srp::negative::pem`. |
| `uselesskey-token-spec` | Published internal | Compatibility shim for the token spec now owned by `uselesskey-token`. | Users should import `TokenSpec` from `uselesskey-token` or facade. | Medium; spec values are public, crate split is not. | `uselesskey_token::srp::spec`. |
| `uselesskey-core-token` | Published internal | Compatibility shim for token-shape primitives now owned by `uselesskey-token`. | None; users should import `uselesskey-token`. | Medium; re-export shell should not become a user dependency. | `uselesskey_token::srp::shape`. |
| `uselesskey-core-token-shape` | Published internal | Compatibility shim for API key, bearer, JWT-shape, and negative-token construction now owned by `uselesskey-token`. | None; users should ask `TokenFixture` for values. | High if exposed because scanner-safe shape details become standalone promises. | `uselesskey_token::srp::shape`. |
| `uselesskey-core-jwk` | Published internal | Compatibility shim for typed JWK/JWKS models now owned by `uselesskey-jwk`. | Users should import `uselesskey-jwk`. | Medium; JSON shape is public through `uselesskey-jwk`, crate split is not. | `uselesskey_jwk::srp::shape`. |
| `uselesskey-core-jwk-builder` | Published internal | Compatibility shim for the JWKS builder now owned by `uselesskey-jwk`. | Users should import `JwksBuilder` from `uselesskey-jwk`. | Medium; ordering is public, builder crate split is not. | `uselesskey_jwk::srp::builder`. |
| `uselesskey-core-jwk-shape` | Published internal | Compatibility shim for structured JWK/JWKS shapes and negatives now owned by `uselesskey-jwk`. | Users should import typed shapes from `uselesskey-jwk`. | High if exposed because JSON-field internals become standalone promises. | `uselesskey_jwk::srp::shape`. |
| `uselesskey-core-jwks-order` | Published internal | Compatibility shim for stable `kid` ordering now owned by `uselesskey-jwk`. | None; users observe stable JWKS output. | Medium; ordering behavior matters, helper crate does not. | `uselesskey_jwk::srp::ordering`. |
| `uselesskey-core-x509-spec` | Published internal | X.509 spec models and encoders. | Users should import `X509Spec` / `ChainSpec` from `uselesskey-x509` or facade. | High; cert shape is visible, crate split is not. | `uselesskey_x509::srp::spec`. |
| `uselesskey-core-x509-derive` | Published internal | X.509 deterministic time, serial, and identity helpers. | None; users observe generated certs. | High if exposed because derivation details become promises. | `uselesskey_x509::srp::derive`. |
| `uselesskey-core-x509` | Published internal | X.509 policy helper/re-export shell. | Users should import `uselesskey-x509`. | Medium; re-export shell should not become a user dependency. | `uselesskey_x509::srp::policy`. |
| `uselesskey-core-x509-negative` | Published internal | X.509 certificate negative-policy implementation. | None; users call fixture negative APIs. | High if exposed because validator-error shapes become standalone promises. | `uselesskey_x509::srp::negative`. |
| `uselesskey-core-x509-chain-negative` | Published internal | X.509 chain negative-policy implementation. | None; users call chain negative APIs. | High if exposed because chain failure semantics become standalone promises. | `uselesskey_x509::srp::chain_negative`. |
| `uselesskey-core-sink` | Published internal | Tempfile and artifact sink implementation. | Users get `TempArtifact` from the facade/core API. | Medium; file-path behavior matters, crate split does not. | `uselesskey_core::srp::sink`. |
| `uselesskey-core-rustls-pki` | Published internal | Shared rustls-pki conversion bridge. | Users should import `uselesskey-rustls`. | High if exposed because downstream adapter internals become promises. | `uselesskey_rustls::srp::pki`. |

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
