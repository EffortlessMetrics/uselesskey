# Support Matrix

_Generated from `docs/metadata/workspace-docs.json` by `cargo xtask docs-sync`._

| Crate | support_tier | publish_status | facade_exposed | intended_audience | semver_expectation | msrv_policy | replacement/deprecation |
|-------|--------------|----------------|:--------------:|-------------------|--------------------|-------------|-------------------------|
| `uselesskey` | `stable` | `published` | — | `most-users` | Public API may evolve with minor releases; breaking changes follow semver. | Tracks workspace MSRV policy. | — |
| `uselesskey-aws-lc-rs` | `incubating` | `published` | — | `adapter-users` | Public API may evolve with minor releases; breaking changes follow semver. | Tracks workspace MSRV policy. | — |
| `uselesskey-bdd` | `experimental` | `test-only` | — | `repo-internal` | Test harness crate; no external stability guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-bdd-steps` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core` | `stable` | `published` | — | `most-users` | Public API may evolve with minor releases; breaking changes follow semver. | Tracks workspace MSRV policy. | Prefer the `uselesskey` facade for most test suites; use core for custom composition. |
| `uselesskey-core-base62` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-cache` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-factory` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-hash` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-hmac-spec` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-id` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-jwk` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-jwk-builder` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-jwk-shape` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-jwks-order` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-keypair` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-keypair-material` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-kid` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-negative` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-negative-der` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-negative-pem` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-rustls-pki` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-seed` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-sink` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-token` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-token-shape` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-x509` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-x509-chain-negative` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-x509-derive` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-x509-negative` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-core-x509-spec` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-ecdsa` | `stable` | `published` | ✓ | `most-users` | Public API may evolve with minor releases; breaking changes follow semver. | Tracks workspace MSRV policy. | — |
| `uselesskey-ed25519` | `stable` | `published` | ✓ | `most-users` | Public API may evolve with minor releases; breaking changes follow semver. | Tracks workspace MSRV policy. | — |
| `uselesskey-feature-grid` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-hmac` | `stable` | `published` | ✓ | `most-users` | Public API may evolve with minor releases; breaking changes follow semver. | Tracks workspace MSRV policy. | — |
| `uselesskey-integration-tests` | `experimental` | `test-only` | — | `repo-internal` | Test harness crate; no external stability guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-interop-tests` | `experimental` | `test-only` | — | `repo-internal` | Test harness crate; no external stability guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-jose-openid` | `incubating` | `published` | — | `adapter-users` | Public API may evolve with minor releases; breaking changes follow semver. | Tracks workspace MSRV policy. | — |
| `uselesskey-jsonwebtoken` | `stable` | `published` | — | `adapter-users` | Public API may evolve with minor releases; breaking changes follow semver. | Tracks workspace MSRV policy. | — |
| `uselesskey-jwk` | `stable` | `published` | ✓ | `most-users` | Public API may evolve with minor releases; breaking changes follow semver. | Tracks workspace MSRV policy. | Prefer the `uselesskey` facade unless direct JWK-only dependency is required. |
| `uselesskey-pgp` | `stable` | `published` | ✓ | `most-users` | Public API may evolve with minor releases; breaking changes follow semver. | Tracks workspace MSRV policy. | — |
| `uselesskey-pgp-native` | `incubating` | `published` | — | `adapter-users` | Public API may evolve with minor releases; breaking changes follow semver. | Tracks workspace MSRV policy. | — |
| `uselesskey-ring` | `stable` | `published` | — | `adapter-users` | Public API may evolve with minor releases; breaking changes follow semver. | Tracks workspace MSRV policy. | — |
| `uselesskey-rsa` | `stable` | `published` | ✓ | `most-users` | Public API may evolve with minor releases; breaking changes follow semver. | Tracks workspace MSRV policy. | — |
| `uselesskey-rustcrypto` | `stable` | `published` | — | `adapter-users` | Public API may evolve with minor releases; breaking changes follow semver. | Tracks workspace MSRV policy. | — |
| `uselesskey-rustls` | `stable` | `published` | — | `adapter-users` | Public API may evolve with minor releases; breaking changes follow semver. | Tracks workspace MSRV policy. | — |
| `uselesskey-test-grid` | `experimental` | `published` | — | `repo-internal` | Internal building block; API may change in minor releases without migration guarantees. | Tracks workspace MSRV policy. | — |
| `uselesskey-token` | `stable` | `published` | ✓ | `most-users` | Public API may evolve with minor releases; breaking changes follow semver. | Tracks workspace MSRV policy. | — |
| `uselesskey-token-spec` | `stable` | `published` | — | `most-users` | Public API may evolve with minor releases; breaking changes follow semver. | Tracks workspace MSRV policy. | — |
| `uselesskey-tonic` | `stable` | `published` | — | `adapter-users` | Public API may evolve with minor releases; breaking changes follow semver. | Tracks workspace MSRV policy. | — |
| `uselesskey-x509` | `stable` | `published` | ✓ | `most-users` | Public API may evolve with minor releases; breaking changes follow semver. | Tracks workspace MSRV policy. | — |
| `xtask` | `experimental` | `internal` | — | `repo-internal` | Workspace automation crate; CLI and internals may change anytime. | Tracks workspace MSRV policy. | — |
