# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0] - 2026-06-19

v0.10.0 is the release-adoption and installed-workflow release. It makes the
CLI and facade paths easier to use from clean downstream projects, adds a
metadata-only bundle audit contract for reviewers and CI, and records the
source handoff for package-proven release evidence.

This release does not claim production security, provider compatibility,
scanner-policy approval, downstream verifier correctness, or publication until
the explicit release gate has completed.

### Added

- Added installed-user bundle audit flows that write `bundle-audit.json` and
  `bundle-audit.md`, keep generated fixture payloads out of reviewer packets,
  and expose stable `failure_class` values for CI branching.
- Added downstream CI recipes and policy presets for generating, verifying,
  auditing, and uploading metadata-only bundle audit evidence.
- Added clean-project external adoption smoke for CLI recipes and facade
  examples, including downstream-shaped webhook, OIDC/JWKS, TLS, and Rust test
  fixture examples.
- Added taxonomy-backed negative JWK/JWKS and token fixtures for validator
  failure-path tests.
- Added the v0.10 source handoff record that pins the swarm handoff SHA,
  command ledger, receipt contract, package-proof boundary, deferred source
  PRs, non-claims, and rollback path.

### Changed

- Refreshed workspace crate versions, internal path dependency constraints,
  lockfile state, and copyable install/dependency snippets for the v0.10.0
  source candidate.
- Reworked README, Start Here, feature-choice, and task-focused docs around
  user jobs instead of repo-internal crate discovery.
- Improved installed CLI help, `doctor`, `profiles`, `inspect-bundle`, and
  `audit-bundle` wording so terminal summaries stay separate from durable
  machine-readable receipts.

### Fixed

- Returned usage errors for conflicting audit modes.
- Improved audit-bundle failure diagnostics while preserving stable machine
  failure classes.
- Strengthened deterministic, cache, PEM corruption, WebAuthn, SSH, CLI, and
  fuzz coverage around the release-adoption surface.

## [0.9.1] - 2026-05-17

v0.9.1 is an adoption-confidence patch. It publishes the runtime scanner-safe
metadata correction for public asymmetric JWK/JWKS outputs, adds
adoption-regression receipts for copied user paths, and carries fixture and
adapter confidence coverage that makes v0.9.0's first-run path safer to trust.

This release does not add product claims, profiles, contract packs, README
badges, provider compatibility promises, or production security assurances.

### Added

- Added `cargo xtask adoption-regression` with Markdown and JSON receipts for
  copied user-path confidence across user-path smoke, runtime scanner-safe
  matrix, webhook profile tests, TLS/OIDC bundle proofs, and no-blob checks.
- Added fixture and adapter confidence coverage for scanner-safe metadata,
  negative variants, deterministic identity pins, debug/redaction-sensitive
  output, and copied contract-pack paths.

### Changed

- Refreshed first-run and how-to snippets so current copyable examples point at
  the v0.9 release line.

### Fixed

- Corrected runtime bundle metadata so public asymmetric RSA/ECDSA/Ed25519
  JWK/JWKS artifacts are scanner-safe while secret-bearing HMAC, token, and
  private key outputs remain outside that claim.
- Restored the no-panic-family new-debt posture after the adoption-confidence
  coverage and X.509 refactor work.

## [0.9.0] - 2026-05-14

v0.9.0 is the command-backed fixture-platform release. It turns public
claims into runnable receipts, adds local PR evidence receipts, finishes the
no-panic new-debt cleanup, and ships the first post-TLS contract pack:
deterministic webhook verifier fixtures.

The public promise is still deliberately narrow: `uselesskey` provides
scanner-safe fixture material and proof receipts for tests. It does not claim
production secret management, production PKI, provider compatibility matrices,
or broad security assurance.

### Added

- Added the source-of-truth operating model: proposal/spec/ADR/plan indexes,
  active goal manifests, policy ledgers, closeout records, and standalone
  `cargo xtask spec-check` with strict and JSON output modes.
- Added claim-backed verification surfaces: `cargo xtask claim-report`,
  `claim-report --check-public-claims`, `contract-packs --check`,
  `claim-proof`, metadata-only verification packs, and release-evidence claim
  receipts.
- Added PR-lite evidence ergonomics through `cargo xtask pr-lite` receipts,
  heavy-evidence routing receipts, local validation guidance, and safe
  diff-scoped mutation fallback behavior.
- Added the webhook contract pack: `uselesskey bundle --profile webhook`,
  deterministic HMAC verifier fixtures, webhook bundle proof, claim-proof
  coverage, verification-pack integration, and task-first webhook docs.
- Added a v0.9.0 release evidence matrix for the command-backed claims,
  verification-pack receipts, PR-lite evidence, no-panic posture, and webhook
  contract-pack proof.

### Changed

- Minor release evidence now carries source-of-truth proof, claim reports,
  contract-pack registry receipts, claim-proof receipts, verification-pack
  summaries, and webhook bundle proof.
- README, verification, and public-claim docs now route badge readers into
  command-backed reports and explicit claim boundaries instead of treating
  badges as a dashboard.
- Contract packs are now registered product surfaces with specs, claims,
  proof commands, how-to docs, and release-evidence lanes.

### Fixed

- Cleaned up the no-panic-family new-debt surface and recorded the Stage A.5
  policy posture without resetting historical baseline debt.
- Refreshed generated public badge endpoints through the existing
  command-backed badge path.

## [0.8.0] - 2026-05-12

TLS contract-pack and public crate-surface cleanup release. v0.8.0 adds
a deterministic TLS contract pack (valid chain plus four negative
classes) with a matching release-evidence proof, lands a task-first
how-to sweep across the public docs, completes the v0.7.x SRP fold by
moving HMAC/rustls/PGP content into their owner crates, and removes the
v0.7.0-vintage published-internal shim crates from the workspace.

`uselesskey` is a test-fixture layer. It is not production key
management, scanner evasion, or cryptographic assurance.

### Added

- `uselesskey bundle --profile tls` generates a deterministic TLS
  contract pack with a valid intermediate-signed chain plus four
  negative-class leaves (expired, not-yet-valid, hostname mismatch,
  untrusted root). Per-fixture rejection expectations in
  `docs/release/v0.8.0-tls-profile-design.md`. (#585, #587)
- `cargo xtask bundle-proof --profile tls` generates a release-evidence
  proof artifact for the TLS contract pack, mirroring the OIDC
  pattern, and is included in the minor-release `release-evidence`
  step list. (#588)
- Task-first how-to docs sweep across the public surface: TLS chain
  validation, Vault KV export, build.rs materialize, WebAuthn
  ceremony validation, PKCS#11 mock fixtures, and webhook signature
  validation. (#589, #590, #591, #592, #593, #594)
- `docs/how-to/migrate-to-v0.8.md` documents the v0.7.x to v0.8.0
  crate-surface migration. Most users do not need to migrate. (#603)

### Changed

- Moved `HmacSpec` and its helpers from `uselesskey-core-hmac-spec`
  into `uselesskey-hmac::srp::spec`. The former crate becomes a thin
  re-export shim while it remains in the workspace. (#595)
- Moved `RustlsPrivateKeyExt`, `RustlsCertExt`, and `RustlsChainExt`
  traits and their impls from `uselesskey-core-rustls-pki` into
  `uselesskey-rustls::srp::pki`. The former crate becomes a thin
  re-export shim while it remains in the workspace. (#598)
- Moved `PgpNativeExt` and its impls from `uselesskey-pgp-native`
  into `uselesskey-pgp::native`, gated behind the new `native` Cargo
  feature on `uselesskey-pgp`. The former crate becomes a thin
  re-export shim while it remains in the workspace. (#599)
- Activated the Rust 1.94/1.95 Clippy ratchets workspace-wide under
  `-D warnings`. (#505)
- Refreshed dependency floors via the standard maintenance lane:
  `blake3`, `tokio`, `clap`, `tonic`, `cucumber`, `rustls-pki-types`,
  `signature`, and `codecov/codecov-action`. (#484-#491)

### Removed

- Removed the 29 v0.7.0-vintage published-internal shim crates from the
  workspace. v0.7.0 folded their content into owner-crate `srp::*`
  modules; v0.7.x kept the shims as compatibility re-exports; v0.8.0
  removes them entirely. The v0.7.x crate versions remain on
  crates.io as historical records. Downstreams that pinned a shim
  directly should follow `docs/how-to/migrate-to-v0.8.md`. (#602)

## [0.7.1] - 2026-05-11

Release-hardening patch for v0.7.0. Adds publish-system guardrails,
scanner-safe reference verification, external install smoke, and a
patch-mode release evidence lane. No new product surface.

### Added

- `cargo xtask scanner-safe-reference --check` verifies the committed
  scanner-safe bundle reference outputs against regenerated bundle and
  exports. (#577)
- `cargo xtask cratesio-smoke --path <dir> | --version <V>` proves the
  external user view: fresh project, `cargo add`, `cargo check`, CLI
  install, scanner-safe bundle workflow. (#580)
- `cargo xtask release-evidence --patch` for a focused patch-release
  evidence lane (no full nightly mutation). (#581)
- `docs/how-to/recover-partial-publish.md` and
  `docs/release/publish-recovery.md` capture partial-publish recovery
  procedure and registry-truth rules. (#579)
- `docs/release/v0.7.0-lessons-learned.md` documents the v0.7.0
  publish-lane retrospective. (#571)

### Changed

- `cargo xtask publish-check` now verifies `PUBLISH_CRATES` is in
  dependency-topological order at PR time, closing the
  PUBLISH_CRATES-drift class of bug fixed inline during v0.7.0. (#572)
- `cargo xtask publish-preflight` and `publish-check` reject
  `workspace.dependencies` entries with `version = ...` when the
  target crate is `publish = false`, closing the test-helper
  dependency-leak class. (#578)

## [0.7.0] - 2026-05-10

The Rust 1.95 scanner-safe fixture platform release. v0.7.0 introduces the
end-to-end scanner-safe bundle workflow (generate, verify, inspect, export),
the OIDC/JWKS contract pack, scanner-safe negative JWK/JWKS and token
fixtures, a public-surface promise map with compatibility shims, and a full
release-evidence lane (RIPR, targeted/nightly mutation, perf, and release
proofs).

`uselesskey` remains a test-fixture layer. It is not production key
management, scanner evasion, or cryptographic assurance.

### Added

- Added the `uselesskey bundle` scanner-safe profile with deterministic
  artifacts, manifest, per-artifact lane metadata, and `receipts/` files.
- Added `uselesskey bundle --profile oidc` for an OIDC/JWKS contract pack with
  valid JWKS and JWT-shape artifacts plus duplicate-`kid`, missing-`kid`,
  `alg: none`, and bad-audience negatives.
- Added `uselesskey verify-bundle` to verify deterministic bundle outputs and
  receipts against their recorded `manifest.json`.
- Added `uselesskey inspect-bundle` for human-readable bundle summaries that
  do not print fixture payloads.
- Added `uselesskey export k8s` and `uselesskey export vault-kv-json` payload
  renderers for verified bundle directories.
- Added scanner-safe negative JWK/JWKS and token-shape fixture helpers in
  `uselesskey-jwk` and `uselesskey-token` for downstream parser and validator
  failure-path tests.
- Added a facade example (`negative_payload_shapes`) covering scanner-safe
  negative JWK/JWKS and token shapes for downstream validator tests.
- Added a public-surface promise map and `cargo xtask public-surface` guard
  separating public support promises from published-internal shards.
- Added the release-evidence runner (`cargo xtask release-evidence
  --summary`), scanner-safe and OIDC bundle proofs (`cargo xtask
  bundle-proof`), and an aggregate release evidence summary.
- Added the targeted-mutation lane: `cargo xtask mutants-pr` (PR scope) and
  `cargo xtask mutants-nightly --scope public` (full owner scope), split from
  the default `cargo xtask pr` gate.
- Added `cargo xtask ripr-pr` for repo-exposure evidence and the
  `impacted-evidence` routing command for targeted mutation/RIPR coverage on
  changed crates.
- Added the mutation survivor ledger (`policy/mutation-survivors.toml`) and
  per-run survivor receipts under `target/mutation/`.
- Added a scheduled performance evidence workflow and expanded fixture
  benchmark coverage for seed derivation, JWK/JWKS emission, WebAuthn,
  PKCS#11 mocks, and scanner-safe materialize/verify paths.
- Added a Codecov advisory coverage workflow, badge, and conservative project
  config.
- Added the `uselesskey-test-support` crate with fallible test helpers so
  test code can drop `unwrap`/`expect` while keeping diagnostics clear.
- Added the panic-safety policy stack: `policy/no-panic-allowlist.toml`,
  `policy/no-panic-baseline.toml`, `cargo xtask check-no-panic-family`, and
  the `bare-allow` burndown flip to blocking.
- Added the fixture failure atlas (`docs/reference/failure-atlas.md`),
  scanner-safe bundle reference, test-evidence-lanes guide, public-surface
  promises, PR disposition policy, v0.7.0 release category notes, evidence
  matrix, checklist issue map, and post-release audit checklist.

### Changed

- Raised MSRV from Rust 1.92 to Rust 1.95 across the workspace and enabled
  the Rust 1.95 compiler/Clippy lint floor under `-D warnings`.
- Reconciled the v0.7.0 roadmap status with the landed bundle, verification,
  Kubernetes/Vault export, scanner-safe profile, OIDC contract pack, and
  receipt workflows.
- Folded JWK/JWKS shape, builder, ordering, and deterministic `kid`
  internals into `uselesskey-jwk::srp::*`, retaining the former
  `uselesskey-core-jwk*`, `uselesskey-core-jwks-order`, and
  `uselesskey-core-kid` crates as published-internal compatibility shims.
- Folded token spec, base62, token-shape, and negative-token internals into
  `uselesskey-token::srp::*`, retaining the former `uselesskey-token-spec`,
  `uselesskey-core-base62`, `uselesskey-core-token-shape`, and
  `uselesskey-core-token` crates as published-internal compatibility shims.
- Folded core cache, factory, hash, identity, seed, sink, keypair, keypair
  material, and generic negative-fixture internals into
  `uselesskey-core::srp::*`, retaining the former `uselesskey-core-*` shards
  as published-internal compatibility shims.
- Folded X.509 spec, deterministic derive, and negative/chain-negative
  policy internals into `uselesskey-x509::srp::*`, retaining the former
  `uselesskey-core-x509*` crates as published-internal compatibility shims.
- Refreshed advisory-blocked dependency floors so PR checks start from a
  clean security baseline; bumped `blake3`, `sha2`, `insta`, and
  `aws-lc-rs` to current floors.
- Replaced direct `unwrap`/`expect` use in workspace tests with fallible
  helpers from `uselesskey-test-support` across entropy, core-id,
  core-keypair, core-keypair-material, feature-grid, core-x509, and
  core-x509-negative.

### Fixed

- Honored byte-budget and UTF-8 boundaries when truncating PEM in negative
  fixtures, preventing oversized or invalid-UTF-8 outputs.
- Fixed the WebAuthn stable-bytes encoding for fields larger than
  `u16::MAX` so deterministic ceremony fixtures stay stable for large
  inputs.
- Failed fast on oversized `u16` fixture encodings in `uselesskey-pkcs11-mock`
  and normalized empty-label provider specs to a default signing key.
- Escaped labels safely in `uselesskey-webhook` canonical JSON payload
  fixtures so generated bodies remain valid JSON for adversarial labels.
- Supported uppercase `0X` seed prefix parsing alongside lowercase `0x`.
- Made `uselesskey-core-factory` tests run without `std` so
  no-default-features lanes stay green.
- Made `cargo xtask pr` resilient when `origin/main` is missing in fresh
  checkouts.
- Hardened BDD matrix feature isolation, added missing `uk-ssh` wiring, and
  made `cargo xtask bdd` ignore commented/docstring scenario text in feature
  counts.
- Silenced `uselesskey-bdd-steps` unused warnings in default builds.

## [0.6.0] - 2026-04-08

### Added

- Added `uselesskey-entropy` as a narrow public lane for deterministic
  high-entropy byte fixtures and scanner-safe placeholder data.
- Added `uselesskey-cli materialize` / `verify` manifest workflows, including
  build-time `OUT_DIR` examples for common shape-only fixtures and specialized
  RSA PKCS#8 materialization.
- Added `cargo xtask economics` and `cargo xtask audit-surface` so lane cost
  and advisory-island receipts are generated as first-class repo artifacts.

### Changed

- Reframed the public docs around lane choice first: entropy, token, semantic
  runtime fixtures, and build-time materialized fixtures.
- Made `uselesskey-cli` publishable and split the build-time consumer surface so
  shape-only materialization stays cheap while RSA materialization remains
  explicit via `rsa-materialize`.
- Added CI drift checks and receipt artifact uploads for dependency economics
  and audit-surface reports.

## [0.5.1] - 2026-03-27

### Added

- Added X.509 chain negatives for not-yet-valid leaf/intermediate fixtures and
  intermediate CA/key-usage path failures.

### Changed

- Refreshed workspace crate versions and release-facing dependency snippets for
  the `0.5.1` release line.
- Updated dependency maintenance lanes to `toml 1.1.0`, `insta 1.47.0`, and
  `sha2 0.11.0`, with the matching RustCrypto/HMAC compatibility surface kept
  green across adapters and fuzz targets.

### Fixed

- Preserved default-chain determinism after the X.509 negative-fixture plumbing
  expansion, so unchanged `ChainSpec` inputs keep their prior certificate
  fingerprints.
- Added chain-serial regression coverage that kills the missed
  `next_serial_number` mutant.
- Aligned the fuzz RustCrypto/HMAC dependency surface with the merged adapter
  dependency updates so post-merge CI stays green.

## [0.5.0] - 2026-03-25

### Added

- Added a reusable adapter template with a scoped checklist for public-surface
  additions and release-readiness requirements.
- Added the `uselesskey-jose-openid` adapter crate for JOSE/OpenID-oriented
  native key conversion flows and example coverage.
- Added the `uselesskey-pgp-native` adapter crate for native OpenPGP key handling
  and example coverage.

### Changed

- Added `docs-sync` and metadata-driven docs checks to PR validation, including
  release-facing example/snippet verification.
- Moved README, adapter matrix, and workspace documentation to the cleaner
  adapter-wave wording and boundary-focused guidance.

## [0.4.1] - 2026-03-17

### Added

- Consistent `label()` / `spec()` accessors across RSA, ECDSA, Ed25519, HMAC,
  token, and OpenPGP fixture types.
- `cargo xtask publish-preflight` now validates versioned `uselesskey*`
  dependency snippets in release-facing docs so stale README examples are
  caught before publish.

### Changed

- Workspace manifests and versioned dependency snippets now target `0.4.1`
  ahead of the release tag.
- Release and roadmap docs now reflect the shipped RNG-boundary work and the
  current publish flow.

### Fixed

- `rustfmt.toml` now explicitly matches the workspace's Rust 2024 edition.
- `uselesskey-interop-tests` now explicitly forbids unsafe code like the rest
  of the workspace.
- Accessor mutation coverage is hardened, including the singleton Ed25519-spec
  equivalent-mutant exclusion and a fast HMAC `kid()` regression killer.

## [0.4.0] - 2026-03-13

### Changed

- Public RNG-facing APIs are now seed-oriented instead of exposing `rand` or
  `rand_core` types through the published surface.
- Seed/core/helper crates now use the newer `rand 0.10` line internally,
  while the stable crypto-edge crates remain on the intentional legacy island
  until a later convergence pass.
- Support crates and fuzz targets were updated to consume the seed-oriented
  helper APIs instead of the old RNG-shaped entry points.

### Added

- `Seed::fill_bytes(&mut [u8])` as the stable byte-oriented boundary for
  deterministic helper and fixture code.

### Notes

- This release does not claim full RNG convergence across every crypto-edge
  crate yet. Stable RSA and Ed25519 generation paths remain intentionally
  isolated on the legacy RNG line for now.

## [0.3.0] - 2026-03-12

### Changed

- `uselesskey` facade default features are now empty instead of enabling RSA by
  default. Consumers now opt into RSA, token, X.509, or other fixture families
  explicitly.
- Token-only facade usage is now documented as:
  `uselesskey = { version = "0.3.0", default-features = false, features = ["token"] }`
  so lightweight consumers avoid pulling `uselesskey-rsa` and `rsa`.

### Added

- `Seed::from_text(&str)` for deterministic seed derivation from stable text.
- `Factory::deterministic_from_str(&str)` as a facade-friendly convenience for
  test helpers that only need stable string seeds.
- A token-only consumer fixture and governance checks proving token-only facade
  usage compiles and that the resolved graph excludes `uselesskey-rsa` and
  `rsa`.
- Facade smoke coverage for order-independent determinism, X.509 re-exports,
  and published-facade-style consumer usage.

## [0.2.0] - 2026-03-06

### Added

#### Testing infrastructure

- **Snapshot tests** — `insta`-based snapshot coverage across all key-type crates
  (RSA, ECDSA, Ed25519, HMAC, Token, PGP) and adapter crates (jsonwebtoken,
  rustls, ring, rustcrypto, aws-lc-rs, tonic), pinning PEM/DER/JWK output
  formats and negative-fixture shapes
- **Property-based tests** — `proptest` strategies for core derivation,
  caching invariants, seed stability, and microcrate contracts
- **BDD scenarios** — Cucumber feature files covering all key types, X.509
  self-signed and chain certificates, JWKS ordering, cross-key validation,
  negative fixtures (corrupt PEM, truncated DER, mismatch, expired/revoked
  certs), and adapter round-trips
- **Cross-adapter interop tests** — signing round-trip and TLS handshake tests
  across rustls, ring, rustcrypto, and aws-lc-rs backends
  (`uselesskey-interop-tests`)
- **Determinism regression snapshots** — hardcoded expected-value tests ensuring
  derivation stability across releases
- **Security invariant tests** — dedicated tests verifying `Debug` impls never
  expose key material
- **Fuzz targets** — cargo-fuzz targets for negative fixture functions, parser
  stress, and seed edge cases
- **Mutant kills** — targeted tests closing surviving mutants in core microcrates
- **Error boundary tests** — edge-case and error-path coverage for factory,
  cache, and adapter crates
- **Feature-flag isolation tests** — verify each feature gate enables exactly
  the expected API surface
- **API surface stability tests** — smoke tests ensuring public API shape
  does not regress
- **Dependency guard tests** — license policy and RNG-pinning validation
- **Concurrency stress tests** — thread-safety and cache coherence under
  parallel access
- **Comprehensive microcrate tests** — coverage gap fills for core-cache,
  core-kid, core-negative, core-x509-spec, core-x509-derive, core-sink,
  jwk-builder, jwk-shape, and more

#### Refactored

- Extracted `uselesskey-token-spec` microcrate for stable token specification
  enum, shared across token generators

#### Documentation

- Polished README with quick-start examples, feature matrix, adapter guide,
  and negative-fixture documentation
- Per-crate README files for crates.io readiness
- Comprehensive architecture docs covering all 48 workspace crates
- Publish-ready `Cargo.toml` metadata across all crates (homepage, categories,
  keywords)

#### CI & tooling

- Installed `typos-cli` and `cargo-deny` in CI workflow
- Added `.typos.toml` for false-positive exclusions on crypto test data
- Scoped CI mutation testing to fast core microcrates; algorithm and adapter
  crates are mutant-tested only when directly impacted in PR runs
- Added `workflow_dispatch` trigger for manual CI invocations
- Increased CI timeouts (PR: 45 min, main: 75 min) for workspace growth
- Switched CI tool installation to `taiki-e/install-action` for pre-built
  binaries (faster cold starts)

#### Fixed

- Platform-dependent PGP RSA-3072 binary lengths redacted in snapshot tests
- RUSTSEC-2025-0119 advisory added to `deny.toml` ignore list

## [0.1.0] - 2026-02-17

Initial public release. **uselesskey** generates deterministic and random
cryptographic key fixtures for testing — preventing secret-shaped blobs from
entering version control while giving tests realistic key formats.

### Added

#### Core engine

- **Deterministic mode** — order-independent BLAKE3 derivation:
  `master_seed + artifact_id → derived_seed → RNG → artifact`.
  Adding new fixtures never perturbs existing ones.
- **Random mode** — non-deterministic generation for one-off tests.
- **Concurrent cache** — DashMap-based, keyed by `(domain, label, spec, variant)`.
  Makes RSA keygen cheap enough to avoid committed fixtures.
- **`no_std` support** — core derivation, caching, and negative helpers work
  without `std` (`uselesskey-core` with `--no-default-features`).

#### Key types

- **RSA** — PKCS#8 / SPKI in PEM / DER (2048, 3072, 4096 bits) via `RsaFactoryExt`
- **ECDSA** — P-256 / ES256, P-384 / ES384 via `EcdsaFactoryExt`
- **Ed25519** via `Ed25519FactoryExt`
- **HMAC** — HS256 / HS384 / HS512 via `HmacFactoryExt`
- **Token** — API-key, bearer, OAuth access-token shapes via `TokenFactoryExt`
- **OpenPGP** — RSA-2048/3072 and Ed25519 armored keyblocks via `PgpFactoryExt`

#### X.509 certificates

- Self-signed certificate generation via `X509FactoryExt`
- Certificate chain generation (root CA → intermediate CA → leaf)
- Chain-level negative fixtures (expired CA, wrong issuer, self-signed leaf,
  unknown CA, reversed chain, revoked leaf with CRL)
- 10-year default certificate validity; key reuse across negative variants
- TLS config builders: `RustlsServerConfigExt`, `RustlsClientConfigExt`,
  `RustlsMtlsExt` with explicit crypto-provider selection

#### JWK / JWKS

- Typed JWK / JWKS output with `JwksBuilder` and stable kid-based ordering

#### Negative fixtures

- **Corrupt PEM** — bad base64, wrong headers, truncated, deterministic
  corruption variants (`corrupt_pem_deterministic`)
- **Truncated DER** — deterministic corruption via `corrupt_der_deterministic`
- **Mismatched keypairs** — valid public key that doesn't match the private key
- Deterministic corruption convenience methods on all key-type and X.509 fixtures

#### Adapter crates

- **`uselesskey-jsonwebtoken`** — `jsonwebtoken` `EncodingKey` / `DecodingKey`
- **`uselesskey-rustls`** — `rustls-pki-types` certificates and private keys
- **`uselesskey-ring`** — `ring` 0.17 native signing key types
- **`uselesskey-rustcrypto`** — RustCrypto native types (`rsa`, `p256`, `p384`,
  `ed25519-dalek`, `hmac`)
- **`uselesskey-aws-lc-rs`** — `aws-lc-rs` native types with `native` feature
- **`uselesskey-tonic`** — gRPC TLS adapter: one-liner server / client / mTLS
  config builders for `tonic::transport`

#### Documentation

- Module-level `//!` docs and doc-tests on all public API items
- Per-crate README files for crates.io readiness
- Examples: `basic_rsa`, `all_key_types`, `jwk_jwks`, `jwt_signing`,
  `tls_server`, `negative_fixtures`

#### Tooling

- `cargo xtask ci` — full CI pipeline (fmt, clippy, tests, feature matrix,
  dep-guard, BDD, no-blob, mutants, fuzz)
- `cargo xtask pr` — PR-scoped tests with JSON receipt and summary reporting
- `cargo xtask feature-matrix` — default, no-default, each-feature, all-features
- `cargo xtask publish-check` / `cargo xtask publish-preflight` — publish dry-runs
- `cargo xtask no-blob` — secret-shaped blob detection
- `cargo xtask dep-guard` — guard against multiple versions of pinned deps

### Architecture

Repository organised into four layers:

**Facade**

| Crate | Purpose |
|-------|---------|
| `uselesskey` | Public API facade — re-exports stable surface |

**Core microcrates**

| Crate | Purpose |
|-------|---------|
| `uselesskey-core` | Factory, derivation, caching, negative helpers |
| `uselesskey-core-base62` | Base-62 generation |
| `uselesskey-core-cache` | DashMap-based concurrent cache |
| `uselesskey-core-factory` | Factory construction helpers |
| `uselesskey-core-hash` | BLAKE3 hashing primitives |
| `uselesskey-core-hmac-spec` | `HmacSpec` model |
| `uselesskey-core-id` | `ArtifactId` type |
| `uselesskey-core-jwk` | Typed JWK / JWKS models |
| `uselesskey-core-jwk-builder` | JWK builder logic |
| `uselesskey-core-jwk-shape` | JWK shape types |
| `uselesskey-core-jwks-order` | Stable kid-based JWKS ordering |
| `uselesskey-core-keypair` | Keypair abstraction |
| `uselesskey-core-keypair-material` | Raw key-material types |
| `uselesskey-core-kid` | Key-ID generation |
| `uselesskey-core-negative` | Negative-fixture orchestration |
| `uselesskey-core-negative-der` | DER corruption helpers |
| `uselesskey-core-negative-pem` | PEM corruption helpers |
| `uselesskey-core-rustls-pki` | rustls PKI type adapters |
| `uselesskey-core-seed` | Seed derivation |
| `uselesskey-core-sink` | Output-sink abstraction |
| `uselesskey-core-token` | Token generation core |
| `uselesskey-core-token-shape` | Token shape types |
| `uselesskey-core-x509` | X.509 core (negative + spec re-exports) |
| `uselesskey-core-x509-chain-negative` | Chain negative-policy types |
| `uselesskey-core-x509-derive` | X.509 derivation helpers |
| `uselesskey-core-x509-negative` | X.509 negative-fixture types |
| `uselesskey-core-x509-spec` | X.509 spec models and encoding |

**Key-type & adapter crates**

| Crate | Purpose |
|-------|---------|
| `uselesskey-rsa` | RSA fixtures (`RsaFactoryExt`) |
| `uselesskey-ecdsa` | ECDSA fixtures (`EcdsaFactoryExt`) |
| `uselesskey-ed25519` | Ed25519 fixtures (`Ed25519FactoryExt`) |
| `uselesskey-hmac` | HMAC fixtures (`HmacFactoryExt`) |
| `uselesskey-token` | Token fixtures (`TokenFactoryExt`) |
| `uselesskey-pgp` | OpenPGP keyblock fixtures (`PgpFactoryExt`) |
| `uselesskey-x509` | X.509 certificate fixtures (`X509FactoryExt`) |
| `uselesskey-jwk` | JWK facade (re-exports `uselesskey-core-jwk`) |
| `uselesskey-jsonwebtoken` | `jsonwebtoken` adapter |
| `uselesskey-rustls` | `rustls` / `rustls-pki-types` adapter |
| `uselesskey-ring` | `ring` adapter |
| `uselesskey-rustcrypto` | RustCrypto adapter |
| `uselesskey-aws-lc-rs` | `aws-lc-rs` adapter |
| `uselesskey-tonic` | `tonic` gRPC TLS adapter |

**Testing & tooling**

| Crate | Purpose |
|-------|---------|
| `uselesskey-bdd` | Cucumber BDD test runner |
| `uselesskey-bdd-steps` | BDD step definitions |
| `uselesskey-interop-tests` | Cross-adapter interop tests |
| `uselesskey-test-grid` | Test-grid generation |
| `uselesskey-feature-grid` | Feature-matrix checks |
| `tests` | Workspace-level integration tests |
| `xtask` | Build automation (`cargo xtask`) |
| `fuzz` | Fuzz targets (excluded from default workspace) |

### Testing

- **BDD** — Cucumber feature files covering RSA, ECDSA, Ed25519, HMAC, Token,
  PGP, X.509, certificate chains, JWKS, cross-key validation, negative
  fixtures, and edge cases
- **Property-based tests** — `proptest` for core derivation, caching, and
  microcrate invariants
- **Snapshot tests** — `insta` snapshots for all key-type and adapter crates
- **Fuzz targets** — 12+ targets covering derivation, negative fixtures, and
  under-fuzzed code paths
- **Cross-adapter interop** — signing and TLS round-trip tests across rustls,
  ring, rustcrypto, and aws-lc-rs
- **Security invariant** — `Debug` impls never expose key material (validated
  by dedicated tests)
- **Determinism regression** — hardcoded expected-value snapshots ensure
  derivation stability across releases

[Unreleased]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/EffortlessMetrics/uselesskey/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/EffortlessMetrics/uselesskey/releases/tag/v0.1.0
