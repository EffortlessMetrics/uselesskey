+++
id = "USELESSKEY-SPEC-0019"
kind = "spec"
title = "Library facade polish"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-19"
milestone = "v0.10.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0003",
  "USELESSKEY-ADR-0004",
]
linked_plan = "plans/usability-polish/implementation-plan.md"
linked_specs = [
  "USELESSKEY-SPEC-0013",
  "USELESSKEY-SPEC-0015",
  "USELESSKEY-SPEC-0016",
  "USELESSKEY-SPEC-0018",
]
support_tier_impact = []
policy_impact = []
+++

# USELESSKEY-SPEC-0019: Library Facade Polish

## Problem

The installed CLI path now gives downstream users a direct way to generate,
inspect, verify, and audit bundles. Rust test authors need the same direct path
through the `uselesskey` facade crate.

The current crate surface is powerful but easy to encounter through internal
crate names, feature-matrix tables, or examples that assume the reader already
knows which extension trait unlocks which fixture family. A new Rust user should
not need crate archaeology before first value.

The target Rust path is:

```text
pick a test job
  -> copy one facade dependency snippet
    -> import Factory plus one extension trait
      -> generate deterministic valid and invalid fixtures
        -> keep generated material in test runtime or target/
          -> understand the boundary
```

This spec defines the library-facing polish for the v0.10.0 product-quality
target. It does not redesign the facade API.

## Behavior

The `uselesskey` facade is the default Rust test-author entry point. Leaf crates
remain valid for compile-time minimization, adapter ownership, and advanced
users, but first-run Rust docs and examples should start with the facade unless
the user job is explicitly adapter-specific.

Facade-first docs and examples must answer:

- which job the snippet solves;
- the smallest useful `uselesskey` feature set;
- the required extension trait imports;
- the deterministic seed or label posture;
- one positive fixture path;
- one negative fixture path when the job is about validation;
- whether generated material stays in memory, under `target/`, or in another
  explicit output directory;
- what the snippet does not prove.

The primary snippet pattern is:

```toml
[dev-dependencies]
uselesskey = { version = "0.9.1", default-features = false, features = ["rsa"] }
```

```rust
use uselesskey::{Factory, RsaFactoryExt, RsaSpec};

let fx = Factory::deterministic_from_str("test-seed");
let key = fx.rsa("issuer", RsaSpec::rs256());
let pkcs8_pem = key.private_key_pkcs8_pem();
```

Feature flags should be shown as the smallest task-shaped sets, not as broad
collections:

| Job | Facade feature set | First imports |
| --- | --- | --- |
| RSA key fixture in a Rust test | `default-features = false, features = ["rsa"]` | `Factory`, `RsaFactoryExt`, `RsaSpec` |
| Token-shaped string fixture | `default-features = false, features = ["token"]` | `Factory`, `TokenFactoryExt`, `TokenSpec` |
| OIDC/JWKS validator fixture | `default-features = false, features = ["rsa", "jwk"]` | `Factory`, `RsaFactoryExt`, `RsaSpec` |
| TLS chain validation fixture | `default-features = false, features = ["x509"]` | `Factory`, `X509FactoryExt`, `ChainSpec` or `X509Spec` |
| Webhook signature fixture | `default-features = false, features = ["webhook"]` | `Factory`, `WebhookFactoryExt`, `WebhookPayloadSpec` |

Adapter crates may appear beside facade snippets only when the job requires
native downstream ecosystem types. The adapter dependency should be named as a
second interface, not as the first way to discover `uselesskey`.

### Missing-Feature Guidance

Rust missing-feature failures usually surface as unresolved imports or missing
extension methods. Facade-first examples and docs must make those failures
actionable by:

- naming the required feature set next to the snippet;
- keeping in-repo examples gated with fallback text that prints the exact
  feature command where practical;
- making external examples use explicit `default-features = false` snippets so
  the dependency shape is visible;
- letting external smoke preserve cargo stderr in receipts when a clean-project
  snippet fails to compile.

This spec does not require a custom compile-time diagnostic macro.

### External Example Shape

Facade-first external examples should be small clean projects under
`examples/external/`. Each example should include:

- `Cargo.toml` with a facade dependency snippet;
- a tiny `src/lib.rs` or `tests/` surface that models a downstream test;
- a `README.md` with the user job, copyable command, and boundary;
- no dependency on workspace-only crates unless the example is explicitly a
  repo-local proof example;
- no generated payloads committed into the example directory.

Examples should prefer deterministic runtime generation in tests. If a fixture
must be written to disk, it should go under `target/` or a temporary directory
owned by the test.

## Non-goals

This spec does not:

- prepare, cut, tag, or publish v0.10.0;
- redesign `Factory`, extension traits, specs, or fixture structs broadly;
- collapse adapter crates into the facade;
- make leaf crates private;
- add new fixture families or contract packs;
- add WebAuthn, PKCS#11, Vault/Kubernetes, or other product breadth;
- claim provider compatibility, production security, release readiness, or
  permission to bypass scanner policy;
- require installed CLI commands to execute `xtask` or claim-ledger commands;
- require a broad policy language for downstream users.

## Required Evidence

Library facade polish is proven by:

- a spec-backed set of facade-first example requirements;
- docs that use current stable dependency snippets in current how-to paths;
- clean external examples that compile through `external-adoption-smoke --path .`
  when bounded;
- `docs-sync --check` for dependency snippet consistency;
- `typos` and `spec-check --strict` for source-of-truth hygiene.

When a PR changes a facade example or external smoke path, it should also run:

```bash
cargo xtask external-adoption-smoke --path .
cargo test -p xtask external_adoption_smoke
```

## Acceptance

This spec is satisfied when:

- Rust test-author docs start from `uselesskey` facade snippets before leaf
  crate internals;
- each facade-first example names the user job, feature set, imports, positive
  path, negative path where relevant, and boundary;
- clean external examples compile without relying on workspace-only crates;
- missing-feature guidance is visible at the snippet or example boundary;
- generated runtime material is not committed as fixture payloads;
- adapter crates remain separate, explicit second interfaces;
- repo-local proof machinery remains separate from first-run Rust examples.

## Acceptance Examples

Good facade-first example:

```text
Job: test a JWT verifier with deterministic RSA/JWKS fixtures
Dependency: uselesskey = { version = "0.9.1", default-features = false, features = ["rsa", "jwk"] }
Imports: Factory, RsaFactoryExt, RsaSpec
Positive: valid public JWK/JWKS accepted by the test verifier
Negative: duplicate kid or wrong-kty fixture rejected by the test verifier
Boundary: proves the downstream test path rejects these deterministic shapes; does not prove provider compatibility
Smoke: cargo xtask external-adoption-smoke --path .
```

Bad facade-first example:

```text
Job: unclear
Dependency: use several leaf crates directly before showing the facade
Imports: missing extension trait
Output: commits generated PEM/JWT payloads into examples/
Boundary: absent
Smoke: not run in a clean project
```

## Test Mapping

| Requirement | Evidence |
| --- | --- |
| Dependency snippets stay current | `cargo xtask docs-sync --check` |
| Facade examples compile externally | `cargo xtask external-adoption-smoke --path .` |
| External smoke stays bounded | `cargo test -p xtask external_adoption_smoke` |
| Generated payloads are not committed | `cargo xtask no-blob` in `pr-lite` or closeout |
| Public claims remain separate from examples | `cargo xtask claim-report --check-public-claims` in closeout |

## Implementation Mapping

| Surface | Owner |
| --- | --- |
| Facade crate API and examples | `crates/uselesskey/` |
| Clean external examples | `examples/external/` |
| External example smoke | `xtask/src/external_adoption_smoke.rs` |
| Feature choice docs | `docs/how-to/choose-features.md` |
| Task router | `docs/how-to/start-here.md` |
| README front door | `README.md` |
| Usability lane plan | `plans/usability-polish/implementation-plan.md` |

## CI Proof

Spec-only changes must run:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Example or smoke changes must also run:

```bash
cargo xtask external-adoption-smoke --path .
cargo test -p xtask external_adoption_smoke
```

Full lane closeout also runs the broader proof listed in
`plans/usability-polish/implementation-plan.md`.

## Metrics / Promotion Rule

This spec stays accepted while it defines the library-facing contract. It is
implemented when:

- facade-first external examples exist for the selected Rust user jobs;
- external adoption smoke covers those examples;
- current docs route Rust test authors to the facade before leaf internals;
- closeout records that the examples compile without release prep or new product
  breadth.
