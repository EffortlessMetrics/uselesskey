+++
id = "USELESSKEY-SPEC-0015"
kind = "spec"
title = "Real user workflows"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-18"
milestone = "v0.10.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0003",
]
linked_plan = "plans/real-workflow-closure/implementation-plan.md"
linked_specs = [
  "USELESSKEY-SPEC-0002",
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0009",
  "USELESSKEY-SPEC-0011",
  "USELESSKEY-SPEC-0012",
  "USELESSKEY-SPEC-0013",
  "USELESSKEY-SPEC-0014",
]
support_tier_impact = []
policy_impact = []
+++

# USELESSKEY-SPEC-0015: Real User Workflows

## Problem

`uselesskey` now has strong repo-local proof and installed bundle audit. That
does not automatically mean a downstream user can solve a test problem quickly.

The product needs a small set of workflow contracts that keep future work
anchored to user jobs:

```text
Rust developer path:
  I need deterministic valid and invalid fixtures in tests.

CI/platform path:
  I need scanner-safe secret-shaped payloads and metadata receipts for verifier
  tests and CI review.

Materialization path:
  I need real key material only when I explicitly generate it under target/ or
  another selected output directory.
```

These workflows are the product aperture for the real workflow closure lane.
They should guide fixture additions, docs, examples, bundle receipts, and public
crate promises without becoming a roadmap dump.

## Behavior

Every accepted workflow must include:

- one copyable command or Rust snippet;
- one positive case;
- one negative case;
- one verification command;
- one receipt or smoke path;
- one "does not prove" boundary.

Workflow docs and examples must route by user job before crate layout. Internal
implementation crates, claim ledgers, release evidence, and `xtask` proof
machinery may be linked as deeper references, but the first user path must be a
copyable installed CLI command or a facade-crate Rust snippet.

### Rust Developer Path

The Rust developer path is for users writing tests inside a Rust project.

Copyable snippet:

```toml
[dev-dependencies]
uselesskey = { version = "0.10.0", default-features = false, features = ["rsa", "jwk", "token"] }
```

```rust
use uselesskey::{Factory, RsaFactoryExt, RsaSpec};

let fx = Factory::deterministic_from_str("issuer-test-seed");
let key = fx.rsa("issuer", RsaSpec::rs256());
let public_jwk = key.public_jwk();
```

Positive case:

```text
valid deterministic fixture material can be generated from the same seed, label,
spec, and variant without perturbing other fixture identities.
```

Negative case:

```text
the same facade path exposes deterministic negative fixtures, such as malformed
JWK/JWKS or token-shaped values, that map to realistic parser/verifier failures.
```

Verification command:

```bash
cargo test
```

Receipt or smoke path:

```bash
cargo xtask external-adoption-smoke --path .
```

Boundary:

```text
This proves deterministic test-fixture behavior for the downstream test. It does
not prove production key management, production crypto safety, provider
compatibility, scanner evasion, or repo public claims.
```

### CI / Platform Path

The CI/platform path is for users who need deterministic bundles and
metadata-only receipts from the installed CLI.

Copyable command:

```bash
uselesskey bundle --profile webhook --out target/uselesskey-webhook
uselesskey verify-bundle --path target/uselesskey-webhook
uselesskey inspect-bundle --path target/uselesskey-webhook
uselesskey audit-bundle --path target/uselesskey-webhook --out target/uselesskey-webhook-audit --ci
```

Positive case:

```text
the generated bundle contains a valid fixture case for the selected profile.
```

Negative case:

```text
the generated bundle contains deterministic negative cases, such as tampered
webhook bodies, duplicate JWKS kids, bad token claims, or invalid TLS chains,
when the profile or task requires them.
```

Verification command:

```bash
uselesskey verify-bundle --path target/uselesskey-webhook
```

Receipt or smoke path:

```bash
cargo xtask external-adoption-smoke --path . --ci-recipes --format json
```

Boundary:

```text
Installed bundle audit proves local bundle consistency and metadata
classification. It does not prove release readiness, repo public claims,
provider compatibility, production security, scanner evasion, or downstream
verifier correctness.
```

### Materialization Path

The materialization path is for users who need real generated key material,
certificates, tokens, requests, or exports as runtime test artifacts.

Copyable command:

```bash
uselesskey bundle --profile scanner-safe --out target/uselesskey-scanner-safe
```

Positive case:

```text
generated artifacts are deterministic for the selected seed/profile and are
written under the selected output directory.
```

Negative case:

```text
secret-shaped or runtime-material artifacts are explicitly classified in the
manifest and audit receipt, and task docs tell users not to commit generated
payloads unless the artifact is documented scanner-safe.
```

Verification command:

```bash
uselesskey audit-bundle --path target/uselesskey-scanner-safe --summary
```

Receipt or smoke path:

```text
target/uselesskey-scanner-safe/receipts/materialization.json
target/uselesskey-scanner-safe/receipts/audit-surface.json
target/uselesskey-scanner-safe/receipts/bundle-verification.json
target/uselesskey-scanner-safe/receipts/scanner-safety.json
target/uselesskey-scanner-safe/receipts/negative-coverage.json
```

Boundary:

```text
Materialization proves the selected fixture output was generated locally with
documented metadata. It does not make every encoded export safe to commit, does
not manage production secrets, and does not replace organization policy.
```

## Non-goals

This spec does not prepare or cut v0.10.0.

This spec does not require a version bump, tag, crates.io publish, GitHub
release, or shipper migration.

This spec does not add a new contract pack, fixture family, README badge,
provider compatibility matrix, production security assurance, or scanner
evasion claim.

This spec does not move claim-proof, verification-pack, or release evidence out
of repo-local `xtask` commands.

This spec does not require installed CLI commands to execute `xtask` or
claim-ledger command strings.

## Required Evidence

Docs-only changes to this spec should run:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Workflow implementation PRs should add the narrow proof command for the touched
surface. Examples:

```bash
cargo test -p uselesskey-jwk --all-features
cargo test -p uselesskey-token --all-features
cargo xtask external-adoption-smoke --path .
cargo xtask adoption-regression --external
cargo +nightly xtask pr-lite
git diff --check
```

## Acceptance

This spec is accepted when:

- it defines the Rust developer, CI/platform, and materialization workflows;
- each workflow has a copyable command or snippet, positive case, negative
  case, verification command, receipt or smoke path, and boundary;
- it keeps installed-user paths separate from repo-local public-claim proof;
- it preserves scanner-safe, metadata-only, provider-compatibility, production
  security, and scanner-evasion boundaries.

This spec is implemented when:

- task-first docs expose each workflow before crate layout;
- external adoption smoke proves the copyable installed CLI and Rust dependency
  paths;
- negative fixture taxonomy and implementation PRs attach realistic negative
  cases to the Rust developer and CI/platform paths;
- bundle manifests and receipts identify scanner-safe and runtime-material
  posture for the materialization path;
- public surface docs identify which crates and features serve each workflow.

## Acceptance Examples

Acceptable Rust developer workflow:

```text
User copies a facade crate snippet, generates a deterministic public JWK, and
uses a documented malformed-JWK negative fixture in a parser test.
```

Acceptable CI/platform workflow:

```text
User runs bundle, verify-bundle, inspect-bundle, and audit-bundle --ci under
target/, then uploads bundle-audit.json and bundle-audit.md as CI artifacts.
```

Acceptable materialization workflow:

```text
User materializes a bundle under target/, audits it, and shares metadata-only
receipts instead of generated secret-shaped payloads.
```

Not acceptable:

```text
Docs route a first-time user through claim-ledger, release-evidence, or active
goal files before showing the command or snippet for their test job.
```

Not acceptable:

```text
Generated runtime payloads are copied into reviewer packets or committed as
examples without an explicit scanner-safe exception.
```

## Test Mapping

Real user workflow proof maps to:

- `cargo xtask external-adoption-smoke --path .` for clean-project Rust and
  installed CLI paths;
- `cargo xtask external-adoption-smoke --path . --ci-recipes --format json` for
  downstream CI recipes;
- `cargo xtask adoption-regression --external` for a broader adoption receipt;
- crate-specific tests for JWK/JWKS, token, and adapter negative fixture shapes;
- `cargo xtask no-blob` when generated payload or scanner-safe posture changes;
- `cargo xtask docs-sync --check` for copyable snippet drift;
- `cargo xtask public-surface` for public crate promise discipline.

## Implementation Mapping

Workflow ownership:

- `crates/uselesskey` owns the facade crate path for Rust developers.
- `crates/uselesskey-cli` owns installed CLI bundle, verify, inspect, audit, and
  materialization commands.
- `crates/uselesskey-jwk` owns JWK/JWKS fixture shapes and negatives.
- `crates/uselesskey-token` owns token-shaped fixture negatives.
- Contract-pack profile owners keep TLS, OIDC/JWKS, and webhook workflows
  bounded to existing claims and non-goals.
- `examples/external/` owns clean-project workflow examples.
- `docs/how-to/` owns task-first workflow pages.
- `xtask` owns repo-local proof and adoption smoke receipts.

## CI Proof

Docs-only PR:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Workflow implementation PR:

```bash
cargo xtask external-adoption-smoke --path .
cargo xtask adoption-regression --external
cargo +nightly xtask pr-lite
git diff --check
```

Closeout PR:

```bash
cargo xtask external-adoption-smoke --path . --format json
cargo xtask adoption-regression --external
cargo xtask claim-report --check-public-claims
cargo xtask contract-packs --check
cargo xtask check-no-panic-family
cargo xtask docs-sync --check
cargo xtask typos
cargo +nightly xtask pr-lite
cargo xtask pr
git diff --check
```

## Metrics / Promotion Rule

This spec can move to implemented when:

- each workflow has a task-first doc or external example;
- each workflow has at least one positive and one negative path;
- external adoption smoke or adoption-regression proves the copyable path;
- materialization docs and receipts keep generated payloads under explicit
  output directories;
- public crate surface docs map each public promise to a workflow.
