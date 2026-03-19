# Roadmap follow-up (post-v0.4.1)

Use this file to create GitHub milestones and issues directly. The entries are intentionally copy-ready.

## Milestone: v0.5.0 adapter wave

### Issue 1 — docs: reset roadmap and mark next execution unit
**Title:** `roadmap: reset planning for v0.5.0 adapter wave`  
**Body:**  
Update `docs/explanation/roadmap.md` to make `Now` `v0.5.0` and split planning into explicit milestones:

- `v0.5.0 adapter wave`
- `v0.5.1 negative fixtures`
- `v0.5.2 benchmarks and perf`

Add a short planning note that `v0.5.1 / v0.5.2` are intentionally deferred and `v0.4.1` work is complete.

**Acceptance:**

- Roadmap `Now` section says `v0.5.0`.
- `Later` section has deferred items and "no commitment" state.
- No stale references imply `v0.4.1` is still current for planning.

### Issue 2 — adr: define adapter acceptance criteria
**Title:** `adr: define adapter acceptance criteria`  
**Body:**  
Create `docs/adr/000X-adapter-acceptance-criteria.md` defining what qualifies as a new adapter crate, expected native-type return, and review bar.

Include:

- Definition of an adapter crate versus core feature.
- What does not qualify as an adapter.
- When a feature belongs in existing crates instead of a new crate.
- Required docs/tests/examples, release surface expectations, and compatibility promise.

**Acceptance:**

- ADR follows existing `docs/adr/` template style.
- Decision rule is explicit and actionable by contributors.
- At least one concrete example of "adapter yes" and "adapter no".

### Issue 3 — adr: define public surface policy
**Title:** `adr: define publishable public surface policy`  
**Body:**  
Create `docs/adr/000X-workspace-public-surface-policy.md` defining which crates are intentionally publishable and what governance applies.

Address:

- Stability commitments for public API across microcrates.
- How to keep internal implementation out of publishable surface.
- Default review bar before adding or retaining a new publishable crate.
- Effect on release risk with 43-candidate publish list size.

**Acceptance:**

- Policy maps to `PUBLISH_CRATES` and release checklist.
- Explicit rule for adding, deprecating, or removing a publishable crate.
- Signed-off-by lead or maintainers in PR description.

### Issue 4 — chore: add reusable adapter template
**Title:** `docs: add reusable adapter authoring checklist/template`  
**Body:**  
Add a short template in `docs/how-to/` (and link from `CONTRIBUTING.md` if appropriate) that includes:

- crate naming and feature flag conventions
- README dependency snippet format
- minimum smoke/integration layout
- example layout and README table update expectations
- feature-matrix + docs metadata requirements

**Acceptance:**

- New adapter contributors can follow a deterministic checklist.
- Template includes a “ready for review” pre-publish checklist.
- Example snippet sections are explicit for common failure modes.

### Issue 5 — chore: scaffold adapter A (JOSE/OpenID)
**Title:** `adapter: scaffold JOSE/OpenID adapter microcrate`  
**Body:**  
Implement the first wave-1 adapter using existing JWK/JWKS/token fixture families.

Required deliverables:

- New crate (or existing adapter extension if sufficient)
- README with dependency snippet and native type mapping
- Example compiling with documented feature set
- At least one smoke or integration test
- `PUBLISH_CRATES` entry and release-note coverage

**Acceptance:**

- Fixtures convert to target native types with deterministic behavior.
- Example commands are documented and reproducible.
- `cargo xtask publish-preflight` passes for this crate.

### Issue 6 — chore: scaffold adapter B (PGP-native)
**Title:** `adapter: scaffold PGP-native microcrate`  
**Body:**  
Implement the second wave-1 adapter for native PGP consumption paths.

Required deliverables:

- New crate or well-scoped adapter package
- README and runnable example
- At least one smoke or integration test
- docs snippet + release metadata updates
- Feature-matrix entry if feature-gated behavior exists

**Acceptance:**

- Armored and binary keyblocks map to native target types.
- Conversion is deterministic and tested.
- `cargo xtask publish-preflight` passes.

### Issue 7 — release: prepare v0.5.0 cleanup artifacts
**Title:** `release: prep docs/changelog for v0.5.0 adapter wave`  
**Body:**  
After adapter work is done, update roadmap/top-level docs and changelog for `v0.5.0`.

- `README.md` Now/Next pointers for adapter wave
- `CHANGELOG.md` release entry
- Release prep verifies clean on merge

**Acceptance:**

- `cargo xtask gate --check`
- `cargo xtask publish-preflight`
- `cargo xtask publish-check`
- `PUBLISH_CRATES` is updated for any new crates

## Milestone: v0.5.1 negative fixtures

### Issue 8 — fixture: add x.509 trust/time/path negatives
**Title:** `fixtures: expand x.509 negative variants`  
**Body:**  
Add deterministic X.509 negative families:

- not-yet-valid leaf
- not-yet-valid intermediate
- EKU mismatch
- incorrect or missing key usage
- invalid basic constraints
- bad CRL signatures
- stale CRL / `nextUpdate` failure
- chain ordering and omission variants

**Acceptance:**

- Deterministic variant naming and fixture contract aligned to existing corruption APIs.
- One example consumer and at least one integration test.
- Docs/snippets for new variants documented.

### Issue 9 — fixture: add jwk/jwks semantic negatives
**Title:** `fixtures: expand jwk and jwks semantic negatives`  
**Body:**  
Add deterministic malformed/semantically inconsistent variants:

- duplicate `kid`
- missing `kid`
- `alg`/`kty` mismatch
- inconsistent `use` / `key_ops`
- malformed `x5c`
- malformed RSA modulus/exponent
- mixed validity ordering cases

**Acceptance:**

- Factory API includes variants with stable naming.
- Negative shapes can be consumed by auth tests without manual payload crafting.
- Snapshot or unit coverage for each new variant.

### Issue 10 — fixture: add token-shape failure variants
**Title:** `fixtures: add token-shape failure variants`  
**Body:**  
Add deterministic non-validating failure fixtures:

- expired token shape
- `nbf` in future
- issuer mismatch
- audience mismatch
- malformed header/body
- malformed segment count/encoding

**Acceptance:**

- No signing/verification API added (fixture-only scope).
- Variants documented as artifacts and consumer examples updated.
- One test coverage path exercises each major negative family.

### Issue 11 — docs: publish guidance for negative fixtures usage
**Title:** `docs: add negative fixture decision and migration guide`  
**Body:**  
Add guidance covering:

- how to pick negative fixture families
- which failure mode maps to which fixture family
- scanner-safe migration notes for teams replacing committed artifacts

**Acceptance:**

- Guide references new families in Issues 8-10.
- Includes copy/paste runnable examples.
- Reviewed for task-oriented flow from README.

## Milestone: v0.5.2 benchmarks and perf

### Issue 12 — perf: add benchmark harness and baseline
**Title:** `bench: add criterion harness for key and cert generation`  
**Body:**  
Add Criterion benches for:

- RSA by key size
- ECDSA / Ed25519 / HMAC generation
- X.509 leaf and chain generation
- cache miss vs hit
- deterministic vs random mode
- concurrency patterns

**Acceptance:**

- Bench harness runs and reports deterministic baseline.
- Benchmark doc with machine/config notes committed.
- Not on default PR gate initially.

### Issue 13 — perf: schedule manual/nighly benchmark workflow
**Title:** `ci: add manual or scheduled perf workflow`  
**Body:**  
Add workflow that runs benchmark suite on a controlled schedule / manual dispatch.

- Stores baseline artifacts or publishes reports.
- No regression threshold in default gate until two baselines captured.

**Acceptance:**

- Workflow executes successfully on a known branch.
- Baseline report committed and linked from docs.

## Milestone: release governance

### Issue 14 — release: add release category configuration
**Title:** `release: add release note categories and post-release checklist`  
**Body:**  
Add release governance files:

- `.github/release.yml` with categorized labels
- `post-release` checklist for docs/docs.rs/crates.io/release artifacts
- optional `xtask post-release-audit` summary command

**Acceptance:**

- Release note output is categorized by type.
- Checklist referenced in release runbook.
- Audit command, if added, reports published crate count and artifact links.
