# Verification

`uselesskey` has three verification surfaces:

- README badges are public, repo-scoped trust markers.
- Pull request evidence is diff-scoped reviewer and agent feedback.
- Release evidence is shipped-truth proof for public version handoff.

Badges are the front panel. The generated evidence, CI receipts, and release
artifacts remain the source of truth.

For the public claim index and local proof path, see
[`docs/status/PUBLIC_CLAIMS.md`](status/PUBLIC_CLAIMS.md) and
[`docs/how-to/verify-uselesskey-public-claims.md`](how-to/verify-uselesskey-public-claims.md).

## README badges

### `ripr+`

`ripr+` is a repo-scoped static evidence badge. It counts unresolved static
exposure gaps plus actionable test-efficiency findings under repository policy.

It is an inbox-zero signal, not coverage, runtime mutation proof, or correctness
proof. Diff-scoped `ripr` artifacts belong in pull request summaries and CI
artifacts, not public README badges.

### `scanner-safe fixtures`

The scanner-safe badge means repository automation found no committed
secret-shaped fixture blobs under the configured fixture policy.

It does not mean the project is safe for production key generation,
certificate management, scanner evasion, or cryptographic assurance.

### Release

The release badge shows the latest GitHub release. GitHub releases are the
public version surface for this repository; crates.io downloads and docs.rs
remain registry and documentation surfaces.

## Regeneration

Regenerate public badge endpoints:

```bash
cargo xtask badges
```

The badge command also refreshes the target-only
`target/ripr/reports/test-efficiency.*` evidence consumed by `ripr+`. To inspect
that evidence directly:

```bash
cargo xtask test-efficiency-report
```

Check for committed endpoint drift:

```bash
cargo xtask badges --check
```

Committed endpoint files live under `badges/`. Detailed reports stay under
`target/` locally or in CI artifacts.

## Claim Reports

`cargo xtask claim-report` turns `policy/claim-ledger.toml` into reader and
machine receipts:

```bash
cargo xtask claim-report
cargo xtask claim-report --format json
cargo xtask claim-report --claim scanner-safe-fixtures
```

The command writes:

```text
target/claim-report/public-claims.md
target/claim-report/public-claims.json
```

Use `cargo xtask claim-report --check-public-claims` to verify that the
hand-written public claim page still contains every stable ledger claim, its
proof commands, and its boundary.

## Claim Proof Receipts

`cargo xtask claim-proof` runs allowlisted proof handlers for selected claims
and writes per-claim receipts:

```bash
cargo xtask claim-proof --claim scanner-safe-fixtures
cargo xtask claim-proof --claim tls-contract-pack
cargo xtask claim-proof --all-stable
```

The command uses symbolic handlers from `policy/claim-ledger.toml`; it does not
shell-evaluate proof-command strings from the ledger. Receipts stay under
`target/claim-proof/`.

## Verification Packs

Use `cargo xtask verification-pack` when a reviewer needs a shareable bundle of
public-claim receipts:

```bash
cargo xtask verification-pack --out target/uselesskey-verification
```

The pack contains claim reports, contract-pack registry reports, badge endpoint
JSON, and selected claim-proof receipts. It contains metadata and receipts only,
not generated fixture payloads.

## Release Evidence Receipts

Patch release evidence records the public claim index:

```bash
cargo xtask release-evidence --version 0.8.1 --patch --dry-run --summary
```

Minor release evidence records both public claims and contract-pack registry
state:

```bash
cargo xtask release-evidence --version 0.9.0 --dry-run --summary
```

Non-dry release evidence writes these receipts:

```text
target/release-evidence/claims/public-claims.md
target/release-evidence/claims/public-claims.json
target/release-evidence/contract-packs/contract-packs.md
target/release-evidence/contract-packs/contract-packs.json
target/release-evidence/verification-pack/README.md
```

## Pull Request Evidence

Pull requests run advisory `ripr` PR evidence, `ripr` review guidance, impacted
evidence, fast gates, docs-sync, publish preflight, example smoke checks, and
targeted mutation when routing rules require it.

`ripr` may suggest focused tests or route targeted mutation. It does not edit
code, generate tests, run mutation, or make merge decisions by default.

Line-placeable `ripr` review guidance is emitted as non-blocking annotations
from `comments[]` only. Summary-only findings stay in summaries and artifacts;
inline PR comments are disabled by default.

Pull request artifacts and summaries are diff-scoped. They must not be reused
as repo-scope README badges.
