# v0.9.1 Release Evidence Matrix

This matrix maps the v0.9.1 patch release story to the proof commands that must
carry it.

v0.9.1 is an adoption-confidence patch. It publishes confidence work already
landed on `main` after v0.9.0:

```text
runtime metadata correction
  -> copied user-path smoke
    -> adoption-regression receipts
      -> claim-proof and verification-pack checks
        -> patch release evidence
```

This document is the release-candidate proof map. It names the required proof,
the receipt surface, and the v0.9.1 candidate status. Generated receipts stay
under `target/` unless a later PR explicitly adds a tracked receipt path.

## Candidate Proof Status

Candidate proof completed on 2026-05-17. Generated receipts stayed under
`target/` and are not committed.

Commands that passed:

```bash
cargo xtask release-evidence --version 0.9.1 --patch --dry-run --summary
cargo xtask adoption-regression
cargo xtask adoption-regression --format json
cargo xtask claim-proof --all-stable
cargo xtask user-path-smoke
cargo xtask check-no-panic-family
cargo xtask claim-report --check-public-claims
cargo xtask contract-packs --check
cargo +nightly xtask pr-lite
cargo xtask pr
git diff --check
```

During candidate proof, `cargo xtask claim-proof --all-stable` found generated
`ripr+` badge endpoint drift. The badge endpoint refresh landed separately in
#749, and the claim proof passed after the candidate branch rebased on that
refresh.

## Pre-Tag Proof Status

Pre-tag proof completed on 2026-05-17 after the workspace and copyable snippets
were bumped to `0.9.1`.

Commands that passed:

```bash
cargo xtask release-evidence --version 0.9.1 --patch --dry-run --summary
cargo xtask publish-preflight
cargo xtask publish-check
cargo xtask no-blob
cargo xtask check-no-panic-family
cargo xtask badges --check
cargo xtask docs-sync --check
cargo xtask pr
git diff --check
```

`cargo xtask pr` first exposed the local Windows ASAN runtime precondition:
the fuzz target exited with `STATUS_DLL_NOT_FOUND` because
`clang_rt.asan_dynamic-x86_64.dll` was not on `PATH`. The rerun passed after
prepending the Visual Studio MSVC runtime directory:

```powershell
$env:PATH = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64;$env:PATH"
cargo xtask pr
```

The fuzz run also refreshed `fuzz/Cargo.lock` so the fuzz workspace lockfile
matches the current workspace package versions and existing manifest dependency
requirements.

## Patch Scope

v0.9.1 is scoped to:

- runtime public asymmetric JWK/JWKS scanner-safe metadata correction;
- `cargo xtask adoption-regression` Markdown and JSON receipts;
- fixture-confidence coverage for copied user paths;
- no-panic new-debt restoration;
- current copyable how-to snippets.

It does not add product claims, profiles, contract packs, README badges,
provider compatibility promises, production security promises, shipper
migration work, historical no-panic baseline work, or broad dependency churn.

## Required Release Gates

| Gate | Command or artifact | Patch claim covered | v0.9.1 candidate status |
| --- | --- | --- | --- |
| Source-of-truth proof | `cargo xtask spec-check --strict` | Specs, plans, active goals, and claim ledgers are parseable and linked. | Passed in candidate proof. |
| Public claim drift check | `cargo xtask claim-report --check-public-claims` | Public claim index matches `policy/claim-ledger.toml`. | Passed in candidate proof. |
| Contract-pack registry | `cargo xtask contract-packs --check` | Existing stable contract packs remain registered and bounded. | Passed in candidate proof. |
| Patch release evidence | `cargo xtask release-evidence --version 0.9.1 --patch --dry-run --summary` | Patch lane carries publish-system and user-path smoke evidence without full minor-release expansion. | Passed in candidate and pre-tag proof. |
| Adoption regression | `cargo xtask adoption-regression` and `cargo xtask adoption-regression --format json` | Copied user paths, runtime scanner-safe matrix, webhook profile tests, TLS/OIDC proofs, and no-blob pass. | Passed in candidate proof. |
| Stable claim proof | `cargo xtask claim-proof --all-stable` | Stable public claims still have whitelisted proof handlers. | Passed in candidate proof after #749 badge refresh. |
| User-path smoke | `cargo xtask user-path-smoke` | Scanner-safe, TLS, OIDC, and webhook copyable paths still work. | Passed in candidate proof. |
| No-panic family | `cargo xtask check-no-panic-family` | Stage A.5 new-debt posture remains clean. | Passed in candidate and pre-tag proof. |
| PR-lite local evidence | `cargo +nightly xtask pr-lite` | Local contributor evidence remains bounded and receipt-backed. | Passed in candidate proof. |
| Full PR gate | `cargo xtask pr` | Fast PR evidence, docs, examples, public-surface, and receipts pass. | Passed in candidate and pre-tag proof. |
| Publish preflight | `cargo xtask publish-preflight` | Metadata, package, and snippet checks are ready before publish. | Passed in pre-tag proof. |
| Publish dry run | `cargo xtask publish-check` | Publishable crates dry-run in dependency order. | Passed in pre-tag proof. |
| Secret-shaped blob gate | `cargo xtask no-blob` | No committed secret-shaped fixture blobs were introduced. | Passed in pre-tag proof; repeat in audit. |
| Badge endpoint drift | `cargo xtask badges --check` | Existing generated badge endpoints remain current; v0.9.1 adds no badge. | Passed in pre-tag proof. |
| Post-release crates.io smoke | `cargo xtask cratesio-smoke --version 0.9.1` | External registry install view works after publish. | Post-release audit only. |
| docs.rs state | `docs/release/post-release-audit-v0.9.1.md` | docs.rs is complete, queued, failed, or not found; queued is not a republish reason. | Post-release audit only. |

## Scanner-Safe Metadata Proof

The patch's user-visible fix is runtime public JWK/JWKS scanner-safe metadata.
The candidate proof must show that public asymmetric JWK/JWKS artifacts are
treated as scanner-safe while secret-bearing HMAC, token, and private key
outputs remain outside that claim.

The direct proof path is:

```bash
cargo xtask adoption-regression
cargo xtask adoption-regression --format json
cargo xtask user-path-smoke
cargo xtask no-blob
```

## Public Claim Matrix

| Public claim | Surfaces | Required evidence | Artifact or command | v0.9.1 status |
| --- | --- | --- | --- | --- |
| Scanner-safe fixtures | README badge, `badges/scanner-safe.json`, `docs/status/PUBLIC_CLAIMS.md`, bundle manifests | Scanner-safe reference, runtime matrix, no-blob gate, generated badge drift check | `cargo xtask claim-proof --claim scanner-safe-fixtures`; `cargo xtask adoption-regression`; `cargo xtask no-blob` | Candidate proof passed. |
| TLS contract pack | `uselesskey bundle --profile tls`, TLS how-to, contract-pack registry | Existing bundle proof and contract-pack registry row remain valid | `cargo xtask bundle-proof --profile tls --out target/release-evidence/tls`; `cargo xtask claim-proof --claim tls-contract-pack` | Post-release audit repeat. |
| OIDC/JWKS contract pack | OIDC/JWKS docs and contract-pack registry | Existing bundle proof and contract-pack registry row remain valid | `cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc`; `cargo xtask claim-proof --claim oidc-jwks-contract-pack` | Post-release audit repeat. |
| Webhook contract pack | `uselesskey bundle --profile webhook`, webhook how-to, contract-pack registry | Existing bundle proof, claim-proof handler, and verification-pack inclusion remain valid | `cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook`; `cargo xtask claim-proof --claim webhook-contract-pack` | Post-release audit repeat. |
| Public crate-surface stability | README, docs metadata, support matrix, publish plan | Public-surface and publish preflight checks | `cargo xtask public-surface`; `cargo xtask publish-preflight`; `cargo xtask publish-check` | Pre-tag and audit. |
| External crates.io install smoke | Post-release audit, release evidence | External install against published registry version | `cargo xtask cratesio-smoke --version 0.9.1` | Post-release only. |

## Verification-Pack Proof

The metadata-only review bundle must remain buildable:

```bash
cargo xtask verification-pack --out target/uselesskey-verification
cargo xtask verification-pack --out target/uselesskey-verification --claim scanner-safe-fixtures
```

The verification pack contains receipts and metadata. It must not copy generated
secret-shaped fixture payloads into a shareable review bundle.

## Claim Boundaries

Scanner-safe fixtures mean repository automation found no committed
secret-shaped fixture blobs under the configured fixture policy and that bundle
metadata classifies fixture material by sensitivity. This does not mean every
derived encoded export is safe to commit, and it does not prove scanner evasion.

TLS contract-pack proof covers deterministic verifier-path fixtures. It does
not prove production PKI, revocation, CT, mTLS, browser trust-store behavior,
or operational certificate management.

OIDC/JWKS contract-pack proof covers deterministic discovery/JWKS verifier
fixtures. It does not prove production identity-provider compatibility, token
lifetime policy, key rotation policy, or network security.

Webhook contract-pack proof covers deterministic HMAC webhook verifier fixtures
for positive and negative request cases. It does not prove production webhook
provider compatibility, secret rotation, delivery retries, timestamp-policy
suitability, replay protection completeness, transport security, or production
secret management.

PR evidence is diff-scoped and advisory. It belongs in summaries, annotations,
and artifacts, not public README badges.

## Candidate Proof Command Set

The release-candidate proof PR should run:

```bash
cargo xtask release-evidence --version 0.9.1 --patch --dry-run --summary
cargo xtask adoption-regression
cargo xtask adoption-regression --format json
cargo xtask claim-proof --all-stable
cargo xtask user-path-smoke
cargo xtask check-no-panic-family
cargo xtask claim-report --check-public-claims
cargo xtask contract-packs --check
cargo +nightly xtask pr-lite
cargo xtask pr
git diff --check
```

The pre-tag proof PR should additionally run:

```bash
cargo xtask publish-preflight
cargo xtask publish-check
cargo xtask no-blob
cargo xtask badges --check
cargo xtask docs-sync --check
```
