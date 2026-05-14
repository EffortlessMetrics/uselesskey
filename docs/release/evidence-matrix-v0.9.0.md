# v0.9.0 Release Evidence Matrix

This matrix maps the v0.9.0 release story to the proof commands that must
carry it.

v0.9.0 is the release where public claims become command-backed, reviewable,
and useful to adopters:

```text
README badge / public claim
  -> verification docs
    -> PUBLIC_CLAIMS
      -> claim-report
        -> claim-proof
          -> verification-pack
            -> release evidence
```

This document is the release-candidate proof map. It names the required proof,
the receipt surface, and the current v0.9.0 candidate status.

## Candidate Proof Status

Candidate proof completed on 2026-05-14. Generated receipts stayed under
`target/` and are not committed.

Commands that passed:

```bash
cargo xtask release-evidence --version 0.9.0 --dry-run --summary
cargo xtask claim-proof --all-stable
cargo xtask verification-pack --out target/uselesskey-verification
cargo xtask bundle-proof --profile tls --out target/release-evidence/tls
cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc
cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook
cargo xtask pr-lite
cargo xtask pr
cargo xtask spec-check --strict
cargo xtask claim-report --check-public-claims
cargo xtask contract-packs --check
git diff --check
```

## Required Release Gates

| Gate | Command or artifact | Release claim covered | v0.9.0 candidate status |
| --- | --- | --- | --- |
| Source-of-truth proof | `cargo xtask spec-check --strict` | Specs, plans, active goals, and claim ledgers are parseable and linked. | Passed in candidate proof. |
| Public claim drift check | `cargo xtask claim-report --check-public-claims` | Public claim index matches `policy/claim-ledger.toml`. | Passed in candidate proof. |
| Contract-pack registry | `cargo xtask contract-packs --check` | Stable contract packs map to specs, claims, proof commands, and how-to docs. | Passed in candidate proof. |
| Stable claim proof | `cargo xtask claim-proof --all-stable` | Stable public claims have whitelisted proof handlers. | Passed in candidate proof. |
| Verification pack | `cargo xtask verification-pack --out target/uselesskey-verification` | Metadata-only review bundle can be generated. | Passed in candidate proof. |
| Badge endpoint drift | `cargo xtask badges --check` | `ripr+` and scanner-safe public Shields endpoints are generated and current. | Passed in candidate proof through stable claim proof; repeat before tagging. |
| PR-lite local evidence | `cargo xtask pr-lite` | Local contributor evidence approximates hosted PR checks and records routing. | Passed in candidate proof. |
| Full PR gate | `cargo xtask pr` | Fast PR evidence, docs, examples, public-surface, and receipts pass. | Passed in candidate proof. |
| No-panic family | `cargo xtask check-no-panic-family` | Stage A.5 new-debt posture remains clean. | Required before tagging. |
| Publish preflight | `cargo xtask publish-preflight` | Metadata and package preflight are ready. | Passed in candidate proof through stable claim proof; repeat before tagging. |
| Publish dry run | `cargo xtask publish-check` | Publishable crates dry-run in dependency order. | Passed in candidate proof through stable claim proof; repeat before tagging. |
| Secret-shaped blob gate | `cargo xtask no-blob` | Generated fixture material has not introduced committed secret-shaped blobs. | Passed in candidate proof; repeat before tagging. |
| Minor release evidence | `cargo xtask release-evidence --version 0.9.0 --dry-run --summary` | Full minor-release proof lane carries stable public claims. | Passed in candidate proof. |
| Post-release crates.io smoke | `cargo xtask cratesio-smoke --version 0.9.0` | External registry install view works after publish. | Post-release audit only. |
| docs.rs state | `docs/release/post-release-audit.md` | docs.rs is complete, queued, failed, or not found; queued is not a republish reason. | Post-release audit only. |

## Public Claim Matrix

| Public claim | Surfaces | Required evidence | Artifact or command | v0.9.0 status |
| --- | --- | --- | --- | --- |
| `ripr+` evidence endpoint | README badge, `badges/ripr-plus.json`, verification docs | Repo-scoped generated badge endpoint and claim ledger coverage | `cargo xtask badges --check`; `cargo xtask claim-report --claim ripr-plus-evidence-endpoint` | Candidate proof passed. |
| Scanner-safe fixtures | README badge, `badges/scanner-safe.json`, `docs/status/PUBLIC_CLAIMS.md` | Scanner-safe reference, no-blob gate, generated badge drift check | `cargo xtask claim-proof --claim scanner-safe-fixtures` | Candidate proof passed. |
| TLS contract pack | `uselesskey bundle --profile tls`, TLS how-to, contract-pack registry | Bundle proof and contract-pack registry row | `cargo xtask bundle-proof --profile tls --out target/release-evidence/tls`; `cargo xtask claim-proof --claim tls-contract-pack` | Candidate proof passed. |
| OIDC/JWKS contract pack | OIDC/JWKS docs and contract-pack registry | Bundle proof and contract-pack registry row | `cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc`; `cargo xtask claim-proof --claim oidc-jwks-contract-pack` | Candidate proof passed. |
| Webhook contract pack | `uselesskey bundle --profile webhook`, webhook how-to, contract-pack registry | Bundle proof, claim-proof handler, verification-pack inclusion | `cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook`; `cargo xtask claim-proof --claim webhook-contract-pack` | New v0.9.0 product claim; candidate proof passed. |
| Public crate-surface stability | README, docs metadata, support matrix, publish plan | Public-surface and publish preflight checks | `cargo xtask public-surface`; `cargo xtask publish-preflight`; `cargo xtask publish-check` | Candidate proof passed through stable claim proof; repeat before tagging. |
| External crates.io install smoke | Post-release audit, release evidence | External install against published registry version | `cargo xtask cratesio-smoke --version 0.9.0` | Post-release only. |
| PR review evidence | GitHub Actions summaries, PR-lite receipts, RIPR artifacts | Diff-scoped PR evidence remains advisory and separate from README badges | `cargo xtask pr-lite`; `cargo xtask pr` | Candidate proof passed. |

## Contract-Pack Proof

The v0.9.0 minor release proof must include the stable contract packs:

```bash
cargo xtask bundle-proof --profile tls --out target/release-evidence/tls
cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc
cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook
cargo xtask contract-packs --check
```

The webhook pack is the new product proof for v0.9.0. TLS remains the reference
contract pack, and OIDC/JWKS remains a stable authentication verifier surface.

## Verification-Pack Proof

The metadata-only review bundle must be buildable before release:

```bash
cargo xtask verification-pack --out target/uselesskey-verification
cargo xtask verification-pack --out target/uselesskey-verification --claim webhook-contract-pack
```

The verification pack contains receipts and metadata. It must not copy generated
secret-shaped fixture payloads into a shareable review bundle.

## Claim Boundaries

`ripr+` is a repo-scoped static evidence and test-efficiency counter. It is not
coverage, mutation adequacy, runtime correctness, or release approval.

Scanner-safe fixtures mean repository automation found no committed
secret-shaped fixture blobs under the configured fixture policy. This does not
mean every derived encoded export is safe to commit.

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
cargo xtask release-evidence --version 0.9.0 --dry-run --summary
cargo xtask claim-proof --all-stable
cargo xtask verification-pack --out target/uselesskey-verification
cargo xtask bundle-proof --profile tls --out target/release-evidence/tls
cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc
cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook
cargo xtask pr-lite
cargo xtask pr
git diff --check
```

The pre-tag proof PR should additionally run:

```bash
cargo xtask publish-preflight
cargo xtask publish-check
cargo xtask no-blob
cargo xtask check-no-panic-family
cargo xtask badges --check
cargo xtask docs-sync --check
```
