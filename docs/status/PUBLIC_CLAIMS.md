# Public Claims

This page summarizes public `uselesskey` claims and points to the command-backed
ledger in [`policy/claim-ledger.toml`](../../policy/claim-ledger.toml).

The Markdown page is for readers. The TOML ledger is the parser target for
`cargo xtask spec-check` and the source for `cargo xtask claim-report`.

Generate the current claim report:

```bash
cargo xtask claim-report
```

Check this page against the ledger:

```bash
cargo xtask claim-report --check-public-claims
```

Run a proof receipt for one claim:

```bash
cargo xtask claim-proof --claim scanner-safe-fixtures
```

Collect reviewer-facing receipts without generated fixture payloads:

```bash
cargo xtask verification-pack --out target/uselesskey-verification
```

## Claim Statuses

| Status | Meaning |
| --- | --- |
| `stable` | User-facing claim that should be proven in normal PR, docs, or release evidence when touched. |
| `release-proof` | Claim whose primary proof is an external or shipped-state release lane. |
| `advisory` | Reviewer or agent evidence that informs work but does not make a user-facing guarantee by itself. |

## Current Claims

| Claim ID | Claim | Status | Proof commands | Boundary |
| --- | --- | --- | --- | --- |
| `scanner-safe-fixtures` | Scanner-safe fixtures | `stable` | `cargo xtask scanner-safe-reference --check`; `cargo xtask no-blob`; `cargo xtask badges --check` | Scanner-safe fixture material does not mean every encoded export is safe to commit. |
| `ripr-plus-evidence-endpoint` | `ripr+` evidence endpoint | `stable` | `cargo xtask badges --check`; `cargo xtask test-efficiency-report` | `ripr+` is repo-scoped static evidence, not coverage or correctness proof. |
| `tls-contract-pack` | TLS contract pack | `stable` | `cargo xtask bundle-proof --profile tls --out target/release-evidence/tls`; `cargo xtask no-blob` | TLS fixtures prove the documented pack paths and negatives, not mTLS, revocation, CT, browser trust stores, or production CA custody. |
| `oidc-jwks-contract-pack` | OIDC/JWKS contract pack | `stable` | `cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc`; `cargo xtask no-blob` | OIDC/JWKS fixtures prove key-set and token-shape contract paths, not production signing-key custody or full OpenID provider behavior. |
| `webhook-contract-pack` | Webhook contract pack | `stable` | `cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook`; `cargo xtask no-blob` | Webhook fixtures prove deterministic HMAC verifier paths and negative classes, not provider compatibility, production secret management, replay protection, transport security, or downstream verifier correctness. |
| `public-crate-surface-cleanup` | Public crate-surface cleanup | `stable` | `cargo xtask public-surface`; `cargo xtask publish-check`; `cargo xtask publish-preflight` | The supported public crate surface is the current published contract; removed internal shims are not promised as v0.8.0 crates. |
| `external-cratesio-install-smoke` | External crates.io install smoke | `release-proof` | `cargo xtask cratesio-smoke --version 0.8.0` | Crates.io smoke proves an external install path for a published version, not every downstream feature combination. |
| `generated-badge-endpoints` | Generated badge endpoints | `stable` | `cargo xtask badges`; `cargo xtask badges --check` | Badge JSON is a generated Shields endpoint receipt, not a hand-written slogan. |
| `ripr-pr-review-evidence` | `ripr` PR review evidence | `advisory` | `cargo xtask ripr-pr --check`; `cargo xtask ripr-review-comments --check` | PR evidence is diff-scoped and advisory; it is not the repo-scoped README `ripr+` badge. |

## Reader Rule

Public claims should answer four questions:

```text
what is promised?
what command proves it?
where is the generated artifact or receipt?
what is explicitly outside the boundary?
```

If a claim cannot answer those questions, it should stay out of the README
masthead and release headline until the proof path exists.

Use `cargo xtask claim-proof --claim <claim-id>` when a reviewer needs runnable
evidence for a supported claim. Use `cargo xtask verification-pack --out <dir>`
when they need claim reports, badge endpoints, contract-pack receipts, and
claim-proof receipts in one metadata-only bundle.
