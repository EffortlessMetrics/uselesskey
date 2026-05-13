# Verification Badges

README badges are public, repo-scoped trust markers. They are not the full
evidence system.

The badge row is a front panel:

```text
README badge -> public claim -> proof command -> receipt -> boundary
```

Use [`docs/status/PUBLIC_CLAIMS.md`](../status/PUBLIC_CLAIMS.md) for the claim
index, `cargo xtask claim-report` for the generated Markdown/JSON report, and
`cargo xtask claim-proof --claim <claim-id>` for runnable claim receipts.

`uselesskey` uses generated Shields endpoint JSON for badges that represent
repo-owned proof:

```text
badges/ripr-plus.json
badges/scanner-safe.json
```

Regenerate:

```bash
cargo xtask badges
```

Check drift:

```bash
cargo xtask badges --check
```

## `ripr+`

`ripr+` is a repo-scoped static evidence and test-efficiency inbox-zero counter.
It is generated from repo-scope `ripr` evidence and the test-efficiency report.

It is not:

- coverage;
- runtime mutation proof;
- correctness proof;
- a PR-scoped review result.

Diff-scoped `ripr` artifacts such as `target/ripr/review/comments.json` belong
in PR summaries, annotations, and artifacts, not README badges.

## `scanner-safe fixtures`

The scanner-safe fixture badge means repository automation found no committed
secret-shaped fixture blobs under the configured fixture policy.

It is not:

- proof every generated export is safe to commit;
- production key management;
- scanner evasion;
- cryptographic assurance.

Generated fixture exports should normally stay under `target/` and be
regenerated in CI or release evidence.

## Endpoint Rules

Committed endpoint files under `badges/` are the public surface. Detailed
reports stay under `target/` or CI artifacts.

Endpoint JSON uses this minimal Shields shape:

```json
{
  "schemaVersion": 1,
  "label": "fixtures",
  "message": "scanner-safe",
  "color": "brightgreen"
}
```

If scanner-safe generation fails, `cargo xtask badges` may write a red debug
endpoint under `target/xtask/badges/`, but it must fail before overwriting the
committed public endpoint.

## Release Receipts

Badge endpoint JSON is intentionally small. Release evidence carries the wider
claim and contract-pack receipts:

```text
target/release-evidence/claims/public-claims.json
target/release-evidence/claims/public-claims.md
target/release-evidence/contract-packs/contract-packs.json
target/release-evidence/contract-packs/contract-packs.md
```

Patch release evidence includes the public claim report. Minor release evidence
also includes the contract-pack registry because contract packs are public
fixture-platform promises. Minor release evidence also carries a metadata-only
verification pack under:

```text
target/release-evidence/verification-pack/
```

## Future Badges

Future endpoints must be generated or absent. Candidate badges such as
`feature-matrix`, `cratesio-smoke`, or `supply-chain` need stable proof
commands, claim-ledger entries, and documented boundaries before they belong in
the README masthead.
