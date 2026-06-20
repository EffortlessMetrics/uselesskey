# v0.10.0 Post-Release Audit

Audit date: 2026-06-20 UTC.

## Summary

v0.10.0 is published and externally verifiable.

- GitHub release is visible at
  <https://github.com/EffortlessMetrics/uselesskey/releases/tag/v0.10.0>.
- Tag `v0.10.0` points at
  `5ea65e1cc6309042731cf4ec91cb39f00a91253a`.
- Source `main` also contains PR #866 at
  `53eba4e49f96597f703bc31ba627c0dc9a1a1445`; that merge commit is
  evidence-only and was not used as the package-hash authority.
- All intended publish crates are visible on crates.io at `0.10.0`.
- docs.rs reports `doc_status: true` for `uselesskey 0.10.0`.
- Published-version CLI and facade smokes passed from fresh Cargo state.

## Release Identity

| Item | State |
| --- | --- |
| Tag | `v0.10.0` |
| Tag SHA | `5ea65e1cc6309042731cf4ec91cb39f00a91253a` |
| GitHub release | <https://github.com/EffortlessMetrics/uselesskey/releases/tag/v0.10.0> |
| GitHub release published | `2026-06-20T07:53:53Z` |
| Release workflow | <https://github.com/EffortlessMetrics/uselesskey/actions/runs/27864843530> |
| Source evidence merge | #866 `release: record v0.10.0 candidate evidence` |

## Source Cutover Chain

The release moved from the swarm proof boundary into the source repository by
normal source PRs:

| PR | Merge commit | Purpose |
| --- | --- | --- |
| #862 | `ace29dd2ae0dc76069eaaa572a1ad67456423b87` | Imported the v0.10 adoption handoff from `uselesskey-swarm`. |
| #864 | `320032df0fad0361238babd253b092953b640a1d` | Prepared the v0.10.0 source candidate. |
| #865 | `5ea65e1cc6309042731cf4ec91cb39f00a91253a` | Proved packaged adoption; this is the published and tagged candidate SHA. |
| #866 | `53eba4e49f96597f703bc31ba627c0dc9a1a1445` | Recorded immutable candidate evidence on `main`; not used for package hashes. |

The release gate was executed from a clean detached worktree at
`5ea65e1cc6309042731cf4ec91cb39f00a91253a`.

## crates.io

The intended publish surface was checked through the crates.io API. Each crate
reported `max_version = 0.10.0` and a visible `0.10.0` version:

```text
uselesskey-jwk
uselesskey-core
uselesskey-entropy
uselesskey-rsa
uselesskey-ecdsa
uselesskey-ed25519
uselesskey-hmac
uselesskey-token
uselesskey-webhook
uselesskey-pkcs11-mock
uselesskey-webauthn
uselesskey-ssh
uselesskey-pgp
uselesskey-x509
uselesskey-test-server
uselesskey-axum
uselesskey-cli
uselesskey-jsonwebtoken
uselesskey-rustls
uselesskey-tonic
uselesskey-ring
uselesskey-rustcrypto
uselesskey-aws-lc-rs
uselesskey
```

Publication used the recorded dependency order. The first `cargo xtask publish`
attempt published the first six crates and then failed at `uselesskey-hmac`
because crates.io DNS lookup failed. After DNS recovered, the resume command
completed the remaining crates:

```bash
cargo xtask publish
cargo xtask publish --from uselesskey-hmac
```

The final publish state marked the first six crates as already visible and the
remaining eighteen as published by the resume.

## docs.rs

docs.rs accepted and built the facade docs for `uselesskey 0.10.0`.

Checked endpoints:

```text
https://docs.rs/crate/uselesskey/0.10.0
https://docs.rs/crate/uselesskey/0.10.0/status.json
```

The status endpoint returned:

```json
{"doc_status":true,"version":"0.10.0"}
```

## Post-Release Proof

These commands passed from the candidate release worktree after publication:

```bash
cargo xtask publish-preflight
cargo xtask publish-check
cargo xtask no-blob
cargo xtask doctor --format json
cargo xtask external-adoption-smoke --version 0.10.0 --ci-recipes --format json
cargo xtask external-adoption-smoke --version 0.10.0 --library-examples
cargo xtask cratesio-smoke --version 0.10.0
git diff --check
```

The published-version CI recipe smoke ran with isolated Cargo state and wrote a
passing JSON report with:

```text
generated_at = 2026-06-20T07:42:00.865979400+00:00
git_sha = 5ea65e1cc6309042731cf4ec91cb39f00a91253a
mode = version
source = 0.10.0
status = pass
```

The library examples smoke passed four clean-project example steps. The
crates.io smoke installed `uselesskey 0.10.0`, installed
`uselesskey-cli 0.10.0`, generated a scanner-safe bundle, verified it, and
inspected it from the published registry view.

## Workflow Notes

The tag-triggered Release workflow started after `v0.10.0` was pushed.

- Run: <https://github.com/EffortlessMetrics/uselesskey/actions/runs/27864843530>
- Event: tag push for `v0.10.0`
- Head SHA: `5ea65e1cc6309042731cf4ec91cb39f00a91253a`
- Status at audit drafting: `in_progress`

This audit records the explicit local release gate as the publish authority. If
the tag-triggered workflow later reports a concrete defect, handle that as a
post-publication corrective-release decision.

## Claim Boundaries

v0.10.0 remains a test-fixture release. It does not claim:

- production security;
- provider compatibility;
- scanner-policy approval;
- downstream verifier correctness;
- release authority in `uselesskey-swarm`.

## Follow-Up

No crates.io, docs.rs, published CLI smoke, facade smoke, no-blob, or package
preflight defect was found.

The release lane can be closed. The next product lane should start from a fresh
active goal instead of extending v0.10.0 release state.
