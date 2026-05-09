# Roadmap Follow-ups (v0.6.x)

This plan decomposes `roadmap.md` into milestone-aligned execution items.

## v0.6.0 lane-choice release

- [x] Roadmap reset for lane-choice positioning
- [x] `uselesskey-entropy` for deterministic high-entropy byte fixtures
- [x] Runtime fixture lane documented as the default scanner-safe path
- [x] Build-time materialization lane with manifest `materialize` / `verify`
- [x] Explicit RSA PKCS#8 materialization example
- [x] `cargo xtask economics` receipt
- [x] `cargo xtask audit-surface` receipt
- [x] v0.6.0 release prep

## v0.6.x stabilization

- [x] Refresh advisory-blocked dependency floors
- [x] Finish open PR queue disposition
- [x] Close superseded WebAuthn and PKCS#11 duplicate branches after keeper PRs land
- [x] Keep mutation-proof tests aligned with touched fixture identity and shape contracts
- [x] Review dependency bumps after code keeper branches are settled

## v0.6.1 follow-on negatives

- [x] JWK/JWKS negative wave 1
- [x] token-shape negative wave 1
- [x] docs/examples coverage for negative fixtures

## v0.6.1 benchmarks and governance

- [x] Criterion harness
- [x] Baseline performance report
- [x] Scheduled/manual perf workflow
- [x] CI threshold policy for benchmark trends
- [x] Release category notes + post-release audit
- [x] Public surface promise map

## v0.6.1 export bundles

- [x] `uselesskey bundle` command design
- [x] `uselesskey verify-bundle` deterministic manifest verifier
- [x] scanner-safe bundle profile with per-artifact lane metadata
- [x] deterministic bundle receipts under `receipts/materialization.json` and `receipts/audit-surface.json`
- [x] Kubernetes secret payload emitter
- [x] Vault payload emitter
- [x] Reference manifests for scanner-safe fixture bundles
- [x] Release-facing downstream bundle recipes

## Governance

- [x] release governance milestone and labels
- [x] roadmap link to this follow-up from `roadmap.md`
- [ ] one issue per checklist line before milestone exit
