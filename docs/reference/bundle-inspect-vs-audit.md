# Bundle Inspect vs Audit

`inspect-bundle` and `audit-bundle` both read an installed CLI bundle, but they
serve different jobs.

## `inspect-bundle`

Use `inspect-bundle` when you want a quick terminal summary before debugging or
reviewing generated files:

```bash
uselesskey inspect-bundle --path target/uselesskey-webhook
```

It verifies the manifest, prints the profile, lists generated files, summarizes
scanner-safe and runtime-material posture, and points to the relevant proof or
check path. It does not write a durable receipt.

## `audit-bundle`

Use `audit-bundle` when you need a metadata-only reviewer packet or a downstream
CI gate:

```bash
uselesskey audit-bundle --path target/uselesskey-webhook --out target/uselesskey-webhook-audit
uselesskey audit-bundle --path target/uselesskey-webhook --ci
```

It writes `bundle-audit.json` and `bundle-audit.md` when `--out` is provided.
Those receipts contain bundle metadata, artifact classifications, stable failure
classes, checks, and boundaries. They do not copy raw fixture payloads.

Use summary mode when a terminal or CI log only needs the compact decision:

```bash
uselesskey audit-bundle --path target/uselesskey-webhook --summary
```

`--summary` is human output. Keep `--ci` for machine-readable failure handling.

## Boundary

`inspect-bundle` is for a human's immediate read. `audit-bundle` is for durable
reviewer and CI evidence.

Neither command proves repo public claims, release readiness, production
security, provider compatibility, scanner evasion, or downstream verifier
correctness. Use repo-local verification commands when you need public-claim or
release evidence.
