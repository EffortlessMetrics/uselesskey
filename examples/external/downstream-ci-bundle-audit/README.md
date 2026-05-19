# Downstream CI Bundle Audit

Use this clean-project example when a downstream repository wants to generate a
fixture bundle in CI, verify it, and upload metadata-only audit receipts.

The installed CLI path is the product surface:

```bash
uselesskey bundle --profile webhook --out target/uselesskey-webhook
uselesskey verify-bundle --path target/uselesskey-webhook
uselesskey audit-bundle --path target/uselesskey-webhook --out target/uselesskey-webhook-audit --ci
```

The reviewable files are:

```text
target/uselesskey-webhook-audit/bundle-audit.json
target/uselesskey-webhook-audit/bundle-audit.md
```

Keep generated fixture payloads under `target/`. The audit receipts are
metadata-only and do not copy raw webhook request bodies, key material, tokens,
or secret-shaped payloads.

## GitHub Actions

The example workflow is stored as:

```text
.github/workflows/uselesskey-audit.yml.example
```

Rename it to `.github/workflows/uselesskey-audit.yml` in a downstream project if
you want GitHub Actions to run it.

## Boundary

This proves local generated bundle consistency in downstream CI. It does not
prove repo public claims, production security, provider compatibility,
permission to bypass scanner policy, release readiness, or downstream verifier
correctness.
