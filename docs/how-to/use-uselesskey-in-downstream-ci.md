# Use uselesskey in Downstream CI

Use this recipe when a downstream project wants deterministic fixtures plus a
metadata-only audit receipt during CI.

For GitHub Actions-specific workflow files, see
[use-uselesskey-in-github-actions.md](use-uselesskey-in-github-actions.md).

```yaml
steps:
  - run: cargo install uselesskey-cli --version 0.9.1
  - run: uselesskey bundle --profile webhook --out target/uselesskey-webhook
  - run: uselesskey verify-bundle --path target/uselesskey-webhook
  - run: uselesskey audit-bundle --path target/uselesskey-webhook --out target/uselesskey-webhook-audit --ci
```

The audit files are safe reviewer metadata:

```text
target/uselesskey-webhook-audit/bundle-audit.md
target/uselesskey-webhook-audit/bundle-audit.json
```

Keep generated fixture payloads under `target/`. Do not commit generated PEM,
DER, JWT, JWK/JWKS, webhook request, Kubernetes Secret, or Vault payload files
unless your project has a separate reviewed policy for those artifacts.

## JSON Gate

Use JSON mode when CI needs a machine-readable decision point:

```bash
uselesskey audit-bundle --path target/uselesskey-webhook --ci
```

Fail CI if the command exits non-zero. A non-zero exit means the local bundle
failed a manifest, containment, receipt, scanner-safe/runtime-material, or
profile validation check.

For compact human CI logs without changing the machine-readable `--ci` path,
run summary mode in a separate step:

```bash
uselesskey audit-bundle --path target/uselesskey-webhook --summary
```

## Boundaries

This downstream CI recipe proves local bundle consistency. It does not prove
provider compatibility, production security, repo public claims, scanner
evasion, or release readiness.

Use repo-local proof only when a reviewer asks for public-claim receipts:

```bash
cargo xtask verification-pack --out target/uselesskey-verification
```
