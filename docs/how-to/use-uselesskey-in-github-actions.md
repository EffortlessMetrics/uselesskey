# Use uselesskey in GitHub Actions

Use these recipes when a downstream repository wants deterministic fixture
bundles plus metadata-only audit receipts in GitHub Actions.

The installed CLI path is the product surface here. Repo-local `cargo xtask`
proof remains for maintainers and public-claim reviewers with a repo checkout.

## Webhook Fixtures

This workflow generates a webhook contract-pack bundle, verifies it, and fails
CI if the installed bundle audit reports a stable failure class.

```yaml
name: uselesskey webhook fixtures

on:
  pull_request:
  push:
    branches: [main]

jobs:
  webhook-fixtures:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - uses: dtolnay/rust-toolchain@stable

      - name: Install uselesskey CLI
        run: cargo install uselesskey-cli --version 0.9.1 --locked

      - name: Generate webhook fixtures
        run: uselesskey bundle --profile webhook --out target/uselesskey-webhook

      - name: Verify webhook bundle
        run: uselesskey verify-bundle --path target/uselesskey-webhook

      - name: Audit webhook bundle
        run: |
          uselesskey audit-bundle \
            --path target/uselesskey-webhook \
            --out target/uselesskey-webhook-audit \
            --ci
```

`--ci` emits machine-readable audit JSON on stdout and exits non-zero when the
bundle fails a stable audit class such as `missing_manifest`, `path_escape`,
`missing_artifact`, `scanner_safe_mismatch`, or `runtime_material_mismatch`.

## TLS and OIDC Fixtures

Use separate output paths for each profile so audit receipts stay attached to
one local bundle.

```yaml
name: uselesskey verifier fixtures

on:
  pull_request:

jobs:
  verifier-fixtures:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - uses: dtolnay/rust-toolchain@stable

      - name: Install uselesskey CLI
        run: cargo install uselesskey-cli --version 0.9.1 --locked

      - name: Generate TLS fixtures
        run: uselesskey bundle --profile tls --out target/uselesskey-tls

      - name: Verify TLS bundle
        run: uselesskey verify-bundle --path target/uselesskey-tls

      - name: Audit TLS bundle
        run: |
          uselesskey audit-bundle \
            --path target/uselesskey-tls \
            --out target/uselesskey-tls-audit \
            --ci

      - name: Generate OIDC fixtures
        run: uselesskey bundle --profile oidc --out target/uselesskey-oidc

      - name: Verify OIDC bundle
        run: uselesskey verify-bundle --path target/uselesskey-oidc

      - name: Audit OIDC bundle
        run: |
          uselesskey audit-bundle \
            --path target/uselesskey-oidc \
            --out target/uselesskey-oidc-audit \
            --ci
```

## Upload Audit Receipts

Upload only metadata-only audit receipts unless your downstream policy
explicitly asks for raw fixture payloads. Keep generated bundles under
`target/`.

```yaml
      - name: Upload uselesskey audit receipts
        uses: actions/upload-artifact@v7
        if: always()
        with:
          name: uselesskey-audit-receipts
          path: |
            target/uselesskey-webhook-audit/bundle-audit.json
            target/uselesskey-webhook-audit/bundle-audit.md
            target/uselesskey-tls-audit/bundle-audit.json
            target/uselesskey-tls-audit/bundle-audit.md
            target/uselesskey-oidc-audit/bundle-audit.json
            target/uselesskey-oidc-audit/bundle-audit.md
          if-no-files-found: ignore
```

## What This Proves

These recipes prove local generated bundle consistency in the downstream CI
job:

- the bundle manifest parses;
- listed artifacts and receipts exist;
- files stay under the bundle path;
- scanner-safe and runtime-material metadata match the bundle receipts;
- profile-specific bundle validation passes.

## What This Does Not Prove

These recipes do not prove:

- production security;
- production key management;
- provider compatibility;
- scanner evasion;
- repo public claims;
- release readiness;
- downstream verifier correctness.

Use repo-local proof only when a reviewer needs public-claim evidence:

```bash
cargo xtask verification-pack --out target/uselesskey-verification
```

