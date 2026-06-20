# Scanner-Safe Placeholder Audit

Use this when downstream CI needs a scanner-safe placeholder bundle and a
reviewer packet that contains only metadata.

## Installed Bundle Path

```bash
uselesskey bundle --profile scanner-safe --out target/uselesskey-scanner-safe
uselesskey verify-bundle target/uselesskey-scanner-safe
uselesskey inspect-bundle target/uselesskey-scanner-safe
uselesskey audit-bundle \
  target/uselesskey-scanner-safe \
  --ci \
  --expect-profile scanner-safe \
  --policy strict \
  --out target/uselesskey-scanner-safe-audit
```

Upload only:

```text
target/uselesskey-scanner-safe-audit/bundle-audit.json
target/uselesskey-scanner-safe-audit/bundle-audit.md
```

## Reviewer Checks

- The manifest profile is `scanner-safe`.
- Audit status is `pass`.
- `scanner_safe` labels match the generated artifacts.
- `runtime_material` labels are explicit.
- Generated placeholder material stayed under `target/`.

## Boundary

This proves local scanner-safe placeholder generation and metadata-only audit
output. It does not prove scanner-policy bypass approval, production secret
handling, or release readiness.
