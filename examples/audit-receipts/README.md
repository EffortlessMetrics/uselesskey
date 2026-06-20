# Audit Receipt Examples

These committed examples show one metadata-only `bundle-audit.json` failure
receipt for each stable audit failure class in
[`docs/schemas/bundle-audit.schema.json`](../../docs/schemas/bundle-audit.schema.json).

They are safe to upload as CI artifacts because they contain only paths, counts,
failure classes, and review boundaries. They do not contain fixture payloads or
runtime material.

Validate the examples with:

```bash
cargo xtask check-audit-receipts
```

The command writes metadata-only review evidence to:

```text
target/source-of-truth/audit-receipts-check.json
target/source-of-truth/audit-receipts-check.md
```
