# Audit Failure Classes

`uselesskey audit-bundle --ci` emits stable failure classes for downstream CI
branching. Use these IDs with `status` and `profile`; do not parse the
human-facing `detail` text as a stable contract.

The class set is schema-backed by
[`bundle-audit.schema.json`](../schemas/bundle-audit.schema.json) and appears in
`checks[].failure_class` in the audit receipt.

Committed metadata-only examples live in
[`examples/audit-receipts/`](../../examples/audit-receipts/). They are validated
with:

```bash
cargo xtask check-audit-receipts
```

The check writes a metadata-only report to
`target/source-of-truth/audit-receipts-check.json` and
`target/source-of-truth/audit-receipts-check.md`.

## Upload-Safe Fields

Audit failure receipts are metadata-only. The safe-to-upload decision fields are:

- `status`
- `profile`
- `manifest_version`
- `artifact_count`
- `receipt_count`
- `scanner_safe_count`
- `runtime_material_count`
- `files`
- `missing_files`
- `unexpected_files`
- `checks[].name`
- `checks[].status`
- `checks[].failure_class`
- `boundaries`
- `does_not_prove`

Path fields are safe relative paths. They must not be absolute paths,
Windows-drive paths, parent traversals, empty path components, trailing
separators, Windows root shapes, or strings containing control characters.

Audit receipts must not include PEM private keys, JWT values, HMAC secrets, JWK
private members, webhook request bodies, or raw generated secret-shaped
payloads.

## Stable Classes

| ID | Meaning | Emitted by | User action | Does not prove |
| --- | --- | --- | --- | --- |
| `missing_manifest` | `manifest.json` is absent from the bundle root. | Bundle audit before manifest parsing. | Pass the directory created by `uselesskey bundle --out`, or regenerate the bundle. | That any expected fixture material exists. |
| `invalid_manifest` | `manifest.json` could not be parsed or has an unsupported shape or version. | Manifest parser and manifest-shape checks. | Regenerate the bundle with the same CLI version, or inspect manifest corruption. | That the bundle came from a trusted producer. |
| `path_escape` | Manifest or receipt paths are unsafe or not contained by the bundle root. | Bundle path-safety validation. | Regenerate the bundle and inspect the manifest producer. | That downstream path handling is safe outside this bundle audit. |
| `missing_artifact` | A manifest-listed artifact file is missing from the bundle. | Bundle consistency check and strict CI policy. | Regenerate the bundle or restore the missing generated file. | That remaining artifacts are semantically valid verifier fixtures. |
| `unexpected_artifact` | A file exists in the bundle tree but is not listed by the manifest. | Bundle consistency check and strict CI policy. | Remove extra files or regenerate into an empty target directory. | That extra files are malicious or harmless. |
| `missing_receipt` | A required receipt entry is absent. | Receipt reconciliation during bundle audit. | Regenerate the bundle with a current CLI. | That artifact files themselves are invalid. |
| `invalid_receipt` | A required receipt exists but cannot be parsed or reconciled. | Receipt parsing and receipt-shape checks. | Regenerate the bundle; inspect persisted receipt corruption if needed. | That the referenced artifact payloads are unsafe by themselves. |
| `scanner_safe_mismatch` | Scanner-safe counts differ between manifest metadata and audit-surface receipt metadata. | Audit-surface receipt reconciliation. | Regenerate the bundle with the same CLI version. | Scanner behavior across all scanner vendors. |
| `runtime_material_mismatch` | Runtime-material counts differ between manifest metadata and audit-surface receipt metadata. | Audit-surface receipt reconciliation. | Regenerate the bundle with the same CLI version. | Runtime secrecy, key custody, or production material handling. |
| `profile_validation_failed` | Profile-specific validation or strict CI policy failed. | Expected-profile checks, strict policy checks, and profile validators. | Audit the matching profile, regenerate the bundle, or update `--expect-profile` for the CI job. | Provider compatibility, production security, or release readiness. |
| `unsupported_profile` | The bundle profile is not supported by this installed audit command. | Profile registry lookup during audit. | Upgrade `uselesskey` or audit with the CLI version that generated the bundle. | That the profile is unsupported by every future CLI version. |

## CI Branching

A downstream CI policy should branch on:

```text
status
profile
checks[].failure_class
```

It should not branch on:

```text
checks[].detail
boundaries
does_not_prove
```

Those fields are review text. They can change for clarity without changing the
failure-class contract.

## Boundary

Failure classes prove local bundle-audit outcomes only. They do not prove
production security, provider compatibility, downstream verifier correctness,
scanner evasion, or release readiness.
