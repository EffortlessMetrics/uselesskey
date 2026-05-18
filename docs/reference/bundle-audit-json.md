# Bundle Audit JSON

`uselesskey audit-bundle --format json` emits a metadata-only bundle audit
receipt. `uselesskey audit-bundle --out <dir>` writes the same shape to
`<dir>/bundle-audit.json`.

The schema is published at
[`docs/schemas/bundle-audit.schema.json`](../schemas/bundle-audit.schema.json).

## What It Is For

Use this JSON in downstream CI when you need a stable machine-readable answer
to:

- which profile was generated;
- which files and receipts the bundle claims;
- which artifacts are scanner-safe;
- which artifacts are runtime material;
- which local consistency checks passed;
- which stable failure class applies if the audit fails.

The JSON receipt is for installed-user bundle audit. It is not repo public-claim
proof, release evidence, provider compatibility proof, production security
proof, or scanner-evasion proof.

## Stable Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `version` | integer | Bundle audit receipt schema version. Version `1` is the current schema. |
| `status` | string | Overall audit result. Current values are `pass` and `fail`. |
| `bundle_path` | string | Display path of the audited bundle. |
| `profile` | string | Bundle profile from `manifest.json`. |
| `manifest_version` | integer | Manifest schema version from `manifest.json`. |
| `manifest_path` | string | Path to the manifest relative to the bundle root. Currently `manifest.json`. |
| `artifact_count` | integer | Number of artifacts listed in the audit receipt. |
| `receipt_count` | integer | Number of receipts listed in the bundle manifest. |
| `scanner_safe_count` | integer | Number of artifacts classified as scanner-safe. |
| `runtime_material_count` | integer | Number of artifacts classified as runtime material. |
| `files` | string array | Bundle files relative to the audited bundle root. |
| `artifacts` | object array | Artifact metadata. Does not include payload contents. |
| `receipts` | object array | Receipt metadata. Does not include receipt payload contents. |
| `missing_files` | string array | Files expected from the manifest but not found. |
| `unexpected_files` | string array | Files found in the bundle tree but not expected from the manifest. |
| `checks` | object array | Local audit checks and their stable failure classes. |
| `boundaries` | string array | Human-readable statements for what audit does prove. |
| `does_not_prove` | string array | Human-readable statements for out-of-scope claims. |

## Artifact Objects

Each `artifacts[]` entry has:

| Field | Type | Meaning |
| --- | --- | --- |
| `path` | string | Artifact path relative to the audited bundle root. |
| `kind` | string | Artifact kind from the bundle manifest. |
| `format` | string | Artifact format from the bundle manifest. |
| `scanner_safe` | boolean | Whether manifest metadata classifies the artifact as scanner-safe. |
| `runtime_material` | boolean | Whether audit classifies the artifact as generated runtime material. |
| `description` | string | Human-facing artifact description from the manifest. |

Artifact objects intentionally omit PEM, DER, JWK, JWKS, JWT, token, HMAC key,
webhook body, certificate, and other raw fixture payload contents.

## Receipt Objects

Each `receipts[]` entry has:

| Field | Type | Meaning |
| --- | --- | --- |
| `path` | string | Receipt path relative to the audited bundle root. |
| `kind` | string | Receipt kind, such as `materialization` or `audit-surface`. |
| `profile` | string | Bundle profile associated with the receipt. |
| `description` | string | Human-facing receipt description. |

The audit receipt lists receipt metadata. It does not copy receipt payloads into
the JSON object.

## Check Objects

Each `checks[]` entry has:

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | string | Stable audit check name. |
| `status` | string | Check result, currently `pass` or `fail`. |
| `failure_class` | string | Stable class to use in CI branching and docs. |
| `detail` | string | Human-facing detail. Treat as diagnostic text, not a stable parser target. |

Downstream CI should branch on `status`, `profile`, and `failure_class`, not on
English prose in `detail`, `boundaries`, or `does_not_prove`.

## Failure Classes

The stable failure class set is:

| Failure class | Meaning |
| --- | --- |
| `missing_manifest` | `manifest.json` is missing. |
| `invalid_manifest` | `manifest.json` could not be parsed or did not match the expected shape. |
| `path_escape` | A manifest path is absolute or escapes the bundle root. |
| `missing_artifact` | A manifest-listed file is missing from the bundle. |
| `unexpected_artifact` | A file exists in the bundle tree but is not listed by the manifest. |
| `missing_receipt` | A required receipt entry is missing. |
| `invalid_receipt` | A required receipt exists but could not be parsed or reconciled. |
| `scanner_safe_mismatch` | Scanner-safe counts differ between manifest metadata and audit-surface receipt metadata. |
| `runtime_material_mismatch` | Runtime-material counts differ between manifest metadata and audit-surface receipt metadata. |
| `profile_validation_failed` | Profile-specific deterministic validation failed. |
| `unsupported_profile` | The bundle profile is not supported by installed bundle audit. |

## Stability Contract

For schema version `1`, downstream users can rely on the required field names,
basic types, and failure class strings documented here.

Fields may gain new values only when the command can do so without weakening the
metadata-only boundary. New schema versions must update the schema file and this
reference page.

Human-facing strings are useful for logs and reviews, but only field names,
types, booleans, counts, paths, `status`, and `failure_class` are intended for
machine decisions.

## Boundary

`audit-bundle` proves local bundle consistency and metadata classification for
the bundle being audited.

It does not prove:

- repo public claims;
- release readiness;
- production security;
- webhook, OIDC, TLS, or other provider compatibility;
- scanner evasion;
- downstream verifier correctness.
