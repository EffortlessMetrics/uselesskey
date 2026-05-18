# Share an Installed Bundle Audit

Use this when you generated a bundle with the installed CLI and need a
metadata-only packet for a security or platform reviewer.

The installed audit path explains the local bundle. It is not repo public-claim
proof, release evidence, provider compatibility proof, or production security
assurance.

## Generate a Bundle

```bash
cargo install uselesskey-cli --version 0.9.1
uselesskey bundle --profile webhook --out target/uselesskey-webhook
uselesskey verify-bundle --path target/uselesskey-webhook
uselesskey inspect-bundle --path target/uselesskey-webhook
```

Keep generated payloads under `target/` or another ignored build directory.

## Audit the Bundle

```bash
uselesskey audit-bundle --path target/uselesskey-webhook --out target/uselesskey-webhook-audit
```

Attach these files:

```text
target/uselesskey-webhook-audit/bundle-audit.md
target/uselesskey-webhook-audit/bundle-audit.json
```

Do not attach generated request payloads, PEM/DER material, token files,
Kubernetes Secret YAML, Vault JSON, or other raw fixture payloads unless your
review process explicitly asks for them.

## JSON for CI

```bash
uselesskey audit-bundle --path target/uselesskey-webhook --format json
```

The JSON receipt reports:

- bundle profile and manifest version;
- artifact paths, kinds, formats, and scanner-safe labels;
- runtime-material counts;
- expected receipt files;
- missing or unexpected files;
- profile validation status;
- explicit boundaries.

## What This Proves

`audit-bundle` proves local bundle consistency:

- the manifest parses;
- generated files are contained by the bundle path;
- listed artifacts and receipts exist;
- the bundle verifies against deterministic generation;
- scanner-safe and runtime-material counts match the audit-surface receipt.

## What This Does Not Prove

`audit-bundle` does not prove:

- repo public claims;
- release readiness;
- provider compatibility;
- production key management or production security;
- scanner evasion;
- downstream verifier correctness.

For repo public-claim proof, use a repo checkout:

```bash
cargo xtask verification-pack --out target/uselesskey-verification
cargo xtask claim-proof --all-stable
```
