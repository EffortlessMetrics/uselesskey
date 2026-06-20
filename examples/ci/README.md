# CI Recipe Consumer

This folder contains a language-neutral consumer example for `bundle-audit.json`.

`consume-bundle-audit.sh` reads the machine contract and branches on stable fields
only:

- `profile`
- `status`
- `checks[].failure_class`

Use it when your CI system needs a portable gate that does not depend on
`uselesskey` internals.

```bash
./examples/ci/consume-bundle-audit.sh target/uselesskey-webhook-audit/bundle-audit.json
```

## Failure policy

The script defaults to failing on any known failure class:

```text
missing_manifest
invalid_manifest
path_escape
missing_artifact
unexpected_artifact
missing_receipt
invalid_receipt
scanner_safe_mismatch
runtime_material_mismatch
profile_validation_failed
unsupported_profile
```

Override the list with:

```bash
BUNDLE_AUDIT_DISALLOWED_CLASSES="unsupported_profile,path_escape" \
./examples/ci/consume-bundle-audit.sh target/uselesskey-webhook-audit/bundle-audit.json
```

Use this in CI with only contract-relevant artifacts:

- `target/uselesskey-<profile>-audit/bundle-audit.json`
- `target/uselesskey-<profile>-audit/bundle-audit.md`
