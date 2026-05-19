# Use the Downstream Policy Pack

Use this page when a downstream CI job should fail on meaningful bundle drift
and produce reviewer-ready, metadata-only evidence.

The policy pack is intentionally small. It gives installed CLI users named
presets and copyable commands; it is not a policy language, governance engine,
provider compatibility proof, production security proof, or scanner-policy
approval.

## Pick a Preset

| Preset | Use it when | Copy this |
| --- | --- | --- |
| `default` | you want local audit JSON without stricter CI expectations | `uselesskey audit-bundle --path target/uselesskey-webhook --ci` |
| `strict` | CI should fail on audit drift for one expected profile | `uselesskey audit-bundle --path target/uselesskey-webhook --ci --expect-profile webhook --policy strict` |
| `reviewer` | you need files to attach to a security or platform review | `uselesskey audit-bundle --path target/uselesskey-webhook --out target/uselesskey-webhook-audit` |

## Strict CI Gate

Generate, verify, inspect, and audit one profile per output directory:

```bash
cargo install uselesskey-cli --version 0.9.1 --locked
uselesskey bundle --profile webhook --out target/uselesskey-webhook
uselesskey verify-bundle --path target/uselesskey-webhook
uselesskey inspect-bundle --path target/uselesskey-webhook
uselesskey audit-bundle \
  --path target/uselesskey-webhook \
  --ci \
  --expect-profile webhook \
  --policy strict
```

The strict preset exits non-zero when the installed bundle audit reports a
stable failure class such as `missing_manifest`, `path_escape`,
`missing_artifact`, `unexpected_artifact`, `missing_receipt`,
`scanner_safe_mismatch`, `runtime_material_mismatch`,
`profile_validation_failed`, or `unsupported_profile`.

Use `--expect-profile <profile>` so a reused CI step cannot accidentally audit
the wrong bundle.

## Reviewer Packet

For a reviewer handoff, write metadata-only receipts:

```bash
uselesskey audit-bundle \
  --path target/uselesskey-webhook \
  --out target/uselesskey-webhook-audit
```

Attach:

```text
target/uselesskey-webhook-audit/bundle-audit.json
target/uselesskey-webhook-audit/bundle-audit.md
```

Do not attach generated PEM, DER, JWT, JWK/JWKS, webhook request,
Kubernetes Secret, Vault JSON, or other raw fixture payloads unless your
organization has a separate reviewed policy for those files.

## Reviewer Checklist

A reviewer should check:

- the CI job generated the intended profile;
- `audit-bundle --ci --expect-profile <profile> --policy strict` passed;
- `bundle-audit.json` and `bundle-audit.md` were uploaded as CI artifacts;
- generated fixture payloads stayed under `target/` or another ignored output
  directory;
- the JSON `profile` matches the job being reviewed;
- the JSON `status` is `pass`;
- every `checks[]` entry has `status: "pass"`;
- `scanner_safe` and `runtime_material` labels match the intended use of each
  artifact;
- the "does not prove" boundary is included in the review note.

If the audit fails, branch on `failure_class`, not the English diagnostic text.
The JSON schema and stable failure classes are documented in
[`../reference/bundle-audit-json.md`](../reference/bundle-audit-json.md).

## What This Proves

The downstream policy pack proves local bundle consistency for an installed CLI
bundle:

- the manifest parses;
- manifest-listed files stay under the bundle root;
- listed artifacts and receipts exist;
- unexpected files are reported;
- scanner-safe and runtime-material counts match the bundle receipts;
- the audited profile matches the CI job when `--expect-profile` is set.

## What This Does Not Prove

This does not prove:

- repo public claims;
- release readiness;
- production security or production key management;
- provider compatibility;
- permission to ignore scanner policy;
- downstream verifier correctness.

Use repo-local proof only when a reviewer needs public-claim evidence:

```bash
cargo xtask verification-pack --out target/uselesskey-verification
cargo xtask claim-proof --all-stable
```
