+++
id = "USELESSKEY-SPEC-0011"
kind = "spec"
title = "Webhook contract pack"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-14"
milestone = "v0.9.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_adrs = ["USELESSKEY-ADR-0001", "USELESSKEY-ADR-0002"]
linked_plan = "plans/webhook-contract-pack/implementation-plan.md"
support_tier_impact = ["docs/status/PUBLIC_CLAIMS.md"]
policy_impact = ["policy/claim-ledger.toml", "policy/contract-packs.toml"]
+++

# USELESSKEY-SPEC-0011: Webhook Contract Pack

## Problem

Webhook consumers need realistic HMAC-signed requests in tests, but real
provider secrets, copied headers, and recorded payloads are easy to mishandle.
Users need fixtures that exercise the verifier behavior they own without
committing production-shaped secrets or overclaiming provider compatibility.

`uselesskey-webhook` already exposes deterministic provider-shaped fixtures.
The missing product unit is a contract pack that turns that behavior into a
runnable, proof-backed workflow:

```text
generate webhook fixtures
  -> run verifier positives and negatives
    -> write receipts
      -> publish claim boundary
        -> carry release evidence
```

## Behavior

The webhook contract pack is a stable `bundle` profile named `webhook`.

The pack must materialize deterministic HMAC-SHA256 webhook verifier fixtures
under a user-selected output directory:

```bash
uselesskey bundle --profile webhook --out target/uselesskey-webhook-pack
```

The generated pack must include:

```text
manifest.json
requests/valid.json
requests/negative-tampered-body.json
requests/negative-wrong-secret.json
requests/negative-stale-timestamp.json
requests/negative-missing-signature.json
requests/negative-malformed-signature.json
receipts/materialization.json
receipts/audit-surface.json
receipts/bundle-verification.json
receipts/scanner-safety.json
receipts/negative-coverage.json
evidence/webhook-profile.md
```

Each request fixture must include:

| Field | Requirement |
| --- | --- |
| `method` | HTTP method used by the verifier test. |
| `path` | Request path used by the verifier test. |
| `timestamp` | Signed timestamp when the case has one. |
| `body` | Request body bytes as text or JSON-safe encoding. |
| `headers` | Header map presented to the verifier. |
| `expected_result` | `accept` or `reject`. |
| `rejection_class` | Stable class identifier. |

Stable rejection classes are:

```text
valid
tampered_body
wrong_secret
stale_timestamp
missing_signature
malformed_signature
```

The pack may use provider-shaped header conventions such as GitHub-style,
Stripe-style, or Slack-style HMAC signatures, but the public claim is generic
deterministic HMAC webhook verifier behavior. Provider-shaped fixtures are
examples for exercising common verifier branches; they are not a compatibility
matrix.

## Claim Boundary

The webhook contract pack proves deterministic HMAC webhook verifier behavior
for generated fixture requests.

It does not prove production webhook provider compatibility, secret rotation,
delivery retries, timestamp policy suitability, replay protection completeness,
transport security, production secret management, or downstream verifier
correctness.

Generated request packs are test artifacts. Users should keep generated
secret-shaped payloads under `target/` or another ignored build directory and
share receipts or verification packs instead of generated payload blobs.

## Non-goals

This spec does not add a provider-specific compatibility matrix.

This spec does not claim Stripe, GitHub, Slack, or any other provider contract
compatibility.

This spec does not define production webhook secret custody, secret rotation,
delivery retries, replay storage, TLS, mTLS, transport security, or endpoint
authorization behavior.

This spec does not require generated request payloads to be committed.

This spec does not add a README badge.

## Required Evidence

The primary proof command is:

```bash
cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook
```

The stable claim proof command is:

```bash
cargo xtask claim-proof --claim webhook-contract-pack
```

Docs-only changes to this spec should run:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Behavior changes should add:

```bash
cargo test -p uselesskey-webhook --all-features
cargo test -p uselesskey-cli --all-features webhook
cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook
cargo xtask no-blob
cargo xtask check-file-policy
cargo xtask pr-lite
cargo xtask pr
git diff --check
```

## Acceptance

This spec is accepted when:

- it defines `webhook` as the stable contract-pack profile name;
- it defines required fixture paths and request fields;
- it defines stable rejection classes;
- it defines the proof command and claim-proof command;
- it records the production/provider/security non-goals.

This spec is implemented when:

- `uselesskey bundle --profile webhook` writes the required pack shape;
- the valid request is accepted by the proof verifier;
- every negative request is rejected with the expected rejection class;
- bundle proof writes Markdown and JSON receipts;
- `webhook-contract-pack` appears in the claim ledger and contract-pack
  registry;
- `claim-proof --claim webhook-contract-pack` runs a whitelisted handler;
- verification-pack can include webhook claim receipts without copying generated
  payload blobs;
- minor release evidence carries the webhook proof.

## Acceptance Examples

### Valid Fixture

`requests/valid.json` must describe a request whose headers, timestamp, body,
and test signing secret verify under the pack verifier:

```json
{
  "method": "POST",
  "path": "/webhooks/uselesskey",
  "timestamp": 1700000000,
  "headers": {
    "Stripe-Signature": "t=1700000000,v1=<hex>"
  },
  "expected_result": "accept",
  "rejection_class": "valid"
}
```

The header shape above is provider-shaped. It is not a Stripe compatibility
claim.

### Negative Fixtures

`negative-tampered-body.json` must retain a signature for the original signed
body while presenting modified request bytes to the verifier. The verifier must
reject it with:

```text
tampered_body
```

`negative-wrong-secret.json` must present a request signed with an alternate
test secret while the verifier uses the expected test secret. The verifier must
reject it with:

```text
wrong_secret
```

`negative-stale-timestamp.json` must present a timestamp outside the configured
tolerance. The verifier must reject it with:

```text
stale_timestamp
```

`negative-missing-signature.json` must omit the signature-bearing header. The
verifier must reject it with:

```text
missing_signature
```

`negative-malformed-signature.json` must include a syntactically invalid or
non-hex signature value. The verifier must reject it with:

```text
malformed_signature
```

### Verification Pack

The reviewer-facing command:

```bash
cargo xtask verification-pack --out target/uselesskey-verification --claim webhook-contract-pack
```

must include metadata and receipts, not generated webhook payload blobs.

## Test Mapping

Webhook contract-pack tests should cover:

- CLI bundle profile parsing for `webhook`;
- generated `manifest.json` profile and file list;
- deterministic materialization from a fixed seed;
- valid request acceptance;
- each stable rejection class;
- receipt presence and shape;
- no committed generated payload blobs;
- claim-proof handler selection and receipt output;
- verification-pack exclusion of generated request payload blobs.

Existing crate behavior maps to:

- `crates/uselesskey-webhook` for provider-shaped HMAC fixture generation and
  near-miss behavior;
- `crates/uselesskey-cli` for `bundle --profile webhook`;
- `xtask` for bundle proof, claim proof, verification-pack, and release
  evidence.

## Implementation Mapping

Implementation ownership:

- `crates/uselesskey-webhook` owns deterministic HMAC webhook fixture behavior;
- `crates/uselesskey-cli` owns the `webhook` bundle profile and generated pack
  layout;
- `xtask` owns `bundle-proof --profile webhook`,
  `claim-proof --claim webhook-contract-pack`, and release-evidence wiring;
- `policy/claim-ledger.toml` owns the public claim mapping;
- `policy/contract-packs.toml` owns the stable pack registry row;
- `docs/how-to/test-webhook-signature-validation.md` owns the task-first user
  workflow;
- verification-pack receipts own reviewer-facing proof metadata.

## CI Proof

Docs-only policy/spec PR:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Implementation PRs:

```bash
cargo test -p uselesskey-webhook --all-features
cargo test -p uselesskey-cli --all-features webhook
cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook
cargo xtask claim-proof --claim webhook-contract-pack
cargo xtask verification-pack --out target/uselesskey-verification --claim webhook-contract-pack
cargo xtask pr-lite
cargo xtask pr
git diff --check
```

Release-evidence PR:

```bash
cargo xtask release-evidence --version 0.9.0 --dry-run --summary
cargo xtask release-evidence --version 0.8.1 --patch --dry-run --summary
```

## Metrics / Promotion Rule

The webhook contract pack can move to stable public-claim status when:

- the CLI profile exists;
- bundle proof passes;
- the claim ledger and contract-pack registry include `webhook-contract-pack`;
- claim-proof and verification-pack support the claim;
- the task-first how-to explains the proof and non-goals;
- minor release evidence carries the proof.

This spec can move to `implemented` when those surfaces are present and
`cargo xtask spec-check --strict` validates the linked artifacts.
