+++
id = "USELESSKEY-SPEC-0016"
kind = "spec"
title = "Negative fixture taxonomy"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-18"
milestone = "v0.10.0"
linked_proposal = "USELESSKEY-PROP-0001"
linked_adrs = [
  "USELESSKEY-ADR-0001",
  "USELESSKEY-ADR-0002",
  "USELESSKEY-ADR-0003",
]
linked_plan = "plans/real-workflow-closure/implementation-plan.md"
linked_specs = [
  "USELESSKEY-SPEC-0002",
  "USELESSKEY-SPEC-0003",
  "USELESSKEY-SPEC-0011",
  "USELESSKEY-SPEC-0014",
  "USELESSKEY-SPEC-0015",
]
support_tier_impact = []
policy_impact = [
  "policy/negative-fixtures.toml",
]
+++

# USELESSKEY-SPEC-0016: Negative Fixture Taxonomy

## Problem

`uselesskey` has deterministic fixture generation, installed bundle audit, and
real user workflow contracts. The next product gap is negative fixture
discipline.

Negative fixtures must not be a grab bag of broken-looking strings. They are a
user-facing contract:

```text
valid fixture:
  proves the happy path can be exercised deterministically

negative fixture:
  proves a realistic parser or verifier rejection path can be exercised
  deterministically, without overclaiming provider compatibility or production
  security
```

This spec defines the taxonomy used by task docs, bundle manifests, examples,
and implementation PRs.

## Behavior

A negative fixture is accepted only when it satisfies all of these properties:

- deterministic from the same seed, label, spec, variant, and derivation
  version;
- scanner-safe unless the fixture is explicitly materialized as runtime test
  material under a selected output directory;
- tied to a realistic downstream parser, verifier, or policy failure;
- named by a stable failure class;
- tested for the intended shape or rejection signal;
- documented with the failure mode and "does not prove" boundary.

Negative fixture names should be specific enough for users and receipts:

```text
negative-missing-kid
negative-duplicate-kid
negative-wrong-kty
negative-unsupported-alg
negative-malformed-base64url
negative-expired
negative-not-yet-valid
negative-bad-audience
negative-stale-timestamp
negative-malformed-signature
```

Implementation PRs may add only a subset of this taxonomy. They must not imply
that unimplemented taxonomy classes already exist.

## Implementation State

The taxonomy is broader than the currently implemented product surface. The
machine-readable implementation ledger is:

```text
policy/negative-fixtures.toml
```

The human status mirror is:

```text
docs/status/negative-fixture-matrix.md
```

Those files distinguish:

| Status | Meaning |
| --- | --- |
| `implemented` | The class has an owner crate or CLI bundle surface, tests, and docs/status mapping. |
| `accepted_planned` | The taxonomy class is accepted, but implementation is intentionally deferred. |
| `deferred` | The class is useful but not part of the current product lane or support surface. |
| `out_of_scope` | The class would overclaim provider compatibility, production security, or scanner-evasion behavior. |

Implementation PRs must update the ledger and status mirror when they add,
defer, rename, or expose a negative class. Docs may describe the broad taxonomy,
but user-facing how-tos, bundle receipts, and examples must only present
`implemented` classes as available product behavior.

## Family Taxonomy

### JWK

JWK negatives cover single-key parser and verifier setup failures.

| Class | Stable ID | Shape | Expected downstream failure |
| --- | --- | --- | --- |
| missing `kid` | `jwk_missing_kid` | public key object with no `kid` member | key selection cannot identify the key |
| wrong `kty` | `jwk_wrong_kty` | otherwise plausible key with mismatched `kty` | verifier rejects key type |
| unsupported `alg` | `jwk_unsupported_alg` | public key with unsupported or disallowed `alg` | verifier policy rejects algorithm |
| malformed base64url | `jwk_malformed_base64url` | key parameter with invalid base64url | parser rejects parameter encoding |
| mismatched parameters | `jwk_mismatched_parameters` | fields from incompatible keys or curves | verifier rejects inconsistent key shape |

Scanner-safety posture:

```text
JWK negatives should be public-key or malformed-shape values by default.
Private JWK material and HMAC `k` values are runtime material unless explicitly
documented otherwise.
```

Minimum proof for a JWK negative:

```text
- deterministic stable value or stable structure
- intended field mutation is present
- no private key material is introduced by accident
- parser/verifier failure is documented or tested
```

### JWKS

JWKS negatives cover set-level key discovery failures.

| Class | Stable ID | Shape | Expected downstream failure |
| --- | --- | --- | --- |
| empty keys | `jwks_empty_keys` | `{ "keys": [] }` | no usable verification key |
| missing `kid` | `jwks_missing_kid` | key-set member without `kid` | key selection cannot identify the key |
| duplicate `kid` | `jwks_duplicate_kid` | two distinct public keys with the same `kid` | ambiguous key selection |
| duplicate key | `jwks_duplicate_key` | repeated equivalent public key entry | policy rejects duplicate material |
| mixed valid/invalid set | `jwks_mixed_valid_invalid` | valid key plus malformed or policy-invalid key | parser or policy surfaces bad set member |

Scanner-safety posture:

```text
JWKS negatives should contain public or malformed public key shapes only. They
must not include private JWK members, HMAC `k`, JWTs, tokens, or webhook bodies.
```

Minimum proof for a JWKS negative:

```text
- `keys` shape is preserved unless the class explicitly targets empty sets
- duplicate classes prove duplicate identity without byte-for-byte ambiguity
- mixed sets identify which member is expected to fail
- manifests and docs use stable failure-class names
```

### JWT / Token

JWT and token negatives cover parser, header, claim, and policy failures.

| Class | Stable ID | Shape | Expected downstream failure |
| --- | --- | --- | --- |
| bad segment count | `jwt_bad_segment_count` | fewer or more than three JWT segments | parser rejects token shape |
| malformed base64url | `jwt_malformed_base64url` | invalid base64url in header, payload, or signature | parser rejects segment encoding |
| invalid header shape | `jwt_invalid_header_shape` | decodable JWT header that is not a header object | parser or validator rejects header type |
| missing `alg` | `jwt_missing_alg` | JWT header without `alg` | verifier policy cannot select an algorithm |
| `alg: none` | `jwt_alg_none` | JWT header with `alg` set to `none` | verifier policy rejects unsigned algorithm |
| missing `kid` | `jwt_missing_kid` | signed-looking token with no header `kid` | key selection cannot identify verification key |
| mismatched `kid` | `jwt_mismatched_kid` | header and payload carry different key IDs | key-selection or policy check rejects inconsistent identity |
| expired claims | `jwt_expired` | `exp` before validation time | claim validation rejects token |
| not-yet-valid claims | `jwt_not_yet_valid` | future `nbf` | claim validation rejects token |
| bad audience | `jwt_bad_audience` | `aud` does not match expected audience | claim validation rejects token |
| bad issuer | `jwt_bad_issuer` | `iss` does not match expected issuer | claim validation rejects token |
| malformed bearer | `token_malformed_bearer` | bearer-shaped value with invalid base64url/token syntax | parser rejects bearer token format |
| near-miss bearer/API token | `token_near_miss` | scanner-safe token-shaped string that fails prefix or format policy | parser or application policy rejects token |

Scanner-safety posture:

```text
JWT/token negatives should be scanner-safe malformed values unless explicitly
materialized for a runtime test. Token-shaped strings must not be real bearer
tokens, OAuth credentials, API keys, or signed production tokens.
```

Minimum proof for a JWT/token negative:

```text
- the intended header, segment, or claim mutation is present
- the positive token cache identity is not perturbed by negative variants
- Debug output and docs do not print secret-bearing values
- adapter tests cover public verifier behavior when an adapter owns the failure
  branch
```

### Webhook

Webhook negatives cover deterministic HMAC verifier branches for fixture
requests.

| Class | Stable ID | Shape | Expected downstream failure |
| --- | --- | --- | --- |
| near-miss signature | `webhook_near_miss_signature` | valid request shape with one signature byte or encoding perturbed | signature verification rejects |
| tampered body | `webhook_tampered_body` | signed headers with modified body | canonical signature check rejects |
| wrong secret | `webhook_wrong_secret` | signature produced with another deterministic fixture secret | signature verification rejects |
| stale timestamp | `webhook_stale_timestamp` | timestamp outside configured tolerance | replay-window policy rejects |
| missing signature | `webhook_missing_signature` | no provider-shaped signature header | verifier rejects missing credential |
| malformed signature | `webhook_malformed_signature` | provider-shaped header with invalid signature encoding | parser or verifier rejects |
| malformed canonical payload | `webhook_malformed_canonical_payload` | request fields that cannot form expected canonical input | canonicalization rejects |

Scanner-safety posture:

```text
Webhook negatives are runtime request fixtures. They may contain deterministic
fake signing material and request bodies under a selected output directory, but
reviewer/audit packets must remain metadata-only.
```

Minimum proof for a webhook negative:

```text
- request path and rejection class are recorded
- provider-shaped headers remain bounded to deterministic fixture behavior
- docs say this does not prove provider compatibility, replay protection
  completeness, transport security, or production secret management
```

### X.509 / TLS

X.509 and TLS negatives cover certificate chain and verifier-policy failures.
The TLS contract pack already includes a strong baseline; this taxonomy keeps
the failure vocabulary task-first.

| Class | Stable ID | Shape | Expected downstream failure |
| --- | --- | --- | --- |
| expired leaf | `x509_expired_leaf` | leaf certificate outside validity window | verifier rejects expiration |
| not-yet-valid leaf | `x509_not_yet_valid_leaf` | leaf certificate before validity window | verifier rejects not-before |
| wrong hostname | `x509_wrong_hostname` | certificate SAN/CN does not match expected host | hostname validation rejects |
| untrusted root | `x509_untrusted_root` | chain signed by a root outside trust store | path validation rejects |
| revoked leaf | `x509_revoked_leaf` | leaf appears in deterministic CRL fixture | revocation-aware test rejects |
| invalid key usage | `x509_invalid_key_usage` | certificate missing required usage bits | verifier policy rejects usage |

Scanner-safety posture:

```text
Public certificates are usually scanner-safe. Private keys and generated DER/PEM
key material are runtime material unless the manifest explicitly marks a public
artifact as scanner-safe.
```

Minimum proof for an X.509/TLS negative:

```text
- certificate validity or policy field matches the documented rejection class
- generated private key material does not enter audit/reviewer packets
- snapshot or verifier tests pin deterministic output shape where practical
```

## Cross-family Rules

Negative fixture implementations must preserve:

- existing positive fixture deterministic identity;
- existing cache identity for positive variants;
- stable failure-class names once published in docs, manifests, receipts, or
  JSON schemas;
- metadata-only audit and reviewer receipts;
- task-first docs that name the parser/verifier failure users should test.

Negative fixtures may share helper code only when the helper preserves a clear
failure-class boundary. A shared malformed-base64url helper is acceptable. A
generic "broken string" helper that hides whether the failure is header, claim,
key, or signature related is not acceptable.

## Stable Failure-Class Lifecycle

Stable failure classes are product contracts once they appear in public docs,
bundle manifests, audit JSON, receipts, examples, or public APIs such as
`stable_id()`.

Lifecycle rules:

- stable IDs are append-only once documented;
- removing or renaming a stable ID requires a compatibility note and migration
  path;
- display labels, descriptions, and Markdown headings may change, but stable IDs
  must not change silently;
- bundle manifests, negative-coverage receipts, audit JSON, and downstream CI
  docs must use stable IDs rather than prose labels for machine decisions;
- docs may group stable IDs, but must not alias two distinct behaviors to one
  stable ID;
- aliases in code must map to an existing stable ID only when they intentionally
  expose the same downstream failure class.

## Manifest and Receipt Mapping

When a negative fixture appears in a bundle, metadata should include:

```text
path
profile
artifact kind
failure class
scanner_safe
runtime_material
receipt links
does-not-prove boundary or boundary reference
```

Bundle audit may report the presence and classification of negative fixtures.
It must not copy raw generated payloads into the audit packet.

## Non-goals

This spec does not implement every taxonomy class.

This spec does not add a new contract pack, provider compatibility matrix,
production security claim, scanner-evasion claim, or release path.

This spec does not require negative fixtures to defeat any secret scanner.

This spec does not move repo-local claim-proof, verification-pack, or release
evidence into the installed CLI.

This spec does not require runtime material to be committed, embedded in docs,
or copied into reviewer packets.

## Required Evidence

Docs-only changes to this spec should run:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

Implementation PRs should run the smallest proof that covers the touched family.
Examples:

```bash
cargo test -p uselesskey-jwk --all-features
cargo test -p uselesskey-token --all-features
cargo test -p uselesskey-jsonwebtoken --all-features
cargo test -p uselesskey-cli --all-features bundle verify_bundle audit_bundle
cargo xtask no-blob
cargo +nightly xtask pr-lite
git diff --check
```

## Acceptance

This spec is accepted when:

- JWK, JWKS, JWT/token, webhook, and X.509/TLS negative fixture families have
  named classes;
- each class records a stable ID, fixture shape, expected downstream failure,
  and scanner-safety posture;
- the implementation ledger and status matrix distinguish implemented,
  accepted/planned, deferred, and out-of-scope classes;
- cross-family rules preserve deterministic identity, metadata-only receipts,
  and task-first docs;
- non-goals prevent provider compatibility, production security, scanner
  evasion, release, and raw-payload review claims.

This spec is implemented incrementally when:

- taxonomy-backed implementation PRs add tests for intended shape or rejection
  signal;
- bundle manifests and audit receipts expose stable failure classes where
  bundle profiles include negatives;
- task-first docs name the failure mode users are expected to test;
- public examples include at least one positive and one taxonomy-backed
  negative path.

## Test Mapping

Taxonomy proof maps to:

- JWK/JWKS tests for single-key and key-set negative shape;
- token and jsonwebtoken tests for token shape, header, claim, and validation
  failures;
- webhook profile tests for request path and rejection-class coverage;
- TLS/X.509 profile tests for certificate failure classes and evidence docs;
- `cargo xtask external-adoption-smoke --path .` when copyable examples or
  installed CLI paths change;
- `cargo xtask no-blob` whenever generated material or scanner-safe posture
  changes.

## Implementation Mapping

Taxonomy ownership:

- `crates/uselesskey-jwk` owns JWK and JWKS negative fixture models, builders,
  serialization shape, and set-level failure classes.
- `crates/uselesskey-token` owns scanner-safe token-shaped negative values and
  stable token negative variant names.
- `crates/uselesskey-jsonwebtoken` owns adapter-level JWT verifier rejection
  tests for header, algorithm, issuer, audience, expiration, and not-before
  behavior.
- `crates/uselesskey-webhook` owns deterministic HMAC webhook near-miss
  fixtures and provider-shaped request rejection classes.
- `crates/uselesskey-x509` owns X.509 certificate negative shapes and
  deterministic certificate failure fixtures.
- `crates/uselesskey-cli` owns bundle profile emission, manifest metadata,
  audit/inspect display, and receipt exposure for negative fixture classes.
- `docs/how-to/` and `examples/external/` own task-first user paths that explain
  which negative class a downstream test is expected to exercise.

Implementation PRs must update the owner that emits the fixture and any
downstream surface that exposes the failure class in docs, manifests, receipts,
or examples.

## CI Proof

Docs-only PR:

```bash
cargo xtask spec-check --strict
cargo xtask docs-sync --check
cargo xtask typos
git diff --check
```

JWK/JWKS implementation PR:

```bash
cargo test -p uselesskey-jwk --all-features
cargo test -p uselesskey --all-features
cargo +nightly xtask pr-lite
git diff --check
```

Token/JWT implementation PR:

```bash
cargo test -p uselesskey-token --all-features
cargo test -p uselesskey-jsonwebtoken --all-features
cargo test -p uselesskey --all-features
cargo +nightly xtask pr-lite
git diff --check
```

Bundle or receipt implementation PR:

```bash
cargo test -p uselesskey-cli --all-features bundle verify_bundle audit_bundle
cargo xtask external-adoption-smoke --path .
cargo xtask no-blob
cargo +nightly xtask pr-lite
git diff --check
```

## Metrics / Promotion Rule

This spec can move to implemented when:

- each family has at least one task-first doc or external example;
- JWK/JWKS and token taxonomy gaps from the real workflow closure lane are
  implemented or explicitly deferred with a reason;
- bundle receipts use stable failure-class names for profile negatives;
- no audit, verification, or reviewer packet copies generated secret-shaped
  payloads.
