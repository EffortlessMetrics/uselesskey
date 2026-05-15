# Contract Packs

Contract packs are deterministic fixture bundles with a documented verifier job,
negative cases, proof command, and explicit boundary.

Use this page when you already know the verifier surface you need and want the
copyable command first. For a broader task router, see
[`../how-to/start-here.md`](../how-to/start-here.md).

Run installed CLI commands as shown below:

```bash
cargo install uselesskey-cli --version 0.9.0
```

Inside this workspace, prefix CLI examples with `cargo run -p uselesskey-cli --`.

## Quick Index

| Profile | Use when you need | Generate | Proof |
| --- | --- | --- | --- |
| `scanner-safe` | scanner-safe baseline fixtures and export receipts | `uselesskey bundle --profile scanner-safe --out target/uselesskey-bundle` | `cargo xtask claim-proof --claim scanner-safe-fixtures` |
| `tls` | TLS chain and certificate rejection fixtures | `uselesskey bundle --profile tls --out target/uselesskey-tls` | `cargo xtask claim-proof --claim tls-contract-pack` |
| `oidc` | OIDC/JWKS validator fixtures and JWT-shaped negatives | `uselesskey bundle --profile oidc --out target/uselesskey-oidc` | `cargo xtask claim-report --claim oidc-jwks-contract-pack` |
| `webhook` | HMAC webhook signature positives and negatives | `uselesskey bundle --profile webhook --out target/uselesskey-webhook` | `cargo xtask claim-proof --claim webhook-contract-pack` |

Every generated bundle should stay under `target/` or another ignored build
directory. Commit docs and receipts only when the repo has an explicit tracked
receipt path. Do not commit generated PEM, DER, JWT, key, Kubernetes Secret, or
Vault payload files.

## Scanner-Safe Baseline

Generate:

```bash
uselesskey bundle --profile scanner-safe --out target/uselesskey-bundle
```

Verify:

```bash
uselesskey verify-bundle --path target/uselesskey-bundle
uselesskey inspect-bundle --path target/uselesskey-bundle
```

Prove:

```bash
cargo xtask claim-proof --claim scanner-safe-fixtures
```

What it proves:

- repository policy found no committed secret-shaped fixture blobs;
- the generated baseline bundle has receipts and an audit surface;
- badge drift checks still agree with scanner-safe policy.

What it does not prove:

- every derived encoded export is safe to commit;
- production key management;
- scanner evasion;
- cryptographic assurance.

Docs:

- [`../how-to/generate-scanner-safe-k8s-secret.md`](../how-to/generate-scanner-safe-k8s-secret.md)
- [`../how-to/downstream-fixture-policy.md`](../how-to/downstream-fixture-policy.md)

## TLS

Generate:

```bash
uselesskey bundle --profile tls --out target/uselesskey-tls
```

Verify:

```bash
uselesskey verify-bundle --path target/uselesskey-tls
uselesskey inspect-bundle --path target/uselesskey-tls
```

Prove:

```bash
cargo xtask claim-proof --claim tls-contract-pack
cargo xtask bundle-proof --profile tls --out target/release-evidence/tls
```

What it proves:

- documented TLS fixture files are generated;
- valid chain material exists;
- expired, not-yet-valid, wrong-hostname, and untrusted-root negatives exist;
- receipts and evidence docs are present.

What it does not prove:

- production PKI;
- revocation, OCSP, certificate transparency, or mTLS;
- browser trust-store behavior;
- production CA custody;
- downstream verifier correctness.

Docs:

- [`../how-to/test-tls-chain-validation.md`](../how-to/test-tls-chain-validation.md)

## OIDC/JWKS

Generate:

```bash
uselesskey bundle --profile oidc --out target/uselesskey-oidc
```

Verify:

```bash
uselesskey verify-bundle --path target/uselesskey-oidc
uselesskey inspect-bundle --path target/uselesskey-oidc
```

Prove:

```bash
cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc
cargo xtask claim-report --claim oidc-jwks-contract-pack
```

What it proves:

- deterministic JWKS and JWT-shaped fixtures are generated;
- documented negative inputs exist for validator rejection paths;
- receipts and evidence docs are present.

What it does not prove:

- production signing-key custody;
- full OpenID provider behavior;
- issuer policy;
- downstream validator correctness.

Docs:

- [`../how-to/test-oidc-jwks-validation.md`](../how-to/test-oidc-jwks-validation.md)
- [`../how-to/test-jwt-negative-validation.md`](../how-to/test-jwt-negative-validation.md)

## Webhook

Generate:

```bash
uselesskey bundle --profile webhook --out target/uselesskey-webhook
```

Verify:

```bash
uselesskey verify-bundle --path target/uselesskey-webhook
uselesskey inspect-bundle --path target/uselesskey-webhook
```

Prove:

```bash
cargo xtask claim-proof --claim webhook-contract-pack
cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook
```

What it proves:

- valid HMAC webhook signature fixtures are generated;
- tampered-body, wrong-secret, stale-timestamp, missing-signature, and
  malformed-signature negatives exist;
- receipts and evidence docs are present.

What it does not prove:

- provider compatibility;
- production secret management;
- replay protection completeness;
- delivery retries;
- transport security;
- downstream verifier correctness.

Docs:

- [`../how-to/test-webhook-signature-validation.md`](../how-to/test-webhook-signature-validation.md)

## Reviewer Bundle

When a reviewer needs all public-claim receipts in one metadata-only directory:

```bash
cargo xtask verification-pack --out target/uselesskey-verification
```

For one claim:

```bash
cargo xtask verification-pack --out target/uselesskey-verification --claim webhook-contract-pack
```

The verification pack contains metadata and receipts only. It must not copy raw
generated fixture payloads into the review bundle.
