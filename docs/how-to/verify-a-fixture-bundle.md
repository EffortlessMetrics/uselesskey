# Verify a Fixture Bundle

Use this when an installed CI job or reviewer needs to know what a generated
bundle contains without committing runtime material.

## Copy this

```bash
uselesskey bundle --profile oidc --out target/uselesskey-oidc
uselesskey verify-bundle target/uselesskey-oidc
uselesskey inspect-bundle target/uselesskey-oidc
uselesskey audit-bundle \
  target/uselesskey-oidc \
  --ci \
  --expect-profile oidc \
  --policy strict \
  --out target/uselesskey-oidc-audit
```

The older `--path target/uselesskey-oidc` form remains supported for scripts
that already use it.

Swap `oidc` for `scanner-safe`, `webhook`, or `tls` when that is the workflow
under test. Use `runtime` only for local experiments that need generated runtime
private or symmetric material; it is not a claim-backed contract pack. Keep the
output under `target/`.

## What It Proves

`verify-bundle` proves local bundle consistency:

- `manifest.json` is present and parseable;
- manifest paths point inside the bundle;
- listed artifacts and receipts exist;
- the bundle matches the selected installed profile shape.

`audit-bundle --ci --expect-profile <profile> --policy strict` emits
metadata-only reviewer evidence and fails CI on stable bundle drift:

- profile name;
- relative paths;
- artifact kinds;
- scanner-safe and runtime-material posture;
- stable negative failure classes where the profile exposes them;
- boundaries and local consistency status.

## What To Attach

Attach only these audit outputs:

```text
target/uselesskey-oidc-audit/bundle-audit.json
target/uselesskey-oidc-audit/bundle-audit.md
```

Do not attach generated PEM, DER, JWT, JWK, JWKS, HMAC secret, webhook request,
Kubernetes Secret, Vault payload, or certificate private-key files.

## Pick a Contract Pack

| Job | Profile | How-to |
| --- | --- | --- |
| OIDC/JWKS validation | `oidc` | [test-oidc-jwks-validation.md](test-oidc-jwks-validation.md) |
| JWT/token negative validation | `oidc` or Rust facade | [test-jwt-negative-validation.md](test-jwt-negative-validation.md) |
| Webhook signature validation | `webhook` | [test-webhook-signature-validation.md](test-webhook-signature-validation.md) |
| TLS chain validation | `tls` | [test-tls-chain-validation.md](test-tls-chain-validation.md) |
| Scanner-safe placeholder audit | `scanner-safe` | [generate-scanner-safe-k8s-secret.md](generate-scanner-safe-k8s-secret.md) |

## What This Does Not Prove

- It does not prove production security.
- It does not prove provider compatibility.
- It does not prove downstream verifier correctness.
- It does not prove release readiness or broader repo public claims by itself.
- It does not make generated runtime material safe to commit.

Repo public claims are proven from a checkout with:

```bash
cargo xtask verification-pack --out target/uselesskey-verification
```

`verification-pack` runs claim-proof for the included claims and copies the
receipts into the pack. Run `cargo xtask claim-proof --claim <id>` separately
only when a reviewer needs standalone claim-proof receipts.
