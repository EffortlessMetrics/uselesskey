# Downstream CI Recipes

Use these recipes when a downstream repository wants copyable CI wiring for
fixture bundles, verifier regression tests, and metadata-only audit receipts.

The installed CLI path is the product surface for bundle recipes:

```bash
uselesskey doctor --format json
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

Library regression recipes use the facade crate in a downstream test crate and
keep generated material in test process memory or under `target/`.

| Job | Recipe |
| --- | --- |
| GitHub Actions bundle + verify + inspect + audit | [github-actions-bundle-verify-audit.yml.example](github-actions-bundle-verify-audit.yml.example) |
| OIDC/JWKS verifier regression | [oidc-jwks-regression.md](oidc-jwks-regression.md) |
| JWT negative test regression | [jwt-negative-regression.md](jwt-negative-regression.md) |
| Webhook signature regression | [webhook-signature-regression.md](webhook-signature-regression.md) |
| TLS chain regression | [tls-chain-regression.md](tls-chain-regression.md) |
| Scanner-safe placeholder audit | [scanner-safe-placeholder-audit.md](scanner-safe-placeholder-audit.md) |

## What This Proves

When this repo's proof command passes:

```bash
cargo xtask external-adoption-smoke --path . --ci-recipes --format json
```

the recipe pack has been exercised from downstream-style workspaces. The proof
checks that the bundle recipes generate, verify, inspect, and audit scanner-safe,
OIDC, webhook, and TLS bundles under `target/`; that library regression recipes
compile and run against the checkout; and that audit outputs are metadata-only
reviewer receipts.

If the local workspace drive is small, set `CARGO_TARGET_DIR` before running the
repo proof. Generated fixture payloads and audit receipts still stay under
`target/external-adoption-smoke/`, while child Cargo build caches move under an
`external-adoption-smoke/` child of the target directory and are recorded in the
receipt:

```bash
CARGO_TARGET_DIR=/mnt/large/uselesskey-target \
  cargo xtask external-adoption-smoke --path . --ci-recipes --format json
```

## Reviewer Packet

Upload only metadata-only audit receipts:

```text
target/uselesskey-<profile>-audit/bundle-audit.json
target/uselesskey-<profile>-audit/bundle-audit.md
```

Review both receipts. The JSON receipt should report `status: "pass"`, the
expected `profile`, and passing `checks[]`. The Markdown receipt should report
`- Status: pass`, the expected `- Profile: <profile>`, a metadata-only
`Boundaries` section, and a production-security item under `Does Not Prove`.

Do not upload generated PEM, DER, JWT, JWK/JWKS, HMAC secret, webhook request,
Kubernetes Secret, Vault payload, or certificate private-key files unless the
downstream repository has a separate reviewed policy for those payloads.

## What This Does Not Prove

- It does not prove provider compatibility.
- It does not prove production security.
- It does not prove downstream verifier correctness.
- It does not prove release readiness.
- It does not give permission to bypass scanner policy.
