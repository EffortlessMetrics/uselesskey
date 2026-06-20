# External Examples

These examples are shaped like downstream repositories. Use them when you want
copyable test, CI, and verifier wiring without learning the workspace internals
first.

## Copy First

For an installed CLI bundle path, start with the webhook profile:

```bash
cargo install uselesskey-cli --version 0.9.1 --locked
uselesskey doctor --format json
uselesskey bundle --profile webhook --out target/uselesskey-webhook
uselesskey verify-bundle target/uselesskey-webhook
uselesskey inspect-bundle target/uselesskey-webhook
uselesskey audit-bundle target/uselesskey-webhook --out target/uselesskey-webhook-audit --ci --expect-profile webhook --policy strict
```

For Rust tests, start with the facade crate:

```toml
[dev-dependencies]
uselesskey = { version = "0.9.1", default-features = false, features = ["rsa", "jwk", "token"] }
```

```bash
cargo test
```

For GitHub Actions, copy
`ci-recipes/github-actions-bundle-verify-audit.yml.example` into
`.github/workflows/` and keep the audit upload step limited to:

```text
target/uselesskey-webhook-audit/bundle-audit.json
target/uselesskey-webhook-audit/bundle-audit.md
```

## Pick A Job

| Job | Example | Proof path |
| --- | --- | --- |
| Bundle, verify, inspect, and audit in downstream CI | [downstream-ci-bundle-audit](downstream-ci-bundle-audit/) | `cargo xtask external-adoption-smoke --path .` |
| Copy GitHub Actions and regression recipes | [ci-recipes](ci-recipes/) | `cargo xtask external-adoption-smoke --path . --ci-recipes --format json` |
| Test ECDSA key parsing and policy paths | [ecdsa-fixture-validation](ecdsa-fixture-validation/) | `cargo xtask external-adoption-smoke --path . --library-examples` |
| Test Ed25519 key parsing and policy paths | [ed25519-fixture-validation](ed25519-fixture-validation/) | `cargo xtask external-adoption-smoke --path . --library-examples` |
| Test deterministic byte fixtures | [entropy-byte-fixtures](entropy-byte-fixtures/) | `cargo xtask external-adoption-smoke --path . --library-examples` |
| Test OIDC/JWKS validation | [oidc-jwks-validation](oidc-jwks-validation/) | `cargo xtask external-adoption-smoke --path . --library-examples` |
| Test OIDC/JWKS HTTP discovery and rotation | [oidc-test-server-validation](oidc-test-server-validation/) | `cargo xtask external-adoption-smoke --path . --library-examples` |
| Test HMAC signature validation | [hmac-signature-validation](hmac-signature-validation/) | `cargo xtask external-adoption-smoke --path . --library-examples` |
| Test jsonwebtoken adapter validation | [jsonwebtoken-adapter-validation](jsonwebtoken-adapter-validation/) | `cargo xtask external-adoption-smoke --path . --library-examples` |
| Test PGP key parsing and policy paths | [pgp-fixture-validation](pgp-fixture-validation/) | `cargo xtask external-adoption-smoke --path . --library-examples` |
| Test PKCS#11 mock validation | [pkcs11-mock-validation](pkcs11-mock-validation/) | `cargo xtask external-adoption-smoke --path . --library-examples` |
| Use facade fixtures in Rust tests | [rust-test-fixtures](rust-test-fixtures/) | `cargo xtask external-adoption-smoke --path . --library-examples` |
| Test SSH key and certificate validation | [ssh-fixture-validation](ssh-fixture-validation/) | `cargo xtask external-adoption-smoke --path . --library-examples` |
| Test TLS chain validation | [tls-chain-validation](tls-chain-validation/) | `cargo xtask external-adoption-smoke --path . --library-examples` |
| Test WebAuthn ceremony validation | [webauthn-ceremony-validation](webauthn-ceremony-validation/) | `cargo xtask external-adoption-smoke --path . --library-examples` |
| Test webhook signature validation | [webhook-verifier](webhook-verifier/) | `cargo xtask external-adoption-smoke --path . --library-examples` |
| Consume `bundle-audit.json` in language-neutral CI | [../ci](../ci/) | `bash examples/ci/consume-bundle-audit.sh target/uselesskey-webhook-audit/bundle-audit.json` |

Run proof modes sequentially in one checkout. The default path smoke,
library-example smoke, and CI-recipe smoke all write
`target/external-adoption-smoke/report.md` and
`target/external-adoption-smoke/report.json`, so keep any receipt you need
before running the next mode.

## Review Boundary

Keep generated fixture payloads under `target/` or another ignored output
directory. Upload metadata-only receipts such as `bundle-audit.json` and
`bundle-audit.md` when reviewers need CI evidence.

These examples prove local fixture wiring and documented failure classes. They
do not prove production security, provider compatibility, scanner-policy
approval, release readiness, or downstream verifier correctness.
