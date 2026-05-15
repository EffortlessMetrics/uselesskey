# Start Here

Use this page when you know what you are trying to test and want the shortest
path to a working fixture.

`uselesskey` is a test-fixture factory. It is not production key generation,
certificate management, provider compatibility certification, scanner evasion,
or cryptographic assurance.

## Pick Your Job

| I need to... | Start with | Copy this |
| --- | --- | --- |
| use fake RSA/JWK fixtures in Rust tests | facade crate | `uselesskey = { version = "0.9.0", features = ["rsa", "jwk"] }` |
| use token-shaped strings without keygen | token lane | `uselesskey = { version = "0.9.0", default-features = false, features = ["token"] }` |
| generate a deterministic scanner-safe bundle | CLI scanner-safe profile | `uselesskey bundle --profile scanner-safe --out target/uselesskey-bundle` |
| test TLS verifier behavior | TLS contract pack | `uselesskey bundle --profile tls --out target/uselesskey-tls` |
| test OIDC/JWKS validator behavior | OIDC/JWKS contract pack | `uselesskey bundle --profile oidc --out target/uselesskey-oidc` |
| test webhook signature negatives | webhook contract pack | `uselesskey bundle --profile webhook --out target/uselesskey-webhook` |
| prove public claims for a reviewer | verification pack | `cargo xtask verification-pack --out target/uselesskey-verification` |

Install the CLI when you want bundle commands outside this workspace:

```bash
cargo install uselesskey-cli --version 0.9.0
```

Inside the workspace, use:

```bash
cargo run -p uselesskey-cli -- bundle --profile webhook --out target/uselesskey-webhook
```

## Rust Test Fixtures

Add the smallest feature set that preserves your test semantics:

```toml
[dev-dependencies]
uselesskey = { version = "0.9.0", features = ["rsa", "jwk"] }
```

Then generate fixtures at runtime:

```rust
use uselesskey::{Factory, RsaFactoryExt, RsaSpec};

let fx = Factory::deterministic_from_str("my-test-seed");
let rsa = fx.rsa("issuer", RsaSpec::rs256());

let pkcs8_pem = rsa.private_key_pkcs8_pem();
let jwk = rsa.public_jwk();
```

What this gives you:

- deterministic fixture material for tests;
- no committed PEM, DER, JWK, or token blobs;
- realistic artifact shapes for parser and verifier paths.

What it does not give you:

- production key generation;
- production secret storage;
- proof your verifier is correct.

For feature selection, see [choose-features.md](choose-features.md).

## Deterministic Bundle Fixtures

Generate and verify a bundle:

```bash
uselesskey bundle --profile scanner-safe --out target/uselesskey-bundle
uselesskey verify-bundle --path target/uselesskey-bundle
```

Keep generated payloads under `target/`. Commit metadata, docs, and policy when
needed, not generated secret-shaped payloads.

For Kubernetes and Vault-shaped exports, see
[generate-scanner-safe-k8s-secret.md](generate-scanner-safe-k8s-secret.md).

## Contract Packs

Use contract packs when you want fixtures plus documented positive and negative
cases.

For the product-family view, see
[`../contract-packs/README.md`](../contract-packs/README.md).

### TLS

```bash
uselesskey bundle --profile tls --out target/uselesskey-tls
uselesskey verify-bundle --path target/uselesskey-tls
cargo xtask claim-proof --claim tls-contract-pack
```

Proves documented TLS fixture paths and negative validation cases. Does not
prove production PKI, revocation, certificate transparency, mTLS, browser
trust-store behavior, or downstream verifier correctness.

### OIDC/JWKS

```bash
uselesskey bundle --profile oidc --out target/uselesskey-oidc
uselesskey verify-bundle --path target/uselesskey-oidc
cargo xtask claim-report --claim oidc-jwks-contract-pack
```

Proves documented OIDC/JWKS fixture shapes and negative validator inputs. Does
not prove provider compatibility, issuer policy, or production token security.

### Webhook

```bash
uselesskey bundle --profile webhook --out target/uselesskey-webhook
uselesskey verify-bundle --path target/uselesskey-webhook
cargo xtask claim-proof --claim webhook-contract-pack
```

Proves deterministic HMAC webhook verifier fixtures for valid, tampered-body,
wrong-secret, stale-timestamp, missing-signature, and malformed-signature cases.
Does not prove provider compatibility, secret rotation, replay protection
completeness, delivery behavior, or transport security.

## Reviewer Proof

Build a metadata-only review bundle:

```bash
cargo xtask verification-pack --out target/uselesskey-verification
```

For one claim:

```bash
cargo xtask verification-pack --out target/uselesskey-verification --claim webhook-contract-pack
```

Attach the generated `target/uselesskey-verification/README.md` and receipt
files. Do not attach generated PEM, DER, JWT, key, Kubernetes Secret, or Vault
payload files.

For the full public-claim workflow, see
[verify-uselesskey-public-claims.md](verify-uselesskey-public-claims.md).
