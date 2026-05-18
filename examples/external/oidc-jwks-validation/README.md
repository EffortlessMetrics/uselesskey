# OIDC/JWKS Validation Fixtures

Use this downstream-shaped example when an OIDC or JWT validator test needs
deterministic JWKS shapes plus key-selection negatives.

```bash
cargo test
```

The example models a small downstream JWKS validator. It accepts a valid RSA
JWKS and rejects taxonomy-backed fixture shapes for:

- duplicate `kid`
- wrong `kty`
- unsupported `alg`
- missing `kid`

Installed CLI bundle audit path:

```bash
uselesskey bundle --profile oidc --out target/uselesskey-oidc
uselesskey audit-bundle --path target/uselesskey-oidc --out target/uselesskey-oidc-audit
```

This proves fixture shape and negative input generation for validator tests, and
shows how a downstream validator can assert specific rejection classes. It does
not prove OpenID discovery behavior, production signing-key custody, issuer
policy, provider compatibility, or production verifier correctness.
