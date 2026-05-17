# OIDC/JWKS Validation Fixtures

Use this downstream-shaped example when an OIDC or JWT validator test needs
deterministic JWKS shapes plus key-selection negatives.

```bash
cargo test
```

This proves fixture shape and negative input generation for validator tests. It
does not prove OpenID discovery behavior, production signing-key custody, issuer
policy, or downstream validator correctness.
