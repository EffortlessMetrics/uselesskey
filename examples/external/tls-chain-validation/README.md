# TLS Chain Validation Fixtures

Use this downstream-shaped example when a TLS verifier or adapter test needs
deterministic certificate-chain fixtures and rustls config construction.

```bash
cargo test
```

This proves fixture and adapter construction for test code. It does not prove
production PKI, revocation, certificate transparency, mTLS, browser trust-store
behavior, production CA custody, or downstream verifier correctness.
