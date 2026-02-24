# uselesskey-core-keypair-material

Reusable PKCS#8/SPKI key-material helpers for `uselesskey` fixture crates.

This microcrate owns the shared helper surface used by RSA/ECDSA/Ed25519
fixture generation:

- PKCS#8 and SPKI accessors
- tempfile sinks for PEM outputs
- deterministic negative fixture helpers
- stable `kid` derivation from SPKI bytes

It is intentionally small and narrowly scoped for SRP.
