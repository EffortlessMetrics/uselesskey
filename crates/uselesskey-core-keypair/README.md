# uselesskey-core-keypair

Reusable PKCS#8/SPKI key-material helpers for `uselesskey` fixture crates.

This crate centralizes common behavior used by multiple key fixture crates:

- PKCS#8 and SPKI material accessors
- tempfile sinks for PEM output
- deterministic negative fixture helpers
- stable `kid` derivation from SPKI bytes

It is a test-fixture utility crate, not a production crypto abstraction.
