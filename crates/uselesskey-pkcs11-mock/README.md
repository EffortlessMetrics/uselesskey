# uselesskey-pkcs11-mock

Deterministic PKCS#11-like mock fixtures for hardware-adjacent tests.

This crate is intentionally **not** a real PKCS#11 provider. It offers a tiny in-memory mock surface for key handles, sign operations, certificate lookup, and slot/token metadata.
