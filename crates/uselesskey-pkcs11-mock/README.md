# uselesskey-pkcs11-mock

Deterministic PKCS#11-style mock fixtures for hardware-adjacent tests.

This crate is a **testing shim**, not a real PKCS#11 provider and not an HSM emulator.
It provides stable key handles, signing, certificate lookup, and slot/token metadata.
