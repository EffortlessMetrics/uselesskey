# uselesskey-ssh

Deterministic OpenSSH key and certificate fixtures for test environments.

This crate extends `uselesskey_core::Factory` with:

- `fx.ssh_key(label, SshSpec)` for RSA/Ed25519 OpenSSH key fixtures
- `fx.ssh_cert(label, SshCertSpec)` for deterministic OpenSSH certificates

Not for production.
