# uselesskey-core-x509-derive

Published-internal compatibility shim for deterministic X.509 derivation
helpers.

Prefer `uselesskey-x509`; deterministic X.509 base-time, serial-number, and
length-prefixed hashing helpers are now owned by `uselesskey_x509::srp::derive`.
This crate is retained for migration only and should not be used as a new direct
dependency.
