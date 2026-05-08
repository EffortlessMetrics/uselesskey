# uselesskey-core-x509-spec

Published-internal compatibility shim for X.509 fixture spec models.

Prefer `uselesskey-x509`; `X509Spec`, `ChainSpec`, `KeyUsage`, and
`NotBeforeOffset` are now owned by `uselesskey_x509::srp::spec` and re-exported
from the `uselesskey-x509` public root. This crate is retained for migration
only and should not be used as a new direct dependency.
