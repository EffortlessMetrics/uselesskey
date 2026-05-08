# uselesskey-core-x509-negative

Published-internal compatibility shim for X.509 certificate negative-policy
helpers.

Prefer `uselesskey-x509`; `X509Negative` is now owned by
`uselesskey_x509::srp::negative` and re-exported from the `uselesskey-x509`
public root. This crate is retained for migration only and should not be used as
a new direct dependency.
