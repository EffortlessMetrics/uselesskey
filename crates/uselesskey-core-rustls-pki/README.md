# uselesskey-core-rustls-pki

Core adapter traits that convert uselesskey fixtures into `rustls-pki-types` key and certificate types.

This crate only covers PKI conversion primitives (`PrivateKeyDer`, `CertificateDer`).
Higher-level rustls configuration builders live in `uselesskey-rustls`.
