# Release

## Publish order

The authoritative publish order is the `PUBLISH_CRATES` constant in
`xtask/src/main.rs`. It is a topo-sorted list of all 43 publishable crates,
leaves first:

1. **Core microcrates** — leaf crates with no workspace deps (`core-base62`,
   `core-seed`, `core-hash`, …), then negative-fixture crates, sinks/shapes,
   JWK/JWKS helpers, X.509 layers, and the `uselesskey-core` aggregate.
2. **Key-type crates** — `rsa`, `ecdsa`, `ed25519`, `hmac`, `token`, `pgp`,
   `x509`, plus `jwk` facade.
3. **Facade** — `uselesskey` (the public API crate).
4. **Adapters** — `jsonwebtoken`, `rustls`, `tonic`, `ring`, `rustcrypto`,
   `aws-lc-rs`.

Do **not** maintain a separate crate list here — `PUBLISH_CRATES` is the
single source of truth.

## Dry run

```bash
cargo xtask publish-check       # dry-run publish in dependency order
cargo xtask publish-preflight   # metadata validation + cargo package
```

## Publish

```bash
cargo xtask publish   # publishes all 43 crates in dependency order with retry
```

This command handles crates.io indexing lag automatically (retries up to 3×
with 60 s backoff per crate, plus a 30 s post-publish wait).
