# Release

## Status

The crates.io prep phase is complete on `main`.

- `chore: publish-prep for v0.2.0 (#229)` is merged.
- `fix(xtask): handle 429 rate limits and already-published crates in publish (#230)` is merged.

Use this document for the steady-state release flow, not as a prep checklist.

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
cargo xtask publish-preflight   # metadata + doc snippet versions + cargo package
cargo xtask publish-check       # cargo publish --dry-run in dependency order
cargo xtask canaries            # external-consumer canaries in path-dep mode
```

Before tagging, make sure the release PR has already:

- bumped publishable crate versions
- updated `CHANGELOG.md`
- refreshed versioned `uselesskey*` dependency snippets in README/doc examples

## Publish

```bash
cargo xtask publish   # publishes all 43 crates in dependency order with retry
```

This command handles crates.io indexing lag automatically. Current behavior:

- retries each crate up to 5 times
- waits 60 s for indexing-race failures (`failed to select a version`, `not found`)
- backs off on rate limits (`429` / `too many requests`) with `120 s * attempt`
- treats "already uploaded" / "already exists" as success for reruns
- waits 30 s after each successful publish for indexing

## Post-publish smoke

Run at least one published-version canary against crates.io:

```bash
cargo xtask canaries --published 0.5.1
```
