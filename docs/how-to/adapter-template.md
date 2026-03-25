# Adapter scaffold template

Use this guide for any new adapter crate in the `uselesskey` workspace.

An adapter crate converts `uselesskey` fixture artifacts into native types from a
specific ecosystem dependency (TLS, JOSE, native crypto, etc.) without moving
fixture generation into that ecosystem.

## Minimum acceptance checklist

- [ ] Crate exists at `crates/uselesskey-<adapter>`.
- [ ] Package name follows the `uselesskey-<adapter>` convention.
- [ ] `Cargo.toml` sets:
  - `publish = true` only if intended for release.
  - `readme = "README.md"` points to the crate README.
  - `license`, `repository`, `rust-version`, `edition`, and `homepage` via workspace
    inheritance where available.
  - `description`, `keywords`, and `categories` describe the adapter surface.
  - `exclude = ["fuzz/**", "corpus/**", "**/*.der", "**/*.pem"]`.
- [ ] `package.metadata.docs.rs` is intentional and explicit.
  - Prefer `features = ["all"]` if most users enable one surface.
  - Use `all-features = true` only when that is the published contract.

## Feature convention

- [ ] No feature flags for “enable adapter” behavior.
  - The crate itself is the opt-in dependency.
- [ ] Use feature flags for optional upstream ecosystems (`ring`, `aws-lc-rs`, `jose`, `pgp`, etc.).
- [ ] Provide a single `all` feature that turns on every conversion path.
- [ ] Keep dependencies optional where possible so feature-only use does not pull
  unused stacks.

## API surface

- [ ] One or more focused traits in the root module.
- [ ] Traits convert only stable fixture object variants (for example `RSAChain`, `RsaFixture`, `PgpArtifact`).
- [ ] Trait docs describe ownership/copy semantics and expected error shape.
- [ ] Keep conversion helpers intentionally narrow and avoid convenience helpers that
  do not add a real native interop boundary.

## Testing and examples

- [ ] Add one smoke test in `tests/` that exercises the primary conversion trait.
- [ ] Add one integration-style test for a realistic downstream use of the native
  type (not property-coverage tests).
- [ ] Add one runnable example under `crates/<crate>/examples/`.
- [ ] Pin deterministic fixture seeds in tests and examples where output stability
  matters.

## Documentation requirements

- [ ] Include crate-level `README.md` with:
  - one-line purpose
  - feature table or list
  - quick snippet with `uselesskey` façade usage
  - example of the native type usage
- [ ] Register the crate in the main docs inventory where appropriate (README/
  docs-sync source).
- [ ] Add a how-to entry from this guide where relevant.

## Release/readiness requirements

- [ ] Add crate to `PUBLISH_CRATES` when it is intended for release.
- [ ] Add/update release metadata and examples if required by release docs.
- [ ] Verify `cargo xtask publish-preflight` includes the new crate path in
  dependency order.
- [ ] Add a short line in next release notes or roadmap follow-up if feature
  coverage changes.

## Quick implementation order

1. Create crate with only artifact conversion API.
2. Add a smoke test and one integration test.
3. Add example and README.
4. Wire docs/release inventory.
5. Run `cargo xtask publish-preflight` before opening PR.
