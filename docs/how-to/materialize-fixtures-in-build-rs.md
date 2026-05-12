# Materialize fixtures in build.rs

You want test fixtures (PEM keys, JWKs, certs) regenerated deterministically
at build time so they live under `OUT_DIR` and never need to be committed.
This guide walks the manifest-driven `uselesskey-cli` materialize workflow
that a downstream crate calls from its own `build.rs`.

The workflow has two flavors: shape-only fixtures (fast, no RSA keygen) and
runtime-rsa fixtures (slower, real RSA material). Both end the same way:
deterministic bytes under `OUT_DIR`, surfaced to your test code via an
auto-generated `include_bytes!` module.

## The manifest

Each consuming crate declares its fixtures in a `uselesskey-fixtures.toml`
manifest next to its `Cargo.toml`. The shape is a top-level `version` plus
one `[[fixture]]` table per output.

From `crates/materialize-shape-buildrs-example/uselesskey-fixtures.toml`:

```toml
version = 1

[[fixture]]
id = "entropy"
kind = "entropy.bytes"
seed = "buildrs-shape-example:entropy"
len = 64
out = "entropy.bin"

[[fixture]]
id = "token"
kind = "token.jwt_shape"
seed = "buildrs-shape-example:token"
out = "token.txt"

[[fixture]]
id = "pem_shape"
kind = "pem.block_shape"
seed = "buildrs-shape-example:pem"
label = "certificate"
out = "placeholder.pem"

[[fixture]]
id = "ssh_shape"
kind = "ssh.public_key_shape"
seed = "buildrs-shape-example:ssh"
label = "deploy@example"
out = "id_ed25519.pub"
```

Field summary, as parsed by `uselesskey_cli::MaterializeFixtureSpec`:

- `version` — manifest schema version. The current value is `1`.
- `id` — stable identifier for this fixture. Drives the generated constant
  name in the emitted module.
- `kind` — which materializer to use. Supported kinds include
  `entropy.bytes`, `token.jwt_shape`, `token.api_key`, `pem.block_shape`,
  `ssh.public_key_shape`, `rsa.pkcs8_der`, and `rsa.pkcs8_pem`.
- `seed` — deterministic seed string. The same seed produces the same
  bytes every run; change the seed to rotate a fixture.
- `len` — byte length for variable-length kinds such as `entropy.bytes`.
- `label` — kind-specific label (PEM block label for `pem.block_shape`,
  SSH comment for `ssh.public_key_shape`).
- `out` — output filename, resolved relative to the destination directory.

## Wire it into `build.rs`

The example `build.rs` is the same for both flavors. From
`crates/materialize-buildrs-example/build.rs`:

```rust
use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=uselesskey-fixtures.toml");

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let manifest_path = manifest_dir.join("uselesskey-fixtures.toml");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("out dir"));
    let module_path = out_dir.join("fixtures.rs");

    let manifest =
        uselesskey_cli::load_materialize_manifest(&manifest_path).expect("materialize manifest");
    uselesskey_cli::materialize_manifest_to_dir(&manifest, &out_dir, false)
        .expect("materialize fixtures");
    uselesskey_cli::emit_include_bytes_module(&manifest, &out_dir, &module_path)
        .expect("emit include_bytes module");
}
```

The three call sites do the work:

- `load_materialize_manifest` parses and validates the TOML at
  `CARGO_MANIFEST_DIR/uselesskey-fixtures.toml`.
- `materialize_manifest_to_dir(&manifest, &out_dir, false)` writes each
  fixture under `OUT_DIR`. The third argument is the `check` flag; pass
  `false` to write and `true` to verify-without-overwrite.
- `emit_include_bytes_module(&manifest, &out_dir, &module_path)` writes
  `OUT_DIR/fixtures.rs`, a module of `pub const NAME: &[u8] = include_bytes!(...)`
  entries — one per `[[fixture]]` in the manifest.

The two `rerun-if-changed` lines keep cargo's rebuild graph correct when
either the build script or the manifest changes.

## Use the materialized fixtures from tests

The emitted module is included from the consuming crate's library or test
file. From `crates/materialize-shape-buildrs-example/src/lib.rs`:

```rust
include!(concat!(env!("OUT_DIR"), "/fixtures.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_script_materializes_expected_shape_fixtures() {
        assert_eq!(ENTROPY.len(), 64);

        let jwt = std::str::from_utf8(TOKEN).expect("jwt fixture should be utf-8");
        assert_eq!(jwt.split('.').count(), 3);

        let pem = std::str::from_utf8(PEM_SHAPE).expect("pem shape should be utf-8");
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));

        let ssh = std::str::from_utf8(SSH_SHAPE).expect("ssh fixture should be utf-8");
        assert!(ssh.starts_with("ssh-ed25519 "));
    }
}
```

Constant names are derived from each fixture's `id` (uppercased). Each
constant is a `&'static [u8]` that points into the build artifact under
`target/`. Nothing about the lookup leaves the crate.

## Two flavors: shape-only vs runtime-rsa

The two example crates differ only in their `Cargo.toml` build-dependency
line and the kinds they materialize.

Shape-only — `crates/materialize-shape-buildrs-example/Cargo.toml`:

```toml
[build-dependencies]
uselesskey-cli = { path = "../uselesskey-cli", version = "0.8.0", default-features = false }
```

Shape-only manifests use kinds like `entropy.bytes`, `token.jwt_shape`,
`pem.block_shape`, and `ssh.public_key_shape`. These materialize without
running an RSA key generator. Builds stay fast and the output is still
deterministic from the per-fixture seed.

Runtime RSA — `crates/materialize-buildrs-example/Cargo.toml`:

```toml
[build-dependencies]
uselesskey-cli = { path = "../uselesskey-cli", version = "0.8.0", default-features = false, features = ["rsa-materialize"] }
```

The `rsa-materialize` feature is what unlocks `rsa.pkcs8_der` and
`rsa.pkcs8_pem` fixture kinds. Those kinds run the real RSA keygen at
build time, so first-time builds are slower than the shape-only flavor.
The bytes are still deterministic from the manifest seed.

Pick the shape-only flavor when your test only needs the surface shape of
a PEM block, JWT, SSH key, or entropy buffer. Pick the runtime-rsa flavor
when downstream tests need to parse PKCS#8 with a real cryptographic key.

## What this proves

- Builds are deterministic: the same manifest + seed produces byte-identical
  fixtures across machines and runs.
- No encoded secret-shaped payload lands in version control: every output
  lives under `OUT_DIR`, which is under `target/`.
- `OUT_DIR` isolation: each consuming crate gets its own per-target
  directory, so two crates with overlapping fixture filenames do not
  collide.
- Downstream consumers can use the emitted `include_bytes!` constants
  inside their own integration tests without depending on a generated file
  outside their crate.

## What this does NOT prove

- It is not a way to provision production secrets.
- It is not a CI/CD secret-rotation system.
- It is not a key-management abstraction.
- It does not validate cryptographic semantics — that is the job of the
  downstream adapter tests.
- It does not replace the bundle workflow when you need a verified,
  manifest-carrying handoff between crates or jobs.

## Scanner-safety boundary

`OUT_DIR` resolves to a path under `target/`, which is `.gitignore`d at
the repository root. The materialized bytes therefore stay out of git by
construction. The rule from the rest of the docs still applies: never
commit the encoded payload of a generated fixture. If a `.pem`, `.pk8`,
`.json`, or `.txt` from `OUT_DIR` is staged for commit, treat it as a
mistake and unstage it before pushing. See
[`../release/publish-recovery.md`](../release/publish-recovery.md) for the
registry-truth analogue when something secret-shaped does reach a commit.

## See also

- [`choose-features.md`](choose-features.md) — picking the right facade
  or leaf feature set, including the `uselesskey-cli` materialize lane.
- [`../../examples/scanner-safe-bundle/README.md`](../../examples/scanner-safe-bundle/README.md)
  — the bundle-driven analogue for cross-crate handoff.
