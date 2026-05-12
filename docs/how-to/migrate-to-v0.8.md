# Migrate from uselesskey v0.7.x to v0.8.0

v0.8.0 collapses internal published-shim crates into owner-crate
`srp::*` modules. **Most users do not need to do anything.**

## TL;DR

If your `Cargo.toml` only depends on:

- `uselesskey` (the facade)
- fixture-family crates (`uselesskey-rsa`, `uselesskey-token`, etc.)
- adapter crates (`uselesskey-rustls`, `uselesskey-jsonwebtoken`, etc.)
- test infrastructure (`uselesskey-test-server`, `uselesskey-pkcs11-mock`)
- CLI (`uselesskey-cli`)

then **bump the version constraint to `"0.8"` and you're done**.
These crates' public APIs are unchanged in v0.8.0.

Only if your `Cargo.toml` references one of the *internal* crates
removed in v0.8.0 (`uselesskey-core-*`, `uselesskey-token-spec`,
`uselesskey-pgp-native`, `uselesskey-jose-openid`) do you need to
migrate — read below.

## What changed

v0.7.0 moved internal content into `srp::*` modules but kept old
crate names published as compatibility shims. v0.8.0 removes those
shim crates from the workspace and from future publishing. v0.7.x
versions remain on crates.io as historical records.

## Mapping table

### Core internals → `uselesskey-core::srp::*`

| v0.7.x crate                       | v0.8.0 replacement                              |
|-----------------------------------|-------------------------------------------------|
| `uselesskey-core-cache`            | `uselesskey_core::srp::cache`                   |
| `uselesskey-core-factory`          | `uselesskey_core::srp::factory`                 |
| `uselesskey-core-hash`             | `uselesskey_core::srp::hash`                    |
| `uselesskey-core-id`               | `uselesskey_core::srp::identity`                |
| `uselesskey-core-seed`             | `uselesskey_core::srp::seed`                    |
| `uselesskey-core-sink`             | `uselesskey_core::srp::sink`                    |
| `uselesskey-core-keypair`          | `uselesskey_core::srp::keypair`                 |
| `uselesskey-core-keypair-material` | `uselesskey_core::srp::keypair_material`        |
| `uselesskey-core-negative`         | `uselesskey_core::srp::negative`                |
| `uselesskey-core-negative-der`     | `uselesskey_core::srp::negative::der`           |
| `uselesskey-core-negative-pem`     | `uselesskey_core::srp::negative::pem`           |

### JWK internals → `uselesskey-jwk::srp::*`

| v0.7.x crate                | v0.8.0 replacement                |
|----------------------------|-----------------------------------|
| `uselesskey-core-kid`       | `uselesskey_jwk::srp::kid`        |
| `uselesskey-core-jwk`       | `uselesskey_jwk::*`               |
| `uselesskey-core-jwk-builder` | `uselesskey_jwk::JwksBuilder`   |
| `uselesskey-core-jwk-shape` | `uselesskey_jwk::srp::shape`      |
| `uselesskey-core-jwks-order`| `uselesskey_jwk::srp::ordering`   |

### Token internals → `uselesskey-token::srp::*`

| v0.7.x crate                 | v0.8.0 replacement              |
|-----------------------------|---------------------------------|
| `uselesskey-core-base62`     | `uselesskey_token::srp::base62`|
| `uselesskey-core-token`      | `uselesskey_token::srp::shape` |
| `uselesskey-core-token-shape`| `uselesskey_token::srp::shape` |
| `uselesskey-token-spec`      | `uselesskey_token::srp::spec`  |

### X.509 internals → `uselesskey-x509::srp::*`

| v0.7.x crate                          | v0.8.0 replacement                        |
|--------------------------------------|-------------------------------------------|
| `uselesskey-core-x509`                | `uselesskey_x509::srp::policy`            |
| `uselesskey-core-x509-spec`           | `uselesskey_x509::srp::spec`              |
| `uselesskey-core-x509-derive`         | `uselesskey_x509::srp::derive`            |
| `uselesskey-core-x509-negative`       | `uselesskey_x509::srp::negative`          |
| `uselesskey-core-x509-chain-negative` | `uselesskey_x509::srp::chain_negative`    |

### HMAC, rustls, pgp folded crates

| v0.7.x crate              | v0.8.0 replacement              |
|--------------------------|---------------------------------|
| `uselesskey-core-hmac-spec` | `uselesskey_hmac::srp::spec`  |
| `uselesskey-core-rustls-pki`| `uselesskey_rustls::srp::pki` |
| `uselesskey-pgp-native`     | `uselesskey_pgp::native` (enable feature `native`) |

### Removed duplicate

| v0.7.x crate              | v0.8.0 replacement              |
|--------------------------|---------------------------------|
| `uselesskey-jose-openid`  | Use `uselesskey-jsonwebtoken` (the same trait is already there as `JwtKeyExt`). The `uselesskey-jose-openid` crate was a byte-equivalent duplicate; no behavior is lost. |

## How to migrate

### 1. Cargo.toml

For each removed crate listed in your `Cargo.toml`, replace with the
owner crate:

```toml
# before
uselesskey-core-cache = "0.7"

# after
uselesskey-core = "0.8"
```

If you depended on multiple shims from the same owner family (e.g.,
four `uselesskey-core-*` crates), you only need one `uselesskey-core`
entry — it carries all the `srp::*` modules.

### 2. Imports

For each `use` statement of a removed crate, replace with the owner
path from the table above:

```rust
// before
use uselesskey_core_cache::ArtifactCache;

// after
use uselesskey_core::srp::cache::ArtifactCache;
```

For `uselesskey-pgp-native`, also enable the `native` feature on
`uselesskey-pgp`:

```toml
uselesskey-pgp = { version = "0.8", features = ["native"] }
```

```rust
// before
use uselesskey_pgp_native::PgpNativeExt;

// after
use uselesskey_pgp::native::PgpNativeExt;
```

For `uselesskey-jose-openid`, switch the dep name and trait:

```toml
# before
uselesskey-jose-openid = "0.7"

# after
uselesskey-jsonwebtoken = "0.8"
```

```rust
// before
use uselesskey_jose_openid::JoseOpenIdKeyExt;
key.encoding_key();

// after
use uselesskey_jsonwebtoken::JwtKeyExt;
key.encoding_key();
```

The method signatures are identical.

### 3. Validate

```bash
cargo update
cargo check --all-features
cargo test
```

If anything fails to resolve, grep for any remaining references:

```bash
rg "uselesskey-core-|uselesskey_core_|uselesskey-token-spec|uselesskey-pgp-native|uselesskey-jose-openid"
```

## v0.7.x crates remain on crates.io

The 29 removed crates remain published at their final v0.7.x version
for any consumer still locked there. No yanks. Upgrade at your own
pace.

## Why we did this

The shim crates had a real purpose during the v0.7.0 SRP fold — they
preserved the published crate names while we moved content into
owner-crate `srp::*` modules. v0.7.x carried them as compatibility
shims for one release cycle. With v0.8.0, they're no longer
forward-published; the workspace and the public crate surface now
agree.

The right user-facing surface in v0.8.0:

- `uselesskey` — facade
- `uselesskey-cli` — operator CLI
- `uselesskey-core` — foundation
- Fixture families: `uselesskey-{entropy,rsa,ecdsa,ed25519,hmac,token,jwk,x509,ssh,pgp,webhook,webauthn}`
- Test infrastructure: `uselesskey-{test-server,pkcs11-mock}`
- Adapters: `uselesskey-{jsonwebtoken,rustls,tonic,axum,ring,rustcrypto,aws-lc-rs}`

See `docs/architecture/public-surface.md` for the canonical map.

## Questions

File an issue at https://github.com/EffortlessMetrics/uselesskey/issues
with the `migration` label.
