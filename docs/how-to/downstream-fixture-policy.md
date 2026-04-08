# Downstream Fixture Policy

Use this page when you need a machine-readable policy for bots and reviewers in downstream repos.

## AGENTS.md snippet

```md
## Fixture policy

- Prefer the cheapest `uselesskey` lane that preserves test semantics:
  - `uselesskey-entropy` for entropy / scanner-shape only
  - `uselesskey-token` for JWT / bearer / API-token shapes only
  - leaf crates such as `uselesskey-rsa` / `uselesskey-x509` / `uselesskey-ssh` for valid runtime crypto semantics
  - `uselesskey-cli materialize` with `default-features = false` for build-time shape-only fixtures
  - `uselesskey-cli` with `features = ["rsa-materialize"]` only when build-time RSA PKCS#8 fixtures are required
- Do not commit PEM/DER/JWT/SSH fixtures by default when a `uselesskey` lane can generate them.
- Do not remove `uselesskey*` dependencies unless the PR shows:
  1. compile/test delta
  2. audit delta
  3. scanner/no-blob delta
  4. proof that semantic coverage is preserved
```

## Fixture manifest example

```toml
version = 1

[[fixture]]
id = "entropy"
kind = "entropy.bytes"
seed = "downstream:entropy"
len = 64
out = "entropy.bin"

[[fixture]]
id = "token"
kind = "token.jwt_shape"
seed = "downstream:token"
out = "token.txt"

[[fixture]]
id = "pem_shape"
kind = "pem.block_shape"
seed = "downstream:pem"
label = "certificate"
out = "placeholder.pem"
```

## Build-time dependency choice

Shape-only common lane:

```toml
[build-dependencies]
uselesskey-cli = { version = "0.6.0", default-features = false }
```

Specialized RSA build-time lane:

```toml
[build-dependencies]
uselesskey-cli = { version = "0.6.0", default-features = false, features = ["rsa-materialize"] }
```

## Materialize in CI or build scripts

Generate the fixture directory before verify or test steps:

```bash
cargo run -p uselesskey-cli -- materialize --manifest uselesskey-fixtures.toml --out-dir target/uselesskey-fixtures
```

When the repo uses build-time fixtures, keep generated outputs out of git:

```gitignore
/target/uselesskey-fixtures/
```

## CI verify snippet

```yaml
- name: Materialize fixtures
  run: cargo run -p uselesskey-cli -- materialize --manifest uselesskey-fixtures.toml --out-dir target/uselesskey-fixtures
- name: Verify materialized fixtures
  run: cargo run -p uselesskey-cli -- verify --manifest uselesskey-fixtures.toml --out-dir target/uselesskey-fixtures
```

## Dependency-removal checklist

- compile/test delta is measured and recorded
- audit delta is measured and recorded
- scanner/no-blob delta is measured and recorded
- semantic coverage is preserved, not approximated away
- the replacement is cheaper on receipts, not just smaller by inspection

## Which lane to use

- Use `uselesskey-entropy` for high-entropy bytes and scanner-shape placeholders.
- Use `uselesskey-token` for JWT/bearer/API-token shape fixtures.
- Use leaf crates for valid runtime crypto semantics.
- Use `uselesskey-cli materialize` with `default-features = false` for shape-only build-time fixtures.
- Add `features = ["rsa-materialize"]` only for specialized RSA PKCS#8 build-time fixtures.
