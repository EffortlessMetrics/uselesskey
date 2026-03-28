# Canaries

Tiny external-consumer apps used to validate the public published surface from the outside.

## Included canaries

- `facade-minimal`: depends only on `uselesskey` and generates key/token/cert fixtures.
- `adapter-rustls`: exercises `uselesskey-rustls` by producing rustls server/client configs.
- `release-doc-copy-paste`: copy-paste quick-start token snippet from docs.

## Running

Path mode against this workspace:

```bash
cargo xtask canaries
```

Published mode against crates.io versions:

```bash
cargo xtask canaries --published 0.5.1
```
