# uselesskey public corpus v0.5.1

This corpus is generated from explicit fixture specs (not scraped examples).

## Commands

```bash
cargo xtask corpus build
cargo xtask corpus verify
```

## Included families

- `x509/`
- `jwks/`
- `tokens/`
- `negative/`

Each case directory includes `case.json` metadata and one or more fixture files.
