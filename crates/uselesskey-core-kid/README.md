# uselesskey-core-kid

Deterministic key-ID (`kid`) helpers for `uselesskey` fixture crates.

This crate is a small, stable utility layer for turning key bytes into short
base64url key IDs for tests.

## Scope

- deterministic, content-based key IDs
- stable defaults shared by fixture crates
- no key material formatting or parsing

## Example

```rust
use uselesskey_core_kid::kid_from_bytes;

let kid = kid_from_bytes(b"public-key-bytes");
assert!(!kid.is_empty());
```
