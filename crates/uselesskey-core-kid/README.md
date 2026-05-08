# uselesskey-core-kid

Deprecated compatibility shim for deterministic key-ID (`kid`) helpers now
owned by `uselesskey-jwk`.

This crate preserves the previous crate-level API path for published-internal
consumers. Prefer the public JWK crate for new code.

## Scope

- deterministic, content-based key IDs
- stable defaults shared by fixture crates
- no key material formatting or parsing

## Example

```rust
use uselesskey_jwk::srp::kid::kid_from_bytes;

let kid = kid_from_bytes(b"public-key-bytes");
assert!(!kid.is_empty());
```
