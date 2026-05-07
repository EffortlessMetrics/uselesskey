# uselesskey-test-support

Fallible test helpers for the `uselesskey` workspace. Used by tests that
return `Result<()>` instead of relying on panicking macros.

This crate is a workspace dev-dependency only; it is not published.

## Helpers

- `ensure!(cond, msg)` — fails the test with `Err(...)` when `cond` is false.
- `ensure_eq!(left, right)` — fails the test with `Err(...)` if `left != right`.
- `require_some(option, msg)` — converts `Option<T>` to `Result<T, _>`.
- `require_ok(result, msg)` — coerces `Result<T, E>` failures into the
  test's error type with a contextual message.

## Pattern

```rust
use uselesskey_test_support::{ensure_eq, require_ok};

#[test]
fn my_fallible_test() -> Result<(), Box<dyn std::error::Error>> {
    let value = require_ok(parse_thing(input), "parse_thing should accept input")?;
    ensure_eq!(value.kind(), Kind::Expected);
    Ok(())
}
```

See `docs/NO_PANIC_POLICY.md` for the broader policy context.
