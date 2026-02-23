# uselesskey-core-seed

Seed parsing and redaction primitives shared across `uselesskey` crates.

## Purpose

- Parse user-provided seed inputs (`hex` or free-form string) into 32 bytes.
- Keep `Debug` output redacted so logs cannot leak seed material.
- Provide a small, reusable seed type for deterministic fixture systems.
