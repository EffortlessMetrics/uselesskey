# uselesskey-core-sink

Test fixture tempfile sinks for `uselesskey`.

## Purpose

- Keep file-path-oriented artifact outputs isolated from the core factory crate.
- Expose deterministic-friendly helpers for writing artifacts to secure tempfiles.
- Preserve cleanup behavior by deleting files when handles drop.

This microcrate is intentionally focused: it has no domain-specific crypto knowledge and
only models output sinks.
