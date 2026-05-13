# Active Goals

This directory stores machine-readable lane state for agents working in
`uselesskey`.

The active goal manifest is the current execution source. Handoffs and learnings
record history; they should not be treated as active instructions.

## Files

- `active.toml` - Current agent lane, once a lane is active.
- `archive/` - Completed or superseded active-goal manifests.
- `templates/active.toml` - Template for new active goals.

Do not create `active.toml` until the lane has an accepted proposal or spec to
link to.

When resuming agent work, read
[`docs/handoffs/agent-bootstrap.md`](../../docs/handoffs/agent-bootstrap.md)
before acting on older chat context.
