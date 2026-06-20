# Handoffs

Handoffs record what changed, what proof exists, and what the next operator
should do after a lane changes state.

Use handoffs for release gates, PR queue transitions, failed external
dependencies, and lane closeout. Do not use handoffs as the active task source;
current agent state belongs under `.uselesskey/goals/`.

Start with [agent-bootstrap.md](agent-bootstrap.md) when resuming agent work.
It defines the read order from `active.toml` to plans, specs, claim reports, and
validation commands.

Use [local-validation.md](local-validation.md) when reporting local PR evidence
or deciding what `pr-lite`, hosted CI, targeted mutation, and release evidence
each prove.

## Required Shape

Use [the handoff template](../templates/handoff.md). A handoff should include:

- Current state
- Relevant PRs, issues, commits, or releases
- Proof already run
- Known blockers
- Next safe action
- Explicit non-goals

## Release Handoffs

- [2026-06-19-v0-10-adoption-handoff.md](2026-06-19-v0-10-adoption-handoff.md)
  imports the `uselesskey-swarm` v0.10 release-adoption packet into the source
  repo and preserves the source release authority boundary.
- [2026-06-20-v0.10.0-release-closeout.md](2026-06-20-v0.10.0-release-closeout.md)
  closes the v0.10.0 source release gate after publication, tag creation,
  registry verification, and published-version smoke.
