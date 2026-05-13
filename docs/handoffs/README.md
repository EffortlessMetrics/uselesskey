# Handoffs

Handoffs record what changed, what proof exists, and what the next operator
should do after a lane changes state.

Use handoffs for release gates, PR queue transitions, failed external
dependencies, and lane closeout. Do not use handoffs as the active task source;
current agent state belongs under `.uselesskey/goals/`.

Start with [agent-bootstrap.md](agent-bootstrap.md) when resuming agent work.
It defines the read order from `active.toml` to plans, specs, claim reports, and
validation commands.

## Required Shape

Use [the handoff template](../templates/handoff.md). A handoff should include:

- Current state
- Relevant PRs, issues, commits, or releases
- Proof already run
- Known blockers
- Next safe action
- Explicit non-goals
