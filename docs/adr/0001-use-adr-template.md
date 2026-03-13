# ADR-0001: Use ADR Template

## Status

Accepted

## Context

The uselesskey project needs a consistent way to document architectural decisions. Without a structured approach:

- Decisions are scattered across commit messages, PR descriptions, and code comments
- The reasoning behind architectural choices becomes lost over time
- New contributors struggle to understand why the codebase is structured the way it is
- Revisiting past decisions requires archaeology through git history

We need a lightweight, structured format that captures decisions without creating excessive documentation overhead.

## Decision

We will use Architecture Decision Records (ADRs) following the Michael Nygard format to document significant architectural decisions.

Each ADR will be stored in `docs/adr/` with the naming convention `NNNN-short-title.md` where:

- `NNNN` is a zero-padded sequence number
- `short-title` is a brief, kebab-case description

Every ADR must include these sections:

1. **Status**: One of Proposed, Accepted, Deprecated, or Superseded
2. **Context**: The issue motivating this decision
3. **Decision**: The change or approach being taken
4. **Consequences**: The resulting advantages and disadvantages
5. **Alternatives Considered**: Other options that were evaluated

## Consequences

### Positive

- **Consistency**: All decisions follow the same format, making them easy to read and compare
- **Discoverability**: A single location (`docs/adr/`) for all architectural decisions
- **Onboarding**: New contributors can quickly understand the architecture's evolution
- **Lightweight**: Minimal overhead compared to formal documentation
- **Version controlled**: ADRs are code-reviewed and tracked in git alongside the code

### Negative

- **Maintenance**: ADRs require effort to create and keep updated
- **Discipline**: Team must remember to create ADRs for significant decisions
- **Scope ambiguity**: "What counts as an architectural decision?" requires judgment

## Alternatives Considered

### No formal documentation

Rely on commit messages and code comments alone.

**Rejected because**: Important context gets lost; commit messages are too granular; code comments don't capture the "why" at the right level.

### RFC-style process

Require formal Request for Comments for all changes.

**Rejected because**: Too heavyweight for a utility library; creates friction that discourages documentation.

### Wiki-based documentation

Use GitHub Wiki or external documentation site.

**Rejected because**: Not version-controlled alongside code; can become stale; separate from PR review process.

### Decision logs in AGENTS.md

Add decisions to the existing AGENTS.md file.

**Rejected because**: AGENTS.md is for AI agent instructions, not historical decision records; would become unwieldy as decisions accumulate.
