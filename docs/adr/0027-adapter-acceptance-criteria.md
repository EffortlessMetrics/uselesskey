# ADR-0027: Adapter Acceptance Criteria

## Status

Accepted

## Context

The workspace now tracks 43 publishable crates through `PUBLISH_CRATES`. Without guardrails, adapter ideas can quietly become permanent cargo-weight:

- ecosystem demand can be satisfied by existing crates with the same native type family
- small conversion helpers can be misclassified as adapters
- release and review burden can grow faster than value

This ADR defines a strict bar for adding new adapter crates so the line between core artifact generation and downstream compatibility adapters stays explicit.

## Decision

An **adapter crate** is a crate whose main purpose is to convert `uselesskey` artifacts into stable, ecosystem-native types for a specific dependency family (for example TLS credentials, JOSE signing keys, or native token/crypto types).

An adapter crate **must** satisfy all of the following to be accepted:

1. **Clear native-type return**
   - The crate exposes helpers whose primary output is a type from the target ecosystem crate(s).
   - The conversion target is not a format already covered by core (PEM/DER/JWK/artifacts only).
2. **Existing surface check**
   - If any existing adapter already provides the same native-type conversion, new work belongs in that adapter, not a new crate.
3. **Ecosystem value**
   - The adapter unlocks a non-trivial integration path that is currently difficult or fragile for test authors.
   - The conversion path is used beyond a single internal consumer.
4. **Crate-cost check**
   - Expected ongoing maintenance is supported by at least one clear consumer need and a documented ownership plan.
5. **Release-ready package boundary**
   - It can be added to `PUBLISH_CRATES` with stable manifest metadata, docs, and release checklist updates.

For each approved adapter crate, the following artifacts are required:

- ADR-approved rationale and compatibility statement
- crate README with dependency snippets and native type mapping
- one runnable example with documented feature set
- one smoke/integration test covering deterministic output path
- `publish-check` / `publish-preflight` pass for the crate
- feature-matrix or docs metadata entry for discoverability

What does **not** qualify as a new adapter crate:

- helper APIs that only format or rename existing core artifacts
- wrappers that only compose existing adapter outputs without introducing new native mapping logic
- one-off internal conversions for a single team/project
- alternative APIs over the same conversion that duplicate another adapter

## Consequences

### Positive

- Contributors get a deterministic decision rule for crate expansion.
- Adapter set stays aligned with real ecosystem integration value, not accidental drift.
- Release risk grows only when a crate has clear cross-consumer benefit.

### Negative

- Some useful but niche conversions will now stay as examples or downstream code instead of first-class crates.
- Every new adapter requires explicit metadata and testing work before landing.

## Alternatives Considered

- **Keep adding adapters as existing adapters accrete more features**
  - **Rejected:** increases coupling and makes compatibility promises less explicit.
- **Put new adapters behind `uselesskey` feature flags**
  - **Rejected:** does not solve version and dependency-graph pressure across the 43-crate publish set.
- **Use issue labels only (no ADR)**
  - **Rejected:** misses required release and maintenance requirements before crate creation.
