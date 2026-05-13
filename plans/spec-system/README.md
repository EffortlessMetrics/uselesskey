# Spec-System Plan Area

This directory tracks the rollout that makes proposals, specs, ADRs, plans,
active goal manifests, and policy ledgers the normal operating model for
`uselesskey`.

The first PR is scaffold-only. It adds navigation and templates without claiming
automation enforcement.

## Plan Files

- [implementation-plan.md](implementation-plan.md) - PR sequence, proof commands, rollback, and stop conditions
- [closeout.md](closeout.md) - implemented lane state, proof commands, and next safe action

## Initial PR Order

1. Define source-of-truth scaffold.
2. Add the spec-governed fixture-platform proposal.
3. Add the source-of-truth and public-claim specs.
4. Add contract-pack and generated-evidence specs.
5. Add ADRs and the active goal manifest.
6. Add `cargo xtask spec-check`.
7. Wire `spec-check` into normal evidence after the command settles.
