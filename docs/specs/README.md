# Specs

Specs define what `uselesskey` promises and how that promise is proven. They are
behavior contracts, not implementation journals.

A spec should make a public claim auditable:

```text
claim -> behavior -> non-goals -> proof command -> receipt -> user doc
```

## Required Shape

Use [the spec template](../templates/spec.md). Each accepted spec should include:

- Problem
- Behavior
- Non-goals
- Required evidence
- Acceptance
- Acceptance examples
- Test mapping
- Implementation mapping
- CI proof
- Metrics or promotion rule

Do not claim enforcement until `cargo xtask spec-check` exists and is wired into
the relevant evidence lane.

## Examples To Keep Concrete

Good examples for this repo are scanner-safe fixtures, TLS contract packs,
OIDC/JWKS validation fixtures, `ripr+` badge endpoints, crates.io smoke, and
public crate-surface cleanup.
