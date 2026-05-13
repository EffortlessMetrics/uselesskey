+++
id = "USELESSKEY-ADR-0004"
kind = "adr"
title = "README badges are a front panel, not a dashboard"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-13"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = ["USELESSKEY-SPEC-0002", "USELESSKEY-SPEC-0004"]
+++

# USELESSKEY-ADR-0004: README Badges Are a Front Panel, Not a Dashboard

## Decision

The `uselesskey` README masthead will stay small, public, repo-scoped,
generated where proof-specific, and grouped by meaning.

The standard public badge stack is:

```text
CI | Codecov | ripr+ | scanner-safe
Release | crates.io downloads | docs.rs
MSRV | license
```

Detailed proof belongs in claim ledgers, specs, verification docs, CI summaries,
and release evidence. The badge row is a front panel, not a dashboard.

## Context

`uselesskey` has many real checks: PR gates, `ripr` evidence, impacted evidence,
scanner-safe checks, release evidence, bundle proofs, public-surface checks,
publish preflight, and crates.io smoke.

Putting every guardrail in the README would make the masthead noisy and weaker.
Users need a few stable public trust markers, plus clear links to the proof
system behind them.

The generated badge endpoint work already made the important split:

- public README badges are repo-scoped;
- PR evidence is diff-scoped;
- generated endpoint JSON lives under `badges/`;
- detailed reports stay under `target/` or CI artifacts.

## Consequences

README stays readable and durable.

Badges must have a clear public meaning and a stable source. Proof-specific
badges such as `ripr+` and scanner-safe fixtures must be generated, not
hand-written.

More checks can exist without becoming masthead noise. They should appear in
CI summaries, release evidence, `docs/VERIFICATION.md`, `docs/status/`, or
reference docs.

New badges have a higher bar. They need a generated endpoint, claim-ledger
entry, proof command, and documented boundary before becoming public masthead
signals.

## Alternatives Considered

Add a badge for every CI guardrail.

Rejected because it turns the README into a dashboard and obscures the product
boundary.

Use vanity or repository-health badges.

Rejected because stars, forks, last commit, and similar badges do not prove a
fixture-platform claim.

Use static hand-written proof badges.

Rejected because they drift and become slogan badges.

Move all proof detail out of the README without badges.

Rejected because users benefit from a compact front panel when it links to real
repo-owned evidence.

## Follow-up Specs / Plans

- `USELESSKEY-SPEC-0002` defines public claim-ledger mapping.
- `USELESSKEY-SPEC-0004` defines generated evidence endpoint behavior.
- `docs/reference/verification-badges.md` documents badge meanings and limits.
- Future `cargo xtask spec-check` should validate the linked source-of-truth
  artifacts that make README badges auditable.
