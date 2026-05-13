+++
id = "USELESSKEY-ADR-0002"
kind = "adr"
title = "Public claims require command-backed evidence"
status = "accepted"
owner = "EffortlessMetrics"
created = "2026-05-13"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = ["USELESSKEY-SPEC-0002", "USELESSKEY-SPEC-0004"]
+++

# USELESSKEY-ADR-0002: Public Claims Require Command-Backed Evidence

## Decision

Public `uselesskey` claims must be backed by generated evidence, proof commands,
release evidence rows, or an explicit advisory/experimental status.

README badges must use repo-scoped generated endpoints. PR-scoped artifacts must
stay in PR summaries, annotations, and CI artifacts.

## Context

`uselesskey` operates in a space where wording can easily overclaim. A
scanner-safe badge, a TLS contract-pack claim, and a `ripr+` badge are useful
only when users can find the proof command and boundary behind them.

The badge endpoint work created generated `ripr+` and scanner-safe Shields JSON
under `badges/`. That should become the rule for public trust markers: generated
or absent, not hand-written.

## Consequences

README stays compact and durable because it links to repo-owned receipts instead
of embedding a proof matrix.

Claims become auditable through `policy/claim-ledger.toml`, docs, and proof
commands.

Badge additions get a higher bar. New badge endpoints need stable evidence and
documented boundaries before they become public masthead signals.

PR evidence remains useful without becoming public badge theater. Diff-scoped
`ripr` comments and summaries stay in the PR lane.

## Alternatives Considered

Allow hand-written badge JSON.

Rejected because it can drift from evidence and turns badges into slogans.

Use PR-scoped `ripr` artifacts for README badges.

Rejected because PR evidence is diff-scoped and advisory; public README badges
must represent repo-scoped state.

Expose every CI guardrail as a README badge.

Rejected because the masthead should be a small front panel, not a dashboard.

Require proof for every claim before it can be documented anywhere.

Rejected because proposals and specs need room to describe planned behavior.
Planned or advisory claims must be labeled honestly until command-backed proof
exists.

## Follow-up Specs / Plans

- `USELESSKEY-SPEC-0002` defines the claim-ledger fields.
- `USELESSKEY-SPEC-0004` defines generated badge endpoint behavior.
- Future `cargo xtask spec-check` should validate claim entries and generated
  endpoint ownership.
