# Coverage

Coverage is an execution-surface signal.

It answers:

> Did tests execute this Rust surface?

It does not answer:

- whether fixture generation is cryptographically appropriate,
- whether deterministic derivation is stable,
- whether negative fixtures are semantically valid,
- whether scanners will treat outputs correctly,
- whether mutation adequacy is strong,
- whether supply-chain risk is acceptable,
- whether publish preflight is complete.

Those are separate lanes: xtask receipts, mutation, publish preflight, cargo-deny, audit-surface, economics, and fixture-specific tests.

## Workflow triggers

The Coverage workflow runs on:

- `push` to `main`,
- `workflow_dispatch` (manual trigger),
- `pull_request` with labels `coverage` or `full-ci`.

## Artifacts

Durable receipts are:

- `coverage.json` — structured coverage metrics (upload to GitHub Actions artifact),
- `coverage.txt` — human-readable coverage summary (upload to GitHub Actions artifact),
- `lcov.info` — LCOV format coverage data (upload to both GitHub Actions artifact and Codecov),
- the GitHub Actions artifact bundle (14-day retention),
- the [Codecov dashboard](https://codecov.io/gh/EffortlessMetrics/uselesskey).

## Configuration

The `codecov.yml` file configures coverage statuses:

- Project coverage: auto target, 5% threshold, informational only
- Patch coverage: 70% target, 20% threshold, informational only
- Comments disabled (no noisy Codecov PR comments)
- Annotations disabled

## Status

Coverage is currently **advisory**. It does not block merges or CI.

Once baseline data is established, the lane may move to informational or blocking status via `codecov.yml` updates.
