# Learnings

Learning records capture durable lessons from releases, incidents, proof lanes,
and product boundary changes.

They should explain what changed in the operating model, not restate every step
from a PR or release log.

## Required Shape

Use [the learning template](../templates/learning.md). A learning record should
include:

- Trigger
- What changed
- Evidence that made the lesson visible
- Repository rule or habit to keep
- Follow-up specs, ADRs, plans, or policy entries

## Records

- [2026-05-spec-system.md](2026-05-spec-system.md) - public fixture claims need command-backed source of truth
- [2026-05-claim-backed-verification.md](2026-05-claim-backed-verification.md) - public claims are useful when users can run the proof
- [2026-05-pr-lite-evidence.md](2026-05-pr-lite-evidence.md) - local evidence is useful when its boundary is explicit
- [2026-05-no-panic-burndown.md](2026-05-no-panic-burndown.md) - no-panic progress needs a stage between advisory and deny
- [2026-05-webhook-contract-pack.md](2026-05-webhook-contract-pack.md) - contract packs become real when a new user workflow uses every proof rail
- [2026-05-v0.9.0-release.md](2026-05-v0.9.0-release.md) - a command-backed release still needs one release authority
- [2026-05-first-run-ux.md](2026-05-first-run-ux.md) - first-run UX works when proof rails stay behind task routing
- [2026-05-adoption-confidence.md](2026-05-adoption-confidence.md) - easy fixture paths need confidence receipts
- [2026-05-v0.9.1-release.md](2026-05-v0.9.1-release.md) - patch releases earn trust by publishing corrected proof surfaces
- [2026-05-v0.10.0-external-adoption.md](2026-05-v0.10.0-external-adoption.md) - external adoption needs clean-project proof
- [2026-05-installed-bundle-audit.md](2026-05-installed-bundle-audit.md) - installed bundles need local audit receipts
