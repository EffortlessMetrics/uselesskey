# Reduced CI lifecycle: cutover and qualification

This is a prepared operating contract, not a record of completed activation.
The source shadow remains manual-only. Repository transfers, workflow enablement,
protection changes, releases, and owned-host operations require their own exact
execution transaction and existing authority.

## Work and dependency map

| Owner | Concrete exit evidence |
| --- | --- |
| [swarm #680](https://github.com/EffortlessMetrics/uselesskey-swarm/issues/680) | Identity-preserving repository transfer and protected lifecycle cutover. |
| [swarm #681](https://github.com/EffortlessMetrics/uselesskey-swarm/issues/681) | Active package/service/App/updater/release bindings and actual policy readback. |
| [swarm #682](https://github.com/EffortlessMetrics/uselesskey-swarm/issues/682) | Complete current development invocation; reviewed selection and explicit skips. |
| [swarm #683](https://github.com/EffortlessMetrics/uselesskey-swarm/issues/683) | Live proof/review/composition binding and independently controlled admission. |
| [swarm #684](https://github.com/EffortlessMetrics/uselesskey-swarm/issues/684) | Complete bounded integration and explicit disposition of omitted obligations. |
| [swarm #685](https://github.com/EffortlessMetrics/uselesskey-swarm/issues/685) | Native Ready, P/H attachment, G execution, protected M, and updater/compute policy. |
| [swarm #667](https://github.com/EffortlessMetrics/uselesskey-swarm/issues/667) | Reconciled source/release baseline, accepted mutation retirement, and durable backflow. |
| [swarm #656](https://github.com/EffortlessMetrics/uselesskey-swarm/issues/656) / [draft #672](https://github.com/EffortlessMetrics/uselesskey-swarm/pull/672) | Real focused regression pilot with current proof; #671 retains product handoff. |

Source reconciliation can advance before transfer. A narrow regression can
proceed independently; a release-width promotion consumes the reconciled public
API, facade, package, compatibility and versioning truth. Transfer does not settle
that semantic work. #633 retains source/control-identity synchronization; its
previous workflow assumptions must be reconciled with the retired router.

## Execution placement follows reduction

Swarm owns implementation and change-specific proof before its development merge.
Canonical owns composed-candidate acceptance, qualified integration, public intake,
and releases. Keep ordinary development CI out of swarm's intended operating path.
Ready means the current candidate is expected to pass its first integration; a
red candidate blocks and returns to repair while unrelated development continues.

The default proposal permits a deliberate dependency-updater exception. Current
[GitHub Dependabot guidance](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-on-actions)
describes dynamic updater workflows that may bypass ordinary Actions disablement.
Deleting workflow files or reading `enabled=false` is insufficient to claim literal
zero Actions. #681/#685 must qualify the actual final policy and generated update
job, or a separately owned replacement when strict zero Actions is selected.
Keep alert ownership explicit. Canonical-only workflow pins need maintenance
ownership even after their old counterparts disappear from swarm.

Public hosted integration, deliberately selected private hosted integration,
and qualified owned execution are legitimate workload-specific outcomes. There
is no cross-organization runner rollout prerequisite for a hosted cutover.
The native merge-queue target here assumes public organization repositories.
If private repository visibility is selected, first verify the destination's
GitHub Enterprise Cloud eligibility for native merge queue; hosted runner access
alone does not establish that eligibility. See the
[merge queue requirements](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue).
em-ci #37 owns reduction, #38 placement/capacity, #223 execution accounting, and
#224 cross-org qualification only if owned execution is selected. The #106 native
lifecycle work still governs retained or safely retired owned capacity. Evaluate
owned machines' OpenClaw/coding/review roles independently; CI acceptance does not
authorize a different persistent role.

## Integration portfolio and omitted obligations

The runner preserves this exact sixteen-command portfolio: `fmt`, `clippy`,
`typos`, `deny`, `test`, `feature-matrix`, `dep-guard`, `docs-sync --check`,
`public-surface`, `bdd`, `no-blob`, `check-no-panic-family`, `check-file-policy`,
`check-lint-policy`, `spec-check --strict`, and `git diff --check`. All but the last
are `cargo xtask` commands. Every command must finish successfully. A partial
ledger cannot become integration success.

| Obligation | Intended disposition |
| --- | --- |
| Change-specific regressions and affected consumers | Development H and composed H before admission; add missing consumer/build/example/package checks when the change requires them. |
| Bounded integration | One complete portfolio on actual G; no full `cargo xtask ci` substitution. |
| Mutation | Retired under accepted swarm ADR 0005 and PRs #618/#619; #667 owns canonical backflow. Earlier cron removal retaining manual tooling is intermediate only. |
| Fuzzing | Explicit, scoped work when justified; remaining ordinary-PR selection is owned by #682. |
| Coverage and performance | Deliberate measurement with source/environment identity; no automatic Draft/PR/main/unchanged-source loop. |
| External advisories | Record source, capture date and freshness requirement; unchanged code does not imply unchanged external vulnerability data. |
| Package and release promises | Affected package/consumer proof before merge; complete release-candidate proof before publishing. Actual publishing remains canonical and separate. |
| Badges | Projection of accepted evidence with no new product-proof loop. |
| Source/control policy | Preserve or reconcile each actual policy check; do not use a generic test list as evidence that an omitted obligation vanished. |

Any uncovered obligation gets an execution point or an explicitly accepted
retirement before its old producer is removed. The fixed portfolio alone is not
proof that every future change-specific obligation is covered.

## Exact integration invocation

Use a clean committed candidate and a reviewed, clean committed control checkout.
Set `HEAD_SHA`,
`BASE_SHA`, `CANDIDATE_WORKSPACE`, and `TRUSTED_PROOF_RUNNER` independently. Use
absolute paths for both the workspace and trusted runner; the receipt path below
must also be absolute. For
composed-H proof, run the manual subject with an explicit B:

```bash
set -euo pipefail
INVOCATION_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
RECEIPT_PATH="$CANDIDATE_WORKSPACE/target/integration-proof/$INVOCATION_ID/receipt.json"
CONTROL_SHA256="$(sha256sum "$TRUSTED_PROOF_RUNNER" | cut -d ' ' -f1)"
POLICY_SHA256="$(python3 "$TRUSTED_PROOF_RUNNER" --policy-digest)"
python3 "$TRUSTED_PROOF_RUNNER" \
  --workspace "$CANDIDATE_WORKSPACE" \
  --subject-kind manual --expected-sha "$HEAD_SHA" --expected-base "$BASE_SHA" \
  --invocation-id "$INVOCATION_ID" --receipt "$RECEIPT_PATH" \
  --expected-control-sha256 "$CONTROL_SHA256" --expected-policy-sha256 "$POLICY_SHA256"
python3 "$TRUSTED_PROOF_RUNNER" --verify-receipt \
  --workspace "$CANDIDATE_WORKSPACE" \
  --expected-sha "$HEAD_SHA" --expected-base "$BASE_SHA" --subject-kind manual \
  --invocation-id "$INVOCATION_ID" --receipt "$RECEIPT_PATH" \
  --expected-control-sha256 "$CONTROL_SHA256" --expected-policy-sha256 "$POLICY_SHA256"
```

Use shell error checking and accept both successful commands; no printed path
alone is proof. A repeated invocation directory is refused. The receipt begins
incomplete and records source head/tree/clean checks, control source/digest,
Cargo.lock/toolchain-input digests, actual tool versions, ordered command outcomes,
and explicit failure/interruption state. Its environment `run_context` is recorded
metadata, not authenticated GitHub provenance. Untracked files and external
dependencies are outside a hermetic-build claim.

The dormant workflow uses G and the native queue base for a future merge-group
event, verifies its exact output and uploads only that invocation's receipt.
Missing artifacts fail. Manual shadow runs omit a base unless separately supplied
through the CLI; they qualify their declared subject only and cannot silently
serve as composed-H/B proof. Native run/attempt/artifact identity and required
check credit remain #685 acceptance work.

## Cutover transaction

Prepared branch publication is already possible without landing on protected
`main`. Before any protected-main landing, #680 must record a bootstrap transaction
from fresh ruleset and classic-protection readback for each repository: exact
candidate/base, required review and code-owner disposition, every required
context and producer, the proof that replaces any retired context, and the
authorized ordered configuration/merge operations with rollback. Resolve swarm's
obsolete required context before attempting the source merge it would block.
Keep unrelated protections and control-change review in force. If a legal merge
path is not established, stop at the prepared branch; disabled Actions never
implies permission to bypass a protection or supplies a missing check.

1. Re-read numeric IDs, exact main/prepared heads, branches, open work, tags,
   releases, protections, workflow states, Apps and credential names/scopes.
   Stop on unexplained drift. The audited main anchors were canonical
   `4c307ab159743472679087898a80a900d70c2109` and swarm
   `219fad7942c1ac60e6f6e9673460232e57336118`; they are observations, not future constants.
2. Freeze merges, releases, updater handling and configuration edits for the
   bounded transfer window. Disable canonical `ci.yml`, `coverage.yml`,
   `mutation.yml`, `performance.yml`, and `badge-endpoints.yml` while source
   administration remains available. Inspect queued/running jobs separately.
3. Keep destination ordinary Actions selected-repository policy empty before
   transfer. Transfer swarm, then canonical, and verify IDs, heads, history,
   issue/PR state, redirects and effective access/protection while both are excluded.
4. Reauthorize selected destination Apps/services using the operator session;
   the existing connector does not acquire new-organization access merely because
   a repository moved. Apply #681's active identity, updater and release bindings.
5. Execute only the recorded bootstrap transaction to land the dormant
   source/control preparation while Actions remain blocked. If its proof or
   protected merge path is unavailable, remain at prepared branches. Reconcile
   actual ancestry before consuming later role/activation layers.
   Verify the five legacy workflows disabled before enabling canonical only.
6. Run manual shadow qualification and correlate exact event, SHA, inputs, run ID,
   attempt and retained receipt. Never identify the qualifying run merely as
   the latest run. Manual green is not authoritative PR admission.
7. Finish and verify swarm's development merge policy. Any removal of the named
   obsolete required context belongs to the recorded bootstrap after transfer
   integrity and before the merge it gates; retain unrelated protections.
   Qualify the updater exception or replacement separately.
8. Complete #682–#684 prerequisites and protect the control producer. Keep real
   promotions Draft until current source and composed-H proof, plan acceptance,
   and review disposition are complete. The schema-only PR-body checker is insufficient.
9. Qualify actual Ready production, actor/token behavior and check attachment to
   P/H. Prove new commits, retargeting, body changes and substantive review activity
   invalidate acceptance before queue entry. A manual dispatch is not the native
   Ready event, and a same-name check from another authority is not equivalent.
10. Configure the qualified required result and merge queue before queueing the
    first protected production candidate. Start with build concurrency one,
    minimum/maximum merge limits one, and Only merge non-failing PRs enabled.
    Admit only the pilot until its result is reconciled. Merge limits do not
    establish the build group's size; inspect actual G composition and preserve
    no-bypass rules.
11. Require one complete green integration on actual G. Reconcile native run,
    attempt, checkout, control, receipt, artifact, result producer and protected M.
    Verify no duplicate full main proof. Unfreeze only the verified operating path.

Do not open Draft PRs solely to stage these Uselesskey candidates while the legacy
PR triggers still run on Draft. Prepared branches and exact compare links provide
a review surface until quiet publication/cutover is established. This does not
weaken any required merge gate or claim the candidates are Ready.

## Failure and rollback

Before activation, keep ordinary Actions closed, preserve the transfer and
evidence, and repair or revert the known source/configuration slice. There is no
reason to transfer repositories back solely to repair a service binding.

After required-result activation, stop admission/merges and retain blocking
protection while repairing or reverting the producer. Do not remove a required
context to let unproved code merge. Red, cancelled, incomplete, unavailable and
unknown remain distinct unsuccessful outcomes. Do not promote them with an empty
CI-poke commit, larger-runner retry, or automatic hosted spillover.

Record each completed step and its exact receipt in its existing owner. Source
tests, a manual run, a historical host canary, and a live protected integration
answer different questions; none is a substitute for the others.
