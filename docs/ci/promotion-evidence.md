# Promotion evidence preparation

The source in this branch prepares a reduced development/integration lifecycle.
`scripts/verify-promotion-evidence.py` is a read-only, operator-assisted verifier.
It does not write a check, dispatch a workflow, enqueue a PR, or grant merge
authority. The shadow `required.yml` remains manual-only, and its dormant PR
step still uses the older schema-only packet checker. Do not activate that step
as sufficient admission merely because this new verifier exists.

Implementation ownership is in swarm [#682](https://github.com/EffortlessMetrics/uselesskey-swarm/issues/682)
(development proof), [#683](https://github.com/EffortlessMetrics/uselesskey-swarm/issues/683)
(admission/custody), [#684](https://github.com/EffortlessMetrics/uselesskey-swarm/issues/684)
(integration), and [#685](https://github.com/EffortlessMetrics/uselesskey-swarm/issues/685)
(native lifecycle qualification). [The cutover runbook](lifecycle-cutover.md)
defines their order and the operational boundary.

## Subjects and controls

| Identity | Meaning and binding |
| --- | --- |
| Development H | Exact head of a merged swarm PR targeting `main`; receipt tree must match the native commit tree. |
| Development PR base | Native `base.sha` retained on that merged PR, recorded as `pr_base`. |
| Development comparison base | Independently obtained merge base of native PR base and H; the envelope's `subject.base` must equal it. |
| Canonical B | Current canonical PR base SHA on `main`; B must be an ancestor of H. |
| Canonical H | Exact final composed canonical branch head, including any conflict repairs or maintenance changes. |
| P | GitHub's native PR test-merge subject. A future Ready producer must establish how its check attaches to P/H. |
| G | Native merge-group subject; the bounded portfolio must execute on the actual checked-out G. |
| M | Landed protected-main commit; live qualification must reconcile it to accepted G. |

An arbitrary ancestor is not an adequate development comparison base. A producer
could select a commit after an earlier product change and report only the later
documentation diff. The verifier derives the native PR comparison base and
compares the complete native changed-path set, including both sides of renames,
to the envelope. The shared pure contract recomputes the path classification.

Run the verifier and its sibling modules from a reviewed operator control
checkout, outside submitted candidate authority. Candidate code must not receive
the operator's API token merely because it contains a script with this name.
Protect changes to the verifier, shared contract, proof plans, integration
portfolio, and their result producer. Control independence can be provided by
protected source and explicit operator custody; a second human identity is not
an intrinsic requirement.

## Development proof and evidence custody

Swarm's `scripts/seal-development-proof.py --run --base SHA --plan FILE` executes
reviewed focused commands, then `cargo xtask pr`, in a clean dedicated checkout.
It archives a complete invocation envelope and prints its exact digest and
invocation identity. Bare xtask receipts, incomplete outcomes, undeclared skips,
stale raw receipts, hidden index flags, and changed subjects cannot seal.

Use swarm's `docs/ci/no-actions-development.md` for the plan contract. In
particular, the old Rust selector can still select fuzz and tool-dependent
coverage; this wrapper has not implemented the remaining selector reduction.

Preserve the envelope as exact UTF-8 bytes in its source repository's Git object
database. Retain it through a dedicated evidence ref, or a documented retention
mechanism that keeps the blob reachable. A bare Git blob upload has no lasting
reachability guarantee. Do not add the receipt to the candidate commit after
testing and then claim the changed head was tested. Evidence storage must remain
separate from the tested subject.

The current reader accepts a full Git blob SHA and SHA-256 in each proof
descriptor. It fetches that blob from the declared repository, verifies its size,
SHA-256, and Git blob identity, and validates the actual bytes. It does not accept
an arbitrary URL that could redirect credentials elsewhere. Supporting an Actions
artifact later requires equally explicit artifact/run/attempt identity and
retention checks; that transport is not implemented here.

`scripts/development_proof_contract.py` is intentionally identical in producer
and consumer. Review and land future changes together under #683/#667, compare
their SHA-256 digests, and update tests on both sides. Do not independently
reimplement a weaker admission parser.

## Capture and accept current review state

The CLI requires Python 3.11 or newer and a read-only `GITHUB_TOKEN` capable of
reading both repositories' PRs, comments, review threads, commits, and blobs.
Use the operator's existing credential path; the tool neither stores nor prints
the token. The fixed API host is `api.github.com`, redirects are refused, and
GraphQL is used only for a fixed review-thread query.

Capture each PR after substantive review. Set the variables to independently
observed identities; `PR_BASE_SHA` is the native PR base, not a producer-selected
comparison base. Run this from the trusted control checkout:

```bash
python3 -B scripts/verify-promotion-evidence.py \
  --repository "$REPOSITORY" --pr "$PR_NUMBER" \
  --expected-head "$HEAD_SHA" --expected-base "$PR_BASE_SHA" \
  --capture-review-state --output "$NEW_OBSERVATION_PATH"
```

This creates an observation, not an acceptance. It records native changed paths,
comparison base, PR body digest, and a fingerprint of complete bounded review
submissions, inline comments, general discussion, and thread resolution states.
The operator must inspect findings, dispositions, chosen proof, and composition.
New comments or edits, including on resolved threads, invalidate the prior
fingerprint. Full API records are fingerprinted conservatively; metadata changes
can also require refresh. Outdated unresolved threads remain blocking.

The verifier supports the two numeric repository identities through their old
and intended transferred names: canonical `1148729677` and swarm `1243900627`.
It requires the current full name to match. Refresh the accepted manifest after
transfer rather than relying on a redirect or substituting a newly created repo.
Both canonical and source PRs must target `main`; same-SHA retargeting is a change.

## Operator manifest

The JSON below is an intentionally invalid template. Replace placeholders,
provide the exact captured digests, and make the acceptance only after the work
is complete. Never convert false/incomplete fields to true merely to satisfy a
parser. The manifest belongs to the operator's control surface, not editable
candidate PR prose.

```json
{
  "schema_version": 1,
  "kind": "uselesskey-promotion-evidence",
  "profile": "development-promotion",
  "repository_id": 1148729677,
  "pull_request": 0,
  "head": "FULL_CANONICAL_H",
  "base": "FULL_CANONICAL_B",
  "body_sha256": "CAPTURED_BODY_SHA256",
  "review_sha256": "CAPTURED_REVIEW_SHA256",
  "accepted_at_ms": 0,
  "operator_acceptance": {
    "actor": "ACCOUNTABLE_OPERATOR",
    "review_disposition": "incomplete",
    "known_blockers": ["replace after resolving the actual blockers"],
    "composition_reviewed": false,
    "plans_reviewed": false,
    "evidence": ["durable review and plan-adequacy decision references"]
  },
  "promotion_proof": {
    "kind": "development",
    "git_blob": "IMMUTABLE_CANONICAL_RECEIPT_BLOB",
    "sha256": "EXACT_RECEIPT_SHA256",
    "invocation_id": "EXACT_INVOCATION_ID",
    "plan_sha256": "ACCEPTED_PLAN_SHA256"
  },
  "development": [{
    "repository": "EffortlessMetrics/uselesskey-swarm",
    "pr": 0,
    "head": "FULL_DEVELOPMENT_H",
    "pr_base": "NATIVE_MERGED_PR_BASE_SHA",
    "base": "INDEPENDENT_NATIVE_COMPARISON_BASE",
    "body_sha256": "CAPTURED_SOURCE_BODY_SHA256",
    "review_sha256": "CAPTURED_SOURCE_REVIEW_SHA256",
    "proof": {
      "kind": "development",
      "git_blob": "IMMUTABLE_SOURCE_RECEIPT_BLOB",
      "sha256": "EXACT_RECEIPT_SHA256",
      "invocation_id": "EXACT_INVOCATION_ID",
      "plan_sha256": "ACCEPTED_PLAN_SHA256"
    }
  }]
}
```

Source development entries always require development proof. Composed-H proof
may instead use `kind: integration`; replace `plan_sha256` with both
`control_sha256` and `policy_sha256` and supply a complete manual H receipt whose
expected base is canonical B. Integration proof cannot silently substitute for
the source change-specific obligation.

For a legitimate canonical-only maintenance change, use
`profile: canonical-maintenance`, an empty `development` array, and
`accepted_paths` equal to the complete sorted native path set. The bounded scope
is `.github/`, `scripts/`, `policy/`, `docs/ci/`, `docs/release/`, root Cargo and
toolchain files, and `crates/*/Cargo.toml`. Renames include their origin paths.
These files can materially affect releases or proof controls; path eligibility
does not establish adequacy. Current composed-H proof and explicit plan/review
acceptance still apply.

```bash
python3 -B scripts/verify-promotion-evidence.py \
  --repository "$CANONICAL_REPOSITORY" --pr "$PROMOTION_PR" \
  --expected-head "$HEAD_SHA" --expected-base "$BASE_SHA" \
  --manifest "$ACCEPTED_MANIFEST" --output "$NEW_VERIFICATION_PATH"
```

Success reports `mechanical_verification: success` and `authority: none`, the
manifest and control digests, and the observed subjects. Existing output paths
are refused. A new observation begins incomplete, so a failed lookup cannot
produce a new success record. Missing credentials, absent objects, incomplete
pagination, unknown fields, or changed state fail rather than becoming absence.
Limits are 2 MiB per JSON response/input, ten pages per collection, fifty source
PRs, 512 API requests, and a five-minute observation budget.

The final read repeats the full review fingerprints and PR identities/bodies.
It bounds races; it is not an atomic server-side merge transaction. #683/#685
must supply live invalidation and protected producer authority before using this
as admission. The tool does not authenticate operator judgment or arbitrary
command execution. Exact receipt identity is not an execution attestation, and
successful commands do not automatically establish sufficient test coverage.

## Local verification

```bash
python3 -B -m unittest discover -s scripts/tests -p test_promotion_evidence.py
python3 -B scripts/test_run_integration_proof.py
python3 -B scripts/check-promotion-packet.py --self-test
python3 -B scripts/run-integration-proof.py --self-test
git diff --check
```

The admission fixtures substitute the GitHub API; integration tests use real
temporary Git repositories and substitute Rust execution. They establish parser,
identity, invocation, and failure behavior. They do not establish native Cargo
success, review adequacy, check credit, merge-queue behavior, or release readiness.
