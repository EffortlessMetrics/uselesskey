# Signed promotion acceptance

The prepared admission consumer requires an operator signature and current live
evidence. It uses OpenSSH detached signatures. Signing records acceptance of a
specific manifest and control revision; the verifier independently checks the
current PR, composed proof and review state. A second person is not required.

The workflow remains manual-only. Signer configuration, evidence publication,
proof-control enforcement and native Ready/check/queue behavior must be qualified
under [swarm #683](https://github.com/EffortlessMetrics/uselesskey-swarm/issues/683)
and [#685](https://github.com/EffortlessMetrics/uselesskey-swarm/issues/685)
before activation. This source change creates no production key
or acceptance ref.

## Custody and limits

Keep the private signing key in the operator's controlled key store or SSH agent.
Never put it in a candidate checkout, repository variable, Actions secret
accessible to candidate workflows, fixture or evidence bundle. The signer accepts
an explicit key path. A public key is sufficient when its private half is
available through the operator's SSH agent.

The consumer needs public allowed-signer bytes and their independently configured
SHA-256. A digest calculated from a candidate-supplied key file is not an
independent pin. Protect both the configuration and the enforcing code. The
prepared workflow takes these public values from repository variables:

| Variable | Required value |
| --- | --- |
| `USELESSKEY_ADMISSION_ALLOWED_SIGNERS` | Exact OpenSSH allowed-signers file bytes. |
| `USELESSKEY_ADMISSION_SIGNERS_SHA256` | SHA-256 of those exact bytes, configured through the accepted administrative path. |

Choose a literal signer principal such as `EffortlessSteven`; use it also in
`operator_acceptance.actor`. Restrict the entry to the namespace
`promotion-acceptance@uselesskey.org`. OpenSSH's
[allowed-signers format](https://man.openbsd.org/ssh-keygen.1#ALLOWED_SIGNERS)
supports validity windows and namespace restrictions. No example key is accepted
as production configuration.

A candidate could still change a workflow to skip verification and report the
same Actions check name. #683 must protect the result-producing control path;
#685 must qualify its actual App and required-check binding. Until then, this is
a working signed-evidence consumer, not an independent check authority.

Manual dispatch uses the separate `Uselesskey Manual Qualification` job/check
name. Neither its self-tests nor its optional integration run can satisfy the
future `Uselesskey Required` context by name. Preserve this separation when
qualifying the native event and protected producer.

A signature authenticates the operator's decision. It does not prove that
unsigned receipts describe real execution, make a proof plan adequate, or replace
review judgment. Native run/artifact custody remains a separate requirement.

## Sign the reviewed manifest

Prepare the complete manifest in [promotion evidence](promotion-evidence.md).
Use the exact reviewed **B control checkout** that the consumer will actually
use; signing with different candidate H controls will be refused. The
bundle binds the exact admission modules, integration receipt consumer and
`required.yml`; a control change requires fresh acceptance.

Signing is a local action over an already-reviewed manifest. It neither executes
proof nor performs the live GitHub checks, publishes the bundle or makes the PR
Ready. An incorrect signed manifest still fails the live verifier.

```bash
set -euo pipefail
python3 -B scripts/sign-promotion-acceptance.py \
  --manifest "$ACCEPTED_MANIFEST" \
  --identity EffortlessSteven \
  --key "$OPERATOR_SIGNING_KEY" \
  --valid-for-seconds 3600 \
  --output "$NEW_ACCEPTANCE_BUNDLE"
```

The commands require a POSIX host with OpenSSH and refuse an existing output.
They reserve a private file and retain its file/directory descriptors across the
operation. A changed parent or replaced reservation is refused; writes use only
the reserved inode and cannot replace a later path occupant. Interrupted writes
are unaccepted: require successful CLI completion and complete JSON before
retaining a bundle or consuming a report. Do not read an output concurrently
while the command is running.

Signing uses canonical finite JSON with
`ssh-keygen -Y sign`, a dedicated namespace and SHA-512 message hashing. OpenSSH
retains the private key. Its subprocess receives no GitHub API token. An encrypted
key must already be available through the agent; this tool collects no passphrase.

Acceptance expires at its signed deadline, at most one day after the manifest's
accepted decision. The requested duration must fit inside the remaining day.
Future dates, expiry, different controls, actor mismatch and malformed signatures
are refused. The age limit bounds replay; live checks and advisory-freshness
policy still apply.

## Retain without changing the tested subject

Retain the public bundle as a normal Git file on `refs/heads/ci-acceptance`, at:

```text
acceptances/PR_NUMBER/HEAD_SHA/BASE_SHA.json
```

The signer prints the exact path. Publish through the operator's existing
Git/GitHub path as a separate evidence commit and preserve the ref/history.
Adding the bundle to the tested candidate changes H and invalidates its proof.
Putting its content-addressed pointer inside the signed PR body creates a
circular body-hash dependency; use the independent evidence ref instead.

The consumer resolves the fixed ref, reads the exact H/B path at that commit,
checks file type/size and Git blob identity, and rereads the ref after live
verification. A concurrent ref change refuses the observation. The signature
prevents an unauthorized writer from fabricating accepted content; the ref still
needs availability, retention and update ownership.

Removing an entry or rotating the allowed key affects the next verification. It
does not revoke an already-published GitHub success automatically. Native
invalidation and rechecking before queue acceptance remain #685 work.

## Verify against live state

The read-only `GITHUB_TOKEN` must read the family repositories and review threads.
Run from trusted controls with public signer bytes and the independent pin:

```bash
set -euo pipefail
python3 -B scripts/verify-signed-promotion.py \
  --repository "$REPOSITORY" --pr "$PR_NUMBER" \
  --expected-head "$HEAD_SHA" --expected-base "$BASE_SHA" \
  --from-acceptance-ref \
  --allowed-signers "$TRUSTED_ALLOWED_SIGNERS" \
  --expected-signers-sha256 "$TRUSTED_SIGNERS_SHA256" \
  --output "$NEW_ADMISSION_REPORT"
```

For diagnostics, `--bundle "$ACCEPTANCE_BUNDLE"` replaces
`--from-acceptance-ref`; it still requires authentication and every live check.
The dormant workflow uses the ref-backed path. Missing configuration/evidence,
wrong identity, stale review or API failure never falls back to the schema-only
checker.

The report records bundle/blob/ref identity, signer/pin, acceptance times,
current subjects and control digests. Expiry is checked again after network
reads. It grants no check-writing, dispatch, queue or merge authority.

## Validation

```bash
python3 -B scripts/tests/test_signed_promotion.py
python3 -B scripts/tests/test_promotion_evidence.py
```

Tests generate fresh temporary OpenSSH keys and remove them after the run. Real
signatures with synthetic API state test altered payloads, wrong keys/principals/
namespaces, missing pins, expiry during reads, control drift, wrong Git identity
and live-evidence refusal. They do not qualify a production key or native check.
