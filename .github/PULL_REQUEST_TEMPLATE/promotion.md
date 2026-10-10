## Promotion

Preparation status: the packet below is a schema-only declaration. It does not
fetch source proof, establish live review acceptance, or prove this composed head.
Use [promotion evidence preparation](../../docs/ci/promotion-evidence.md) and
[signed acceptance](../../docs/ci/signed-promotion-acceptance.md), with the
separate [swarm #683](https://github.com/EffortlessMetrics/uselesskey-swarm/issues/683)
and [#685](https://github.com/EffortlessMetrics/uselesskey-swarm/issues/685)
admission/qualification owners before enabling automatic Ready.

This pull request integrates reviewed development work from `uselesskey-swarm` into canonical source.

Keep it **Draft** until the final canonical head, every development proof, the review disposition, and blocker state are exact. Any commit after Ready invalidates the recorded `promotion_head`; return the pull request to Draft, refresh the packet, and earn admission again.

## Promotion packet

Replace every placeholder before Ready. The bounded packet is machine-validated; do not add fields or move it outside the markers. Repeat `[[development]]` once for each accepted development PR represented by this promotion.

<!-- uselesskey-promotion:v1 -->
```toml
schema_version = 1
promotion_head = "0000000000000000000000000000000000000000"
review_disposition = "incomplete"
known_blockers = ["replace this placeholder before Ready"]

[[development]]
repository = "uselesskey/uselesskey-swarm"
pr = 0
head = "0000000000000000000000000000000000000000"
proof_head = "0000000000000000000000000000000000000000"
proof_receipt_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
```
<!-- /uselesskey-promotion:v1 -->

## Scope

Development PRs, commits, and behavior included in this promotion.

## Exclusions

Related development that remains intentionally outside this promotion.

## Compatibility and release boundary

User-visible behavior, fixture/output identity, public API, package, versioning, and release implications. State `none` only when that has been checked.

## Proof

For every `[[development]]` entry, list the exact development-head commands, results, proof receipt path, and SHA-256 digest represented by the packet.

## Review disposition

Substantive findings, repairs, rejected findings with evidence, unresolved review threads, and the final disposition. `review_disposition = "complete"` means every recorded exact development head has no unresolved substantive review work and this composed canonical diff has received its required review.

## Rollback

How to remove or revert the promoted change without rewriting released history or weakening required proof.
