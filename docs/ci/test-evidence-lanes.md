# Test Evidence Lanes

`uselesskey` is a fixture platform for secret-shaped test systems. CI evidence
should be organized around that promise: deterministic fixtures, scanner-safe
bundle defaults, realistic negative cases, and adapter contracts should be
backed by the right proof at the right time.

The goal is not simply faster CI. The goal is to make each lane answer a clear
question without making every pull request pay release-candidate cost.

## Signal Boundaries

Different tools answer different questions:

| Signal | Question answered | Boundary |
| --- | --- | --- |
| Coverage | Did tests execute this surface? | Does not prove assertions would detect wrong behavior. |
| `ripr` | Does changed behavior appear to have a meaningful test oracle? | Static exposure signal; does not run mutants. |
| Targeted mutation | Did high-risk changed behavior survive concrete mutants? | Runtime proof for selected owner crates, not a workspace-wide default. |
| Nightly mutation | Did the broader public fixture surface gain new survivors? | Broad regression signal outside ordinary PR latency. |
| Release evidence | Can the shipped public promises be proven together? | Release-candidate proof, not day-to-day PR feedback. |

`ripr` does not replace mutation testing. Use `ripr` before mutation to route
expensive proof toward behavior that needs it, then use mutation to confirm
high-risk behavior where runtime proof matters.

## Lane 1: PR Fast Evidence

Runs on every pull request.

Purpose:

- catch build, lint, docs, support metadata, scanner-risk, and public-surface
  drift quickly;
- show whether changed behavior appears to reach a meaningful test oracle;
- keep ordinary review feedback fast enough to act on.

Typical signals:

- formatting and Clippy;
- impact-scoped tests;
- `cargo xtask docs-sync --check`;
- `cargo xtask public-surface` when topology or support metadata changes;
- `cargo xtask publish-preflight --allow-dirty` when package metadata changes;
- `cargo xtask examples-smoke` when examples or user recipes change;
- `cargo xtask no-blob` when fixture, docs, bundle, or example outputs change;
- `cargo xtask ripr-pr` for advisory `ripr` PR exposure evidence;
- `git diff --check`.

Blocking posture:

- normal build, lint, docs, public-surface, publish, no-blob, and example
  failures block when their affected surface is in scope;
- `ripr` should start advisory and become blocking only for severe exposure
  gaps after the baseline is stable;
- full mutation does not run here by default. Use `cargo xtask pr --with-mutants`
  or `cargo xtask mutants-pr --changed` when PR-scoped mutation is required.

## Lane 2: PR Targeted Mutation

Runs only when the change is high risk or explicitly requested.

Triggers:

- `mutation` or `release-risk` label;
- core derivation, hash, identity, seed, sink, or cache behavior changed;
- negative fixture semantics changed;
- bundle verifier, materialization, manifest, or receipt behavior changed;
- adapter conversion behavior changed;
- public owner crate internals changed;
- `ripr` reports a severe exposure gap on a public owner surface.

Scope:

- changed owner crate first;
- at most the directly affected owner crates unless the PR explicitly opts into
  a full-owner or release-risk run;
- compatibility shims use narrow import/publish proof unless their behavior is
  more than a re-export.

Blocking posture:

- targeted mutation is blocking when triggered;
- missed mutants should produce focused tests or a documented equivalent-mutant
  rationale;
- do not weaken fixture assertions or public contracts only to reduce mutant
  count.

## Lane 3: Nightly Mutation

Runs on a schedule and by manual dispatch.

Purpose:

- keep broad mutation signal without charging every PR for it;
- detect new survivor regressions across public fixture promises;
- keep a running evidence trail for release readiness.

Default scope:

- `uselesskey-core`;
- public fixture-family crates such as `uselesskey-jwk`, `uselesskey-token`,
  `uselesskey-x509`, `uselesskey-rsa`, `uselesskey-ecdsa`,
  `uselesskey-ed25519`, and `uselesskey-hmac`;
- `uselesskey-cli`;
- critical adapters when their contracts are active release promises.

Artifacts should summarize:

- mutants found;
- caught;
- survived or missed;
- unviable;
- new survivors since the last run;
- known accepted survivors with issue links.

Nightly mutation is advisory for ordinary PRs. It can become release-blocking
once the survivor ledger is classified and maintained.

## Lane 4: Release Evidence

Runs for release branches, release candidates, or tag candidates.

Purpose:

- prove the shipped public fixture platform, not just the changed diff;
- give users and maintainers a linkable evidence package for deterministic
  fixtures, negative cases, scanner-safe bundles, adapters, and package proof.

Signals:

- full mutation on selected public owner crates;
- repository-level `ripr` exposure summary;
- `cargo xtask public-surface`;
- package proof and publish dry-runs;
- bundle generation and `verify-bundle`;
- scanner-safe `no-blob` proof;
- docs/examples smoke;
- adapter matrix checks;
- receipt drift checks.

Release evidence should produce durable Markdown and JSON artifacts that can be
linked from release notes.

## Change-Type Routing

| Change type | Fast PR evidence | Targeted mutation | Nightly/release role |
| --- | --- | --- | --- |
| Docs-only policy or roadmap | Docs sync, typos, link/diff checks | No, unless examples execute behavior | Nightly unaffected. |
| User examples or bundle recipes | Examples smoke, no-blob, docs sync | Only if executable behavior changes | Release examples proof. |
| Public-surface metadata or crate topology | Public-surface, publish-preflight, docs sync | Owner mutation when behavior moved | Release matrix proof. |
| Core derivation/hash/identity | Fast gates plus deterministic regression tests | Yes, full owner mutation | Release-blocking evidence. |
| Negative fixture semantics | Owner tests plus `ripr` exposure | Yes, owner-targeted mutation | Failure-atlas proof. |
| Bundle manifest/verifier/receipts | CLI tests, bundle verify, no-blob | Yes, CLI-targeted mutation | Bundle release receipts. |
| Adapter conversion behavior | Adapter tests and examples | Yes, adapter-targeted mutation | Adapter contract proof. |
| Compatibility shim only | Import, no-default, package, metadata proof | Usually no | Release shim policy. |

## Author Workflow

For an ordinary PR:

1. Run the fast local gates for the touched surface.
2. Run `cargo xtask ripr-pr` and read `target/ripr/pr/summary.md`.
3. Add focused tests when changed behavior is weakly exposed.
4. Use targeted mutation only when the routing rules call for it.

For a high-risk PR:

1. Run the fast local gates.
2. Run `cargo xtask ripr-pr` to find missing or weak test oracles.
3. Add focused tests for severe exposure gaps.
4. Run `cargo xtask mutants-pr --changed` or
   `cargo xtask mutants-pr --crate <crate> --full-owner` for the owner crate.
5. Record the exact mutation command and result in the PR body.

`cargo xtask ripr-pr` treats `ripr` as an external tool and writes advisory
artifacts under `target/ripr/pr/`:

- `repo-exposure.json`;
- `summary.md`;
- `review.md`.

Pull request CI uploads that directory as the `ripr-pr` artifact.

If `ripr` is not installed, the command writes skipped artifacts with a clear
reason and exits successfully. Other `ripr` runtime failures should fail the
command so the tool integration does not silently mask bad evidence.
