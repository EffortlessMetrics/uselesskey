# CLI Proof Handoff Boundary

The v0.10.0 external-adoption buildout keeps proof execution repo-local.

Installed CLI users can discover the relevant proof path:

```bash
uselesskey profiles
uselesskey profile webhook --explain
uselesskey inspect-bundle --path target/uselesskey-webhook
```

Those commands explain generated files, scanner-safe posture, runtime-material
posture, proof or check paths, and claim boundaries. They do not execute public
claim proof.

Reviewers and maintainers who need receipts still use a repo checkout:

```bash
cargo xtask claim-proof --claim webhook-contract-pack
cargo xtask verification-pack --out target/uselesskey-verification --claim webhook-contract-pack
```

## Decision

For this buildout lane, `uselesskey` will not add an installed `prove` command.
The installed CLI remains a generator, verifier, inspector, and proof handoff
surface. Executable proof remains in `cargo xtask`.

That means the supported user split is:

| User | Interface |
| --- | --- |
| Installed CLI user | `uselesskey profiles`, `bundle`, `verify-bundle`, `inspect-bundle` |
| Rust test author | crate dependency snippets and library APIs |
| Reviewer with repo checkout | `cargo xtask verification-pack` |
| Maintainer or agent | `cargo xtask pr`, `adoption-regression`, `claim-proof`, release evidence |

## Why

The proof system currently depends on repo-owned policy, specs, and `xtask`
handlers. An installed CLI proof command would be misleading if it shell-ran
ambient `cargo xtask` commands or executed command strings from policy files in
whatever directory the user happened to be in.

Keeping proof repo-local avoids:

- arbitrary command execution from ledgers or profile metadata;
- proof claims that depend on an unrelated current directory;
- copying generated secret-shaped payloads into reviewer bundles;
- turning installed CLI convenience into a production security claim.

## Future Promotion Rule

A future installed proof command can be reconsidered only if it has an owned
proof engine. Acceptable shapes include:

- a reusable proof library/API owned by `uselesskey`;
- a packaged proof engine that does not rely on ambient repo state;
- a metadata-only command that writes instructions or bundle-local inspection
  receipts without claiming repo public-claim proof was executed.

Any future reviewer bundle produced by the installed CLI must remain
metadata-only and must not copy generated PEM, DER, JWT, key, Kubernetes
Secret, Vault payload, or webhook request payload files.

The formal boundary is
[`USELESSKEY-SPEC-0012`](../specs/USELESSKEY-SPEC-0012-cli-proof-handoff.md).
