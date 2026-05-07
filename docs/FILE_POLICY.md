# Non-Rust file policy

> Authoritative file: `policy/non-rust-allowlist.toml`. Enforced by `cargo
> xtask check-file-policy`. See also [POLICY_ALLOWLISTS.md](POLICY_ALLOWLISTS.md).

## Why

`uselesskey` is a Rust workspace. The default implementation surface is Rust
plus `xtask`. Every other tracked file represents a deliberate non-Rust
surface — CI declarations, BDD features, generated metadata, golden fixtures.
Each non-Rust surface needs an explicit owner, reason, classification, and a
test/CI command that exercises it.

This is not aesthetics. It prevents:

- silent introduction of shell scripts that bypass `cargo xtask`
- generated artifacts checked in without a regenerator command
- vendored config that nobody owns

## Default-allowed defaults

The checker treats the following as default-allowed (still classified for the
report):

- `*.rs`, `Cargo.toml`, `Cargo.lock`, `*.md`
- `LICENSE-APACHE`, `LICENSE-MIT`, `CODEOWNERS`,
  `.gitignore`, `.gitattributes`, `.editorconfig`

## Required schema

```toml
[[allow]]
glob = ".github/workflows/*.yml"
kind = "ci_declarative"
owner = "release/ci"
surface = "ci"
classification = "config"  # config | test | tooling | generated | production
reason = "GitHub Actions workflow definitions are platform-required YAML."
covered_by = ["cargo xtask ci"]
# generated entries also include:
# generated_by = "cargo xtask docs-sync"
# optional:
# expires = "2026-09-01"
# retired = false
```

### Classifications

| Classification | Meaning                                                                    |
|----------------|----------------------------------------------------------------------------|
| `config`       | Declarative configuration consumed by an external tool.                    |
| `test`         | Test fixture, golden file, BDD feature, snapshot, regression seed.         |
| `tooling`      | Repo-managed tooling/automation (hooks, helper scripts).                   |
| `generated`    | Generated artifact; must specify `generated_by`.                           |
| `production`   | Production non-Rust surface (none currently in `uselesskey`).              |

## What `check-file-policy` enforces

- Enumerate git-tracked files.
- Classify each file. Default-allowed defaults pass automatically.
- Match the rest against `policy/non-rust-allowlist.toml`.
- Fail on:
  - tracked files with no matching entry,
  - entries missing `owner`/`reason`/`surface`/`classification`,
  - `production`/`test`/`tooling` entries missing `covered_by`,
  - entries past their `expires` date,
  - entries with no matching tracked file (unless `retired = true`).
- Write `target/file-policy.md` and `target/file-policy.json` reports.
